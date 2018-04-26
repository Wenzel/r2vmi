#include <inttypes.h>

#include "utils.h"
#include "io_vmi.h"

#define LINEAR48(x)    ((x) &= 0xffffffffffff)

static bool interrupted = false;

// stolen from libvmi/examples/step-event-example
void print_event(vmi_event_t *event)
{
    printf("\tPAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %u)\n",
           (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
           (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
           (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
           event->mem_event.gfn,
           event->mem_event.offset,
           event->mem_event.gla,
           event->vcpu_id
           );
}

// compare 2 virtual addresses
bool vaddr_equal(vmi_instance_t vmi, addr_t vaddr1, addr_t vaddr2)
{
    page_mode_t page_mode = vmi_get_page_mode(vmi, 0);

    switch (page_mode) {
    case VMI_PM_IA32E:
        // only 48 bits are used by the MMU as linear address
        if (LINEAR48(vaddr1) == LINEAR48(vaddr2))
            return true;
        break;
    default:
        eprintf("Unhandled page mode");
        break;
    }
    return false;
}

char* dtb_to_pname(vmi_instance_t vmi, addr_t dtb) {
    addr_t ps_head = 0;
    addr_t flink = 0;
    addr_t start_proc = 0;
    addr_t pdb_offset = 0;
    addr_t tasks_offset = 0;
    addr_t name_offset = 0;
    addr_t value = 0;
    status_t status;


    status = vmi_get_offset(vmi, "win_tasks", &tasks_offset);
    if (VMI_FAILURE == status)
    {
        printf("failed\n");
        return NULL;
    }

    status = vmi_get_offset(vmi, "win_pdbase", &pdb_offset);
    if (VMI_FAILURE == status)
    {
        printf("failed\n");
        return NULL;
    }

    status = vmi_get_offset(vmi, "win_pname", &name_offset);
    if (VMI_FAILURE == status)
    {
        printf("failed\n");
        return NULL;
    }
    status = vmi_translate_ksym2v(vmi, "PsActiveProcessHead", &ps_head);
    if (VMI_FAILURE == status)
    {
        printf("failed\n");
        return NULL;
    }
    status = vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &flink);
    if (VMI_FAILURE == status)
    {
        printf("failed\n");
        return NULL;
    }

    while (flink != ps_head)
    {
        // get eprocess head
        start_proc = flink - tasks_offset;

        // get dtb value
        vmi_read_addr_va(vmi, start_proc + pdb_offset, 0, &value);
        if (value == dtb)
        {
            // read process name
            return vmi_read_str_va(vmi, start_proc + name_offset, 0);
        }
        // read new flink
        vmi_read_addr_va(vmi, flink, 0, &flink);
    }
    return NULL;
}

static event_response_t cb_on_continue_until_event(vmi_instance_t vmi, vmi_event_t *event)
{
    RIOVmi* rio_vmi;
    addr_t bp_vaddr;
    status_t status;
    bp_event_data* event_data;
    const char* proc_name = NULL;

    printf("%s\n", __func__);

    if(!event || event->type != VMI_EVENT_MEMORY || !event->data) {
        eprintf("ERROR (%s): invalid event encounted\n", __func__);
        return 0;
    }

    // get event data
    event_data = (bp_event_data*)(event->data);
    rio_vmi = event_data->rio_vmi;
    bp_vaddr = event_data->bp_vaddr;

    // our address ?
    if (!vaddr_equal(vmi, event->x86_regs->rip, bp_vaddr))
    {
        eprintf("Wrong RIP: 0x%lx\n", event->x86_regs->rip);
        return VMI_EVENT_RESPONSE_EMULATE;
    }

    proc_name = dtb_to_pname(vmi, event->x86_regs->cr3);
    if (!proc_name)
        proc_name = "NEW_PROCESS.EXE";

    printf("At NtResumeThread: %s, CR3: 0x%lx\n", proc_name, event->x86_regs->cr3);
    status = vmi_pause_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to resume VM\n");
        return false;
    }

    //interrupted = true;
    return VMI_EVENT_RESPONSE_EMULATE;
}

static bool continue_until(RIOVmi *rio_vmi, addr_t addr)
{
    printf("%s\n", __func__);
    status_t status;
    addr_t paddr;
    addr_t gfn;
    vmi_event_t continue_until_event = {0};
    bp_event_data event_data = {0};

    event_data.rio_vmi = rio_vmi;
    event_data.bp_vaddr = addr;
    continue_until_event.data = &event_data;
    // get paddr
    status = vmi_translate_kv2p(rio_vmi->vmi, addr, &paddr);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to get paddr for 0x%lx\n", addr);
        return false;
    }
    gfn = paddr >> 12;

    SETUP_MEM_EVENT(&continue_until_event, gfn, VMI_MEMACCESS_X, cb_on_continue_until_event, 0);

    status = vmi_register_event(rio_vmi->vmi, &continue_until_event);
    if (status == VMI_FAILURE)
    {
        eprintf("vmi event registration failure\n");
        return false;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to resume VM\n");
        return false;
    }

    interrupted = false;
    while (!interrupted)
    {
        printf("Listening on VMI events...\n");
        status = vmi_events_listen(rio_vmi->vmi, 1000);
        if (status == VMI_FAILURE)
        {
            interrupted = true;
            return false;
        }
    }

    // unregister cr3 event
    status = vmi_clear_event(rio_vmi->vmi, &continue_until_event, NULL);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to clear event\n");
        return false;
    }
    return true;
}

bool attach_new_process(RDebug *dbg)
{
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;
    addr_t resume_thread_addr;

    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;

    status = vmi_translate_ksym2v(rio_vmi->vmi, "NtResumeThread", &resume_thread_addr);
    if (status == VMI_FAILURE)
    {
        eprintf("Unable to get symbol\n");
        return false;
    }
    printf("NtResumeThread: 0x%lx\n", resume_thread_addr);
    continue_until(rio_vmi, resume_thread_addr);
    return true;
}
