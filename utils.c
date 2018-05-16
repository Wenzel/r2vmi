#include <inttypes.h>

#include "utils.h"
#include "io_vmi.h"

#define LINEAR48(x)    ((x) &= 0xffffffffffff)

static bool interrupted = false;

typedef struct
{
    // store the mem_event, because we need to register it
    // when inside the single step callback
    vmi_event_t *mem_event;
    addr_t target_vaddr;
    addr_t target_gfn;
    RIOVmi *rio_vmi;
} breakpoint_cb_data;

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

static event_response_t cb_on_sstep(vmi_instance_t vmi, vmi_event_t *event)
{
    status_t status;
    breakpoint_cb_data *cb_data = NULL;
    char *proc_name = NULL;

    printf("%s\n", __func__);

    if(!event || event->type != VMI_EVENT_SINGLESTEP || !event->data) {
        eprintf("ERROR (%s): invalid event encounted\n", __func__);
        return 0;
    }

    // get event data
    cb_data = (breakpoint_cb_data*)(event->data);

    // same page ?
    if (event->ss_event.gfn != cb_data->target_gfn)
    {
        // out of the targeted page
        // reregister mem_event
        status = vmi_register_event(vmi, cb_data->mem_event);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to register event\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
        // toggle singlestep OFF
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    // hit target ?
    if (!vaddr_equal(vmi, event->x86_regs->rip, cb_data->target_vaddr))
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    // hit
    proc_name = dtb_to_pname(vmi, event->x86_regs->cr3);
    if (!proc_name)
        proc_name = "NEW_PROCESS.EXE";

    printf("At KiStartUserThread: %s, CR3: 0x%lx\n", proc_name, event->x86_regs->cr3);
    if (is_target_process(cb_data->rio_vmi, proc_name, event->x86_regs->cr3))
    {
        status = vmi_pause_vm(vmi);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to resume VM\n");
            return false;
        }

        interrupted = true;
        // toggle singlestep OFF
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t cb_on_continue_until_event(vmi_instance_t vmi, vmi_event_t *event)
{
    status_t status;
    breakpoint_cb_data *cb_data;
    const char* proc_name = NULL;

    printf("%s\n", __func__);

    if(!event || event->type != VMI_EVENT_MEMORY || !event->data) {
        eprintf("ERROR (%s): invalid event encounted\n", __func__);
        return 0;
    }

    // get event data
    cb_data = (breakpoint_cb_data*)(event->data);

    // our address ?
    if (!vaddr_equal(vmi, event->x86_regs->rip, cb_data->target_vaddr))
    {
        eprintf("Wrong RIP: 0x%lx\n", event->x86_regs->rip);
        // unregister mem_event to lift page permissions
        status = vmi_clear_event(vmi, event, NULL);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to clear event\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
        // toggle singlestep ON
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    // it's a hit !
    proc_name = dtb_to_pname(vmi, event->x86_regs->cr3);
    if (!proc_name)
        proc_name = "NEW_PROCESS.EXE";

    printf("At KiStartUserThread: %s, CR3: 0x%lx\n", proc_name, event->x86_regs->cr3);
    if (is_target_process(cb_data->rio_vmi, proc_name, event->x86_regs->cr3))
    {
        status = vmi_pause_vm(vmi);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to resume VM\n");
            return false;
        }

        interrupted = true;
    }
    return VMI_EVENT_RESPONSE_NONE;
}

static bool continue_until(RIOVmi *rio_vmi, addr_t addr)
{
    printf("%s\n", __func__);
    status_t status;
    addr_t paddr;
    addr_t gfn;
    vmi_event_t mem_event = {0};
    breakpoint_cb_data cb_data = {0};

    // get nb vcpu
    int nb_vcpu = vmi_get_num_vcpus(rio_vmi->vmi);

    // build single step events
    vmi_event_t ss_events[nb_vcpu];
    for (int i = 0; i < nb_vcpu; i++)
    {
        bzero(&ss_events[i], sizeof(vmi_event_t));
        // prepare the event, but don't enable single step yet
        SETUP_SINGLESTEP_EVENT(&ss_events[i], 1u << i, cb_on_sstep, false);
        // assign event data
        ss_events[i].data = (void*)&cb_data;
        // register
        status = vmi_register_event(rio_vmi->vmi, &ss_events[i]);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to register event\n");
            return false;
        }
    }

    // build memory event
    // get paddr
    status = vmi_translate_kv2p(rio_vmi->vmi, addr, &paddr);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to get paddr for 0x%lx\n", addr);
        return false;
    }
    gfn = paddr >> 12;
    SETUP_MEM_EVENT(&mem_event, gfn, VMI_MEMACCESS_X, cb_on_continue_until_event, false);
    // assign data
    mem_event.data = (void*)&cb_data;
    // register
    status = vmi_register_event(rio_vmi->vmi, &mem_event);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to register event\n");
        return false;
    }

    // fill callback_data
    cb_data.mem_event = &mem_event;
    cb_data.target_vaddr = addr;
    cb_data.target_gfn = gfn;
    cb_data.rio_vmi = rio_vmi;

    // resume vm execution
    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to resume VM\n");
        return false;
    }

    // listen
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

    // clear mem_event
    status = vmi_clear_event(rio_vmi->vmi, &mem_event, NULL);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to clear event\n");
        return false;
    }

    // clear single step
    for (int i = 0; i < nb_vcpu; i++)
    {
        status = vmi_clear_event(rio_vmi->vmi, &ss_events[i], NULL);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to clear event\n");
            return false;
        }
    }
    return true;
}

bool attach_new_process(RDebug *dbg)
{
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;
    addr_t start_thread_addr;

    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;

    status = vmi_translate_ksym2v(rio_vmi->vmi, "KiStartUserThread", &start_thread_addr);
    if (status == VMI_FAILURE)
    {
        eprintf("Unable to get symbol\n");
        return false;
    }
    printf("KiStartUserThread: 0x%lx\n", start_thread_addr);
    continue_until(rio_vmi, start_thread_addr);
    // set pid and proc name

    return true;
}

bool is_target_process(RIOVmi *rio_vmi, const char *proc_name, uint64_t dtb)
{
    int pid;
    status_t status;

    status = vmi_dtb_to_pid(rio_vmi->vmi, dtb, &pid);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to get pid\n");
        return false;
    }

    if (rio_vmi->url_identify_by_name &&
            !strncasecmp(proc_name, rio_vmi->proc_name, strlen(rio_vmi->proc_name)))
    {
        rio_vmi->pid = pid;
        return true;
    }
    else if (!rio_vmi->url_identify_by_name && pid == rio_vmi->pid)
    {
        rio_vmi->proc_name = strdup(proc_name);
        return true;
    }
    return false;
}
