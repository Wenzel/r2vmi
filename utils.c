#include <inttypes.h>

#include "utils.h"
#include "io_vmi.h"

#define LINEAR48(x)    ((x) &= 0xffffffffffff)

// hardcoded winxp, waiting for new libvmi rekall API
// _EPROCESS.ThreadListHead
#define EPROC_THREAD_HEAD_OFF   0x190
// _ETHREAD.Win32StartAddress
#define ETH_W32_START_OFF       0x228
// _Ethread.ThreadListEntry
#define ETH_THREAD_HEAD_OFF     0x22c

/*
// hardcoded win7, waiting for new libvmi rekall API
// _EPROCESS.ThreadListHead
#define EPROC_THREAD_HEAD_OFF   0x308
// _ETHREAD.Win32StartAddress
#define ETH_W32_START_OFF       0x418
// _Ethread.ThreadListEntry
#define ETH_THREAD_HEAD_OFF     0x428
*/

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
    eprintf("\tPAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %u)\n",
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
    case VMI_PM_PAE:
        if (vaddr1 == vaddr2)
            return true;
        break;
    default:
        eprintf("Unhandled page mode\n");
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
    // idle process ?
    status = vmi_read_addr_ksym(vmi, "PsIdleProcess", &start_proc);
    if (VMI_FAILURE == status)
    {
        return NULL;
    }
    status = vmi_read_addr_va(vmi, start_proc + pdb_offset, 0, &value);
    if (VMI_FAILURE == status)
    {
        printf("fail to read CR3\n");
        return NULL;
    }
    if (value == dtb)
    {
        return vmi_read_str_va(vmi, start_proc + name_offset, 0);
    }

    return NULL;
}

status_t vmi_dtb_to_pid_extended_idle(vmi_instance_t vmi, addr_t dtb, vmi_pid_t *pid)
{
    status_t status;
    addr_t start_proc;
    addr_t pid_offset;


    status = vmi_dtb_to_pid(vmi, dtb, pid);
    if (VMI_FAILURE == status)
    {
        // Idle process ?
        status = vmi_read_addr_ksym(vmi, "PsIdleProcess", &start_proc);
        if (VMI_FAILURE == status)
        {
            return VMI_FAILURE;
        }
        status = vmi_get_offset(vmi, "win_pid", &pid_offset);
        if (VMI_FAILURE == status)
        {
            printf("fail to get offset\n");
            return VMI_FAILURE;
        }
        status = vmi_read_32_va(vmi, start_proc + pid_offset, 0, (uint32_t*)pid);
        if (VMI_FAILURE == status)
        {
            printf("fail to read pid");
            return VMI_FAILURE;
        }
    }
    return VMI_SUCCESS;
}

static event_response_t cb_on_cr3_load(vmi_instance_t vmi, vmi_event_t *event){
    RIOVmi *rio_vmi = NULL;
    status_t status;
    pid_t pid = 0;
    char* proc_name = NULL;

    printf("%s\n", __func__);

    if(!event || event->type != VMI_EVENT_REGISTER || !event->data) {
        eprintf("ERROR (%s): invalid event encounted\n", __func__);
        return 0;
    }

    // get event data
    rio_vmi = (RIOVmi*) event->data;

    // process name
    proc_name = dtb_to_pname(vmi, event->reg_event.value);
    if (!proc_name)
    {
        printf("CR3: 0x%lx can't find process\n", event->reg_event.value);
        // stop monitoring
        interrupted = true;
        // pause the VM before we get out of main loop
        status = vmi_pause_vm(vmi);
        if (status == VMI_FAILURE)
        {
            eprintf("%s: Fail to pause VM\n", __func__);
            return 0;
        }
        // if we can't find the process in the list
        // it means we have intercepted a new CR3
        rio_vmi->attach_new_process = true;
        // set current VCPU
        rio_vmi->current_vcpu = event->vcpu_id;
        // save new CR3 value
        rio_vmi->pid_cr3 = event->reg_event.value;
        return 0;
    }

    status = vmi_dtb_to_pid_extended_idle(vmi, (addr_t) event->reg_event.value, &pid);
    if (status == VMI_FAILURE)
    {
        eprintf("ERROR (%s): fail to retrieve pid from cr3\n", __func__);
        return 0;
    }

    printf("Intercepted PID: %d, CR3: 0x%lx, Name: %s, RIP: 0x%lx\n",
           pid, event->reg_event.value, proc_name, event->x86_regs->rip);

    if (is_target_process(rio_vmi, proc_name, event->reg_event.value))
    {
        // delete old and maybe partial name for the full proc name
        free(rio_vmi->proc_name);
        rio_vmi->proc_name = strdup(proc_name);
        printf("Found %s (%d)!\n", rio_vmi->proc_name, rio_vmi->pid);
        // stop monitoring
        interrupted = true;
        // pause the VM before we get out of main loop
        status = vmi_pause_vm(vmi);
        if (status == VMI_FAILURE)
        {
            eprintf("%s: Fail to pause VM\n", __func__);
            return 0;
        }
        // set current VCPU
        rio_vmi->current_vcpu = event->vcpu_id;
        // save new CR3 value
        rio_vmi->pid_cr3 = event->reg_event.value;
    }
    free(proc_name);

    return 0;
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
        printf("out of the targeted page\n");
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
    return VMI_EVENT_RESPONSE_EMULATE;
}

static bool continue_until(RIOVmi *rio_vmi, addr_t addr, bool kernel_translate)
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
    if (kernel_translate)
        status = vmi_translate_kv2p(rio_vmi->vmi, addr, &paddr);
    else
        status = vmi_translate_uv2p(rio_vmi->vmi, rio_vmi->pid, addr, &paddr);
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
        int nb_events = vmi_are_events_pending(rio_vmi->vmi);
        printf("Listening on VMI events...%d events pending\n", nb_events);
        status = vmi_events_listen(rio_vmi->vmi, 1000);
        if (status == VMI_FAILURE)
        {
            interrupted = true;
            return false;
        }
    }

    // clear event buffer if any
    status = vmi_events_listen(rio_vmi->vmi, 0);
    if (status == VMI_FAILURE)
    {
        eprintf("fail to clear event buffer\n");
        return false;
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

static addr_t find_eprocess(vmi_instance_t vmi, uint64_t dtb)
{
    addr_t ps_head = 0;
    addr_t flink = 0;
    addr_t start_proc = 0;
    addr_t pdb_offset = 0;
    addr_t tasks_offset = 0;
    addr_t value = 0;
    status_t status;


    status = vmi_get_offset(vmi, "win_tasks", &tasks_offset);
    if (VMI_FAILURE == status)
    {
        printf("failed\n");
        return 0;
    }

    status = vmi_get_offset(vmi, "win_pdbase", &pdb_offset);
    if (VMI_FAILURE == status)
    {
        printf("failed\n");
        return 0;
    }

    status = vmi_translate_ksym2v(vmi, "PsActiveProcessHead", &ps_head);
    if (VMI_FAILURE == status)
    {
        printf("failed\n");
        return 0;
    }
    status = vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &flink);
    if (VMI_FAILURE == status)
    {
        printf("failed\n");
        return 0;
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
            return start_proc;
        }
        // read new flink
        vmi_read_addr_va(vmi, flink, 0, &flink);
    }
    return 0;
}

static addr_t find_ethread(vmi_instance_t vmi, addr_t eproc)
{
    addr_t ethread;
    addr_t thread_list_head;
    status_t status;

    status = vmi_read_addr_va(vmi, eproc + EPROC_THREAD_HEAD_OFF, 0, &thread_list_head);
    if (status == VMI_FAILURE)
    {
        eprintf("Cannot read ethread\n");
        return 0;
    }
    ethread = thread_list_head - ETH_THREAD_HEAD_OFF;
    return ethread;
}

static bool is_userland(uint64_t rflag)
{
    // extract the IOPL field
    int iopl = rflag & ((1 << 13) | (1 << 12));
    printf("iopl: %d\n", iopl);
    return (iopl == 3) ? true : false;
}

static event_response_t cb_on_sstep_until_userland(vmi_instance_t vmi, vmi_event_t *event)
{
    uint64_t rflag;

    printf("%s\n", __func__);

    if(!event || event->type != VMI_EVENT_SINGLESTEP) {
        eprintf("ERROR (%s): invalid event encounted\n", __func__);
        return 0;
    }

    // check for mem event
    addr_t paddr = 0;
    vmi_translate_kv2p(vmi, event->x86_regs->rip, &paddr);
    addr_t gfn = paddr >> 12;
    printf("Checking for mem event on page: 0x%" PRIx64 "\n", gfn);
    vmi_event_t *mem_event = vmi_get_mem_event(vmi, gfn, VMI_MEMACCESS_X);
    if (mem_event != NULL)
    {
        printf("Mem event found !\n");
    }

    rflag = event->x86_regs->rflags;
    printf("rflag: 0x%" PRIx64 ", rip: 0x%" PRIx64 "\n", rflag, event->x86_regs->rip);
    if (is_userland(rflag))
    {
        vmi_pause_vm(vmi);
        interrupted = true;
    }
    return VMI_EVENT_RESPONSE_NONE;
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
    if (VMI_FAILURE == status)
    {
        // winxp ? KiStartThread
        status = vmi_translate_ksym2v(rio_vmi->vmi, "KiThreadStartup", &start_thread_addr);
        if (VMI_FAILURE == status)
        {
            eprintf("Fail to get KiStartUserThread | KiThreadStartup symbol\n");
            return false;
        }
    }

    printf("KiStartUserThread: 0x%lx\n", start_thread_addr);
    continue_until(rio_vmi, start_thread_addr, true);

    addr_t eproc = find_eprocess(rio_vmi->vmi, rio_vmi->pid_cr3);
    if (!eproc)
    {
        eprintf("Cannot find EPROCESS\n");
        return false;
    }
    printf("EPROCESS 0x%lx\n", eproc);
    addr_t ethread = find_ethread(rio_vmi->vmi, eproc);
    if (!ethread)
    {
        eprintf("Cannot find ETHREAD\n");
        return false;
    }
    printf("ETHREAD 0x%lx\n", ethread);
    addr_t w32_start_addr;
    status = vmi_read_addr_va(rio_vmi->vmi, ethread + ETH_W32_START_OFF, 0, &w32_start_addr);
    if (status == VMI_FAILURE)
    {
        eprintf("Cannot read Win32StartAddress\n");
        return false;
    }
    printf("Win32StartAddress 0x%lx\n", w32_start_addr);

    printf("mode: %d\n", VMI_PM_IA32E);

    // singlestep until userland
    vmi_event_t sstep_event;
    sstep_event.version = VMI_EVENTS_VERSION;
    sstep_event.type = VMI_EVENT_SINGLESTEP;
    sstep_event.callback = cb_on_sstep_until_userland;
    sstep_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(sstep_event.ss_event, rio_vmi->current_vcpu);

    // register
    status = vmi_register_event(rio_vmi->vmi, &sstep_event);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to register event\n");
        return false;
    }

    // resume
    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to resume vm\n");
        return false;
    }

    interrupted = false;
    while (!interrupted)
    {
        vmi_events_listen(rio_vmi->vmi, 1000);
    }

    // process rest of event queue
    vmi_events_listen(rio_vmi->vmi, 0);

    // clear
    vmi_clear_event(rio_vmi->vmi, &sstep_event, NULL);

//    page_info_t pinfo;
//    status = vmi_pagetable_lookup_extended(rio_vmi->vmi, rio_vmi->pid_cr3, w32_start_addr, &pinfo);
//    if (status == VMI_FAILURE)
//    {
//        eprintf("Win32StartAddress is not mapped\n");
//        return false;
//    }


//    addr_t ntcontinue_addr;
//    status = vmi_translate_ksym2v(rio_vmi->vmi, "NtContinue", &ntcontinue_addr);
//    if (status == VMI_FAILURE)
//    {
//        eprintf("fail to translate symbol\n");
//        return false;
//    }

//    continue_until(rio_vmi, ntcontinue_addr, true);

//    addr_t win32startaddress_paddr;
//    status = vmi_pagetable_lookup(rio_vmi->vmi, rio_vmi->pid_cr3, w32_start_addr, &win32startaddress_paddr);
//    if (status == VMI_SUCCESS)
//    {
//        printf("Win32StartAddress is mapped\n");
//    }


//    bool win32startaddress_mapped = false;
//    while (!win32startaddress_mapped)
//    {
//        printf("continue until MmAccessFault\n");
//        addr_t mmaccessfault_vaddr;
//        // set breakpoint on MmAccessFault
//        status = vmi_translate_ksym2v(rio_vmi->vmi, "MmAccessFault", &mmaccessfault_vaddr);
//        if (status == VMI_FAILURE)
//        {
//            eprintf("fail to translate symbol\n");
//            return false;
//        }
//        continue_until(rio_vmi, mmaccessfault_vaddr, true);
//        // test if win32startaddress is mapped
//        addr_t win32startaddress_paddr;
//        status = vmi_pagetable_lookup(rio_vmi->vmi, rio_vmi->pid_cr3, w32_start_addr, &win32startaddress_paddr);
//        if (status == VMI_SUCCESS)
//        {
//            printf("Win32StartAddress is mapped\n");
//            win32startaddress_mapped = true;
//        }
//    }

    // continue
    // continue_until(rio_vmi, w32_start_addr, false);

    return true;
}

bool is_target_process(RIOVmi *rio_vmi, const char *proc_name, uint64_t dtb)
{
    int pid;
    status_t status;

    status = vmi_dtb_to_pid_extended_idle(rio_vmi->vmi, dtb, &pid);
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

bool intercept_process(RDebug *dbg, int pid)
{
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status = 0;

    printf("Attaching to pid %d...\n", pid);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    status = vmi_pause_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("%s: Fail to pause VM\n", __func__);
        return 1;
    }

    vmi_event_t cr3_load_event = {0};
    SETUP_REG_EVENT(&cr3_load_event, CR3, VMI_REGACCESS_W, 0, cb_on_cr3_load);

    // setting event data
    cr3_load_event.data = (void*) rio_vmi;

    status = vmi_register_event(rio_vmi->vmi, &cr3_load_event);
    if (status == VMI_FAILURE)
    {
        eprintf("%s: vmi event registration failure\n", __func__);
        return false;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("%s: Fail to resume VM\n", __func__);
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
    status = vmi_clear_event(rio_vmi->vmi, &cr3_load_event, NULL);
    if (status == VMI_FAILURE)
    {
        eprintf("%s Fail to clear event\n", __func__);
        return false;
    }

    // clear event buffer if any
    status = vmi_events_listen(rio_vmi->vmi, 0);
    if (status == VMI_FAILURE)
    {
        eprintf("%s: Fail to clear event buffer\n", __func__);
        return false;
    }

    return true;
}
