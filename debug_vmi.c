#include <r_asm.h>
#include <r_debug.h>
#include <strings.h>

#include "io_vmi.h"
#include "utils.h"

static RIOVmi *g_rio_vmi = NULL;

// vmi_events_listen loop
static bool interrupted = false;


//
// callbacks
//
static event_response_t cb_on_mem_event(vmi_instance_t vmi, vmi_event_t *event){
    status_t status;
    bp_event_data *event_data;
    const char *pname = NULL;

    printf("%s\n", __func__);

    if(!event || event->type != VMI_EVENT_MEMORY || !event->data) {
        eprintf("ERROR (%s): invalid event encounted\n", __func__);
        return 0;
    }

    // get event_data
    event_data = (bp_event_data*) event->data;

    pname = dtb_to_pname(vmi, event->x86_regs->cr3);

    // at the right rip ?
    if (!vaddr_equal(vmi, event->x86_regs->rip, event_data->bp_vaddr))
    {
        eprintf("mem_event: wrong rip: %"PRIx64" (bp_vaddr: %"PRIx64")\n", event->x86_regs->rip, event_data->bp_vaddr);
        return VMI_EVENT_RESPONSE_EMULATE;
    }

    // our pid ?
    if (event->x86_regs->cr3 != event_data->pid_cr3)
    {
        eprintf("mem_event: wrong cr3 (%s)\n", pname);
        return VMI_EVENT_RESPONSE_EMULATE;
    }

    printf("RIP: %"PRIx64 " (%s)\n", event->x86_regs->rip, pname);
    print_event(event);

    // pause VM
    status = vmi_pause_vm(vmi);
    if (VMI_FAILURE == status)
        eprintf("Fail to pause vm\n");

    // stop listen
    interrupted = true;

    return 0;
}

static event_response_t cb_on_sstep(vmi_instance_t vmi, vmi_event_t *event) {
    status_t status;

    printf("%s\n", __func__);

    if(!event || event->type != VMI_EVENT_SINGLESTEP) {
        eprintf("ERROR (%s): invalid event encounted\n", __func__);
        return 0;
    }

    // stop monitoring
    interrupted = true;
    // pause the VM before exiting the callback
    status = vmi_pause_vm(vmi);
    if (status == VMI_FAILURE)
        eprintf("Fail to pause VM\n");

    return 0;
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
            eprintf("Fail to pause VM\n");
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

    status = vmi_dtb_to_pid(vmi, (addr_t) event->reg_event.value, &pid);
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
            eprintf("Fail to pause VM\n");
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

static event_response_t cb_on_int3(vmi_instance_t vmi, vmi_event_t *event){
    printf("%s\n", __func__);

    return 0;
}

static void unregister_breakpoint(gpointer key, gpointer value, gpointer user_data)
{
    addr_t bp_vaddr = (addr_t) key;
    vmi_event_t *event = (vmi_event_t*) value;
    RIOVmi *rio_vmi = (RIOVmi*) user_data;
    status_t status;

    status = vmi_clear_event(rio_vmi->vmi, event, NULL);
    if (VMI_FAILURE == status)
    {
        eprintf("Fail to clear breakpoint %"PRIx64"\n", bp_vaddr);
    }
}

static void register_breakpoint(gpointer key, gpointer value, gpointer user_data)
{
    addr_t bp_vaddr = (addr_t) key;
    vmi_event_t *event = (vmi_event_t*) value;
    RIOVmi *rio_vmi = (RIOVmi*) user_data;
    status_t status;

    status = vmi_register_event(rio_vmi->vmi, event);
    if (VMI_FAILURE == status)
    {
        eprintf("Fail to register breakpoint %"PRIx64"\n", bp_vaddr);
    }
}


//
// R2 debug interface
//
static int __step(RDebug *dbg) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;

    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    // clear all breakpoint events
    // otherwise we risk to get a breakpoint event instead of singlestep event
    // if they are on the same RIP
    g_hash_table_foreach(rio_vmi->bp_events_table, unregister_breakpoint, (gpointer) rio_vmi);

    rio_vmi->sstep_event = calloc(1, sizeof(vmi_event_t));
    rio_vmi->sstep_event->version = VMI_EVENTS_VERSION;
    rio_vmi->sstep_event->type = VMI_EVENT_SINGLESTEP;
    rio_vmi->sstep_event->callback = cb_on_sstep;
    rio_vmi->sstep_event->ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(rio_vmi->sstep_event->ss_event, rio_vmi->current_vcpu);
    status = vmi_register_event(rio_vmi->vmi, rio_vmi->sstep_event);
    if (status == VMI_FAILURE)
    {
        eprintf("Failed to register event\n");
        return false;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Failed to resume VM execution\n");
        return 1;
    }

    return true;
}


// "dc" continue execution
static int __continue(RDebug *dbg, int pid, int tid, int sig) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;

    printf("%s, sig: %d\n", __func__, sig);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (VMI_FAILURE == status)
    {
        eprintf("Failed to resume VM execution\n");
        return 1;
    }

    return 0;
}

static int __attach(RDebug *dbg, int pid) {
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


    // hack to get rio_vmi in __breakpoint
    g_rio_vmi = rio_vmi;

    status = vmi_pause_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to pause VM\n");
        return 1;
    }

    vmi_event_t cr3_load_event = {0};
    SETUP_REG_EVENT(&cr3_load_event, CR3, VMI_REGACCESS_W, 0, cb_on_cr3_load);

    // setting event data
    cr3_load_event.data = (void*) rio_vmi;

    status = vmi_register_event(rio_vmi->vmi, &cr3_load_event);
    if (status == VMI_FAILURE)
    {
        eprintf("vmi event registration failure\n");
        vmi_resume_vm(rio_vmi->vmi);
        return 1;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to resume VM\n");
        return 1;
    }


    while (!interrupted)
    {
        printf("Listening on VMI events...\n");
        status = vmi_events_listen(rio_vmi->vmi, 1000);
        if (status == VMI_FAILURE)
        {
            interrupted = true;
            return 1;
        }
    }

    // unregister cr3 event
    status = vmi_clear_event(rio_vmi->vmi, &cr3_load_event, NULL);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to clear event\n");
        return 1;
    }

    // set attached to allow reg_read
    rio_vmi->attached = true;

    // did we attached to a new process ?
    if (rio_vmi->attach_new_process)
    {
        return attach_new_process(dbg);
    }
    else
    {
        eprintf("Attaching to existing process is not implemented\n");
    }

    return 0;
}

static int __detach(RDebug *dbg, int pid) {
    printf("%s\n", __func__);

    return 1;
}

static RList* __threads(RDebug *dbg, int pid) {
    printf("%s\n", __func__);

    return NULL;
}

static RDebugReasonType __wait(RDebug *dbg, int pid) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;
    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    interrupted = false;
    while (!interrupted) {
        printf("Listen to VMI events\n");
        status = vmi_events_listen(rio_vmi->vmi, 1000);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to listen to events\n");
            return false;
        }
    }

    // clear event if singlestep
    // breakpoint events are cleared in __breakpoint if unset
    // was it a single step ?
    if (rio_vmi->sstep_event)
    {
        status = vmi_clear_event(rio_vmi->vmi, rio_vmi->sstep_event, NULL);
        if (VMI_FAILURE == status)
        {
            eprintf("Fail to clear event\n");
            return false;
        }
        free(rio_vmi->sstep_event);
        // re-register all breakpoint events that we previously unregistered
        g_hash_table_foreach(rio_vmi->bp_events_table, register_breakpoint, (gpointer) rio_vmi);
    }

    // invalidate attach_cr3
    rio_vmi->pid_cr3 = 0;

    return 0;
}

// "dm" get memory maps of target process
static RList *__map_get(RDebug* dbg) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;
    addr_t dtb = 0;
    page_mode_t page_mode;
    char unknown[] = "unknown_";

    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return NULL;
    }

    status = vmi_pid_to_dtb(rio_vmi->vmi, rio_vmi->pid, &dtb);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to get dtb from pid\n");
        return NULL;
    }

    page_mode = vmi_get_page_mode(rio_vmi->vmi, rio_vmi->current_vcpu);

    GSList *va_pages = vmi_get_va_pages(rio_vmi->vmi, dtb);
    if (!va_pages)
    {
        eprintf("Fail to get va pages\n");
        return NULL;
    }

    RList *r_maps = r_list_newf((RListFree) r_debug_map_free);
    GSList *loop = va_pages;
    int nb = 0;
    while (loop)
    {
        addr_t pte_value = 0;
        page_info_t *page = loop->data;
        int permissions = R_IO_READ;
        int supervisor = 0;
        char str_nb[20];

        // new map name
        int str_nb_size = sprintf(str_nb, "%d", nb);
        char *map_name = calloc(strlen(unknown) + str_nb_size + 1, 1);
        strncat(map_name, unknown, sizeof(unknown));
        strncat(map_name, str_nb, str_nb_size);
        // get permissions
        switch (page_mode) {
        case VMI_PM_LEGACY:
            pte_value = page->x86_legacy.pte_value;
            break;
        case VMI_PM_PAE:
            pte_value = page->x86_pae.pte_value;
            if (!VMI_GET_BIT(pte_value, 63))
                permissions |= R_IO_EXEC;
            break;
        case VMI_PM_IA32E:
            pte_value = page->x86_ia32e.pte_value;
            break;
        default:
            eprintf("Unhandled page mode");
            // TODO free
            return NULL;
        }
        supervisor = USER_SUPERVISOR(pte_value);
        if (READ_WRITE(pte_value))
            permissions |= R_IO_WRITE;
        // build RDebugMap
        addr_t map_start = page->vaddr;
        addr_t map_end = page->vaddr + page->size;
        RDebugMap *r_debug_map = r_debug_map_new (map_name, map_start, map_end, permissions, supervisor);
        // append
        r_list_append (r_maps, r_debug_map);
        // loop
        loop = loop->next;
        nb +=1;
    }

    // free va_pages
    while (va_pages)
    {
        g_free(va_pages->data);
        va_pages = va_pages->next;
    }
    g_slist_free(va_pages);

    return r_maps;
}

static RList* __modules_get(RDebug *dbg) {
    printf("%s\n", __func__);

    return NULL;
}

static int __breakpoint (void *bp, RBreakpointItem *b, bool set) {
    RBreakpoint* rbreak = NULL;
    // RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;
    addr_t bp_vaddr = b->addr;
    gboolean ret;
    vmi_event_t *bp_event = NULL;
    printf("%s, set: %d, addr: %"PRIx64", hw: %d\n", __func__, set, bp_vaddr, b->hw);

    if (!bp)
        return false;

    rbreak = (RBreakpoint*) bp;
    // i don't know how to access my desc from here
    // desc = rbreak->iob.desc_get(rbreak->iob.io, rbreak->iob.io->);
    // rio_vmi = desc->data
    // use g_rio_vmi for now
    rio_vmi = g_rio_vmi;

    if (set)
    {
        // the breakpoint API will be called multiple times for the same breakpoint
        // in case of single stepping for example, radare2 still calls this API
        // for each breakpoint before the single-step
        // therefore, check if the breakpoint has already been inserted
        bp_event = (vmi_event_t*) g_hash_table_lookup(rio_vmi->bp_events_table, GINT_TO_POINTER(bp_vaddr));
        if (!bp_event)
        {
            if (b->hw)
            {
                // need to translate the virtual address to physical
                addr_t paddr;
                status = vmi_translate_uv2p(g_rio_vmi->vmi, bp_vaddr, rio_vmi->pid, &paddr);
                if (VMI_FAILURE == status)
                {
                    eprintf("Fail to get physical addresss\n");
                    return 1;
                }

                // get guest frame number
                addr_t gfn = paddr >> 12;
                printf("paddr: %016"PRIx64", gfn: %"PRIx64"\n", paddr, gfn);

                // prepare new vmi_event
                bp_event = calloc(1, sizeof(vmi_event_t));
                if (!bp_event)
                {
                    eprintf("Fail to allocate memory\n");
                    return false;
                }
                SETUP_MEM_EVENT(bp_event, gfn, VMI_MEMACCESS_X, cb_on_mem_event, 0);
            }
            else
            {
                // write 0xCC
                const unsigned char int3 = 0xCC;
                bool result = rbreak->iob.write_at(rbreak->iob.io, b->addr, &int3, sizeof(int3));
                if (!result)
                {
                    eprintf("Fail to write software breakpoint\n");
                    return false;
                }

                // prepare new vmi_event
                bp_event = calloc(1, sizeof(vmi_event_t));
                if (!bp_event)
                {
                    eprintf("Fail to allocate memory\n");
                    return false;
                }
                SETUP_INTERRUPT_EVENT(bp_event, 0, cb_on_int3);
            }
            // add event data
            bp_event_data *event_data = calloc(1, sizeof(bp_event_data));
            if (!event_data)
            {
                eprintf("Fail to allocate memory\n");
                return false;
            }
            event_data->pid_cr3 = rio_vmi->pid_cr3;
            event_data->bp_vaddr = bp_vaddr;
            bp_event->data = event_data;

            // add our breakpoint to the hashtable
            // [bp_vaddr] -> [vmi_event *]
            ret = g_hash_table_insert(rio_vmi->bp_events_table, GINT_TO_POINTER(bp_vaddr), bp_event);
            if (FALSE == ret)
            {
                eprintf("Fail to insert event into ghashtable\n");
                return 1;
            }
            printf("after insert\n");

            // register breakpoint event
            // either interrupt or mem event
            status = vmi_register_event(rio_vmi->vmi, bp_event);
            if (VMI_FAILURE == status)
            {
                eprintf("Fail to register event\n");
                return 1;
            }
        }
    } else {
        // unset
        // get event from ghashtable
        bp_event = (vmi_event_t*) g_hash_table_lookup(rio_vmi->bp_events_table, GINT_TO_POINTER(bp_vaddr));
        if (bp_event)
        {
            // unregister event
            status = vmi_clear_event(rio_vmi->vmi, bp_event, NULL);
            if (VMI_FAILURE == status)
            {
                eprintf("Fail to clear event\n");
                return false;
            }
            if (bp_event->data)
                free(bp_event->data);
            free(bp_event);

            // remove key/value from table
            ret = g_hash_table_remove(rio_vmi->bp_events_table, GINT_TO_POINTER(bp_vaddr));
            if (FALSE == ret)
            {
                eprintf("Fail to remove key from breakpoint table\n");
                return false;
            }

            if (!b->hw)
            {
                // TODO write instruction back, replace int3
            }
        }
        else
        {
            eprintf("Fail to find breakpoint in table\n");
            return false;
        }
    }

    return true;
}

// "drp" register profile
static const char *__reg_profile(RDebug *dbg) {
    printf("%s\n", __func__);
    int arch = r_sys_arch_id (dbg->arch);
    int bits = dbg->anal->bits;

    switch (arch) {
    case R_SYS_ARCH_X86:
        switch (bits) {
        case 32:
            return strdup (
            #include "x86-32.h"
                        );
            break;
        case 64:
            return strdup (
            #include "x86-64.h"
                        );
            break;
        default:
            eprintf("bit size not supported by vmi debugger\n");
            return NULL;

        }
        break;
    default:
        eprintf("Architecture not supported by vmi debugger\n");
        return NULL;
    }

}

// "dk" send signal
static bool __kill(RDebug *dbg, int pid, int tid, int sig) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    printf("%s, sig: %d\n", __func__, sig);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return false;
    }

    if (sig < 0 || sig > 31)
        return false;
    return true;
}

static int __select(int pid, int tid) {
    printf("%s\n", __func__);

    return 1;
}

static RDebugInfo* __info(RDebug *dbg, const char *arg) {
    printf("%s\n", __func__);

    return NULL;
}

static RList* __frames(RDebug *dbg, ut64 at) {
    printf("%s\n", __func__);

    return NULL;
}

static int __reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status = 0;
    int buf_size = 0;
    pid_t pid;
    uint64_t cr3 = 0;
    registers_t regs;

    printf("%s, type: %d, size:%d\n", __func__, type, size);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    if (!rio_vmi->attached)
        return 0;

    unsigned int nb_vcpus = vmi_get_num_vcpus(rio_vmi->vmi);

    bool found = false;
    for (int vcpu = 0; vcpu < nb_vcpus; vcpu++)
    {
        // get cr3
        // if we have just attached, we cannot rely on vcpu_reg() since the VCPU
        // state has not been synchronized with the new CR3 value from the attach event
        if (rio_vmi->pid_cr3)
            cr3 = rio_vmi->pid_cr3;
        else
        {
            status = vmi_get_vcpureg(rio_vmi->vmi, &cr3, CR3, vcpu);
            if (status == VMI_FAILURE)
            {
                eprintf("Fail to get vcpu registers\n");
                return 1;
            }
        }
        // convert to pid
        status = vmi_dtb_to_pid(rio_vmi->vmi, cr3, &pid);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to convert CR3 to PID\n");
            return 1;
        }
        if (pid == rio_vmi->pid)
        {
            found = true;

            // get registers
            status = vmi_get_vcpuregs(rio_vmi->vmi, &regs, vcpu);
            if (status == VMI_FAILURE)
            {
                eprintf("Fail to get vcpu registers\n");
                return 1;
            }
            break;
        }
    }
    if (!found)
    {
        eprintf("Cannot find CR3 !\n");
        return 1;
    }

    int arch = r_sys_arch_id (dbg->arch);
    int bits = dbg->anal->bits;

    switch (arch) {
    case R_SYS_ARCH_X86:
        switch (bits) {
        case 32:
            eprintf("Bits not supported\n");
            return 1;
        case 64:
            memcpy(buf      , &(regs.x86.rax), sizeof(regs.x86.rax));
            memcpy(buf + 8  , &(regs.x86.rbx), sizeof(regs.x86.rbx));
            memcpy(buf + 16 , &(regs.x86.rcx), sizeof(regs.x86.rcx));
            memcpy(buf + 24 , &(regs.x86.rdx), sizeof(regs.x86.rdx));
            memcpy(buf + 32 , &(regs.x86.rsi), sizeof(regs.x86.rsi));
            memcpy(buf + 40 , &(regs.x86.rdi), sizeof(regs.x86.rdi));
            memcpy(buf + 48 , &(regs.x86.rbp), sizeof(regs.x86.rbp));
            memcpy(buf + 56 , &(regs.x86.rsp), sizeof(regs.x86.rsp));
            memcpy(buf + 64 , &(regs.x86.r8), sizeof(regs.x86.r8));
            memcpy(buf + 72 , &(regs.x86.r9), sizeof(regs.x86.r9));
            memcpy(buf + 80 , &(regs.x86.r10), sizeof(regs.x86.r10));
            memcpy(buf + 88 , &(regs.x86.r11), sizeof(regs.x86.r11));
            memcpy(buf + 96 , &(regs.x86.r12), sizeof(regs.x86.r12));
            memcpy(buf + 104 , &(regs.x86.r13), sizeof(regs.x86.r13));
            memcpy(buf + 112 , &(regs.x86.r14), sizeof(regs.x86.r14));
            memcpy(buf + 120 , &(regs.x86.r15), sizeof(regs.x86.r15));
            memcpy(buf + 128, &(regs.x86.rip), sizeof(regs.x86.rip));
            break;
        }
        break;
    default:
        eprintf("Architecture not supported\n");
        return 1;
    }
    buf_size = 128 + sizeof(uint64_t);
    // printf("RIP: %p\n", regs.x86.rip);

    return buf_size;
}

RDebugPlugin r_debug_plugin_vmi = {
    .name = "vmi",
    .license = "LGPL3",
    .arch = "x86",
    .bits = R_SYS_BITS_32 | R_SYS_BITS_64,
    .canstep = 1,
    .info = &__info,
    .attach = &__attach,
    .detach = &__detach,
    .select = &__select,
    .threads = &__threads,
    .step = &__step,
    .cont = &__continue,
    .wait = &__wait,
    .kill = &__kill,
    .frames = &__frames,
    .reg_read = &__reg_read,
    .reg_profile = (void*) &__reg_profile,
    .map_get = &__map_get,
    .modules_get = &__modules_get,
    .breakpoint = &__breakpoint,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_DBG,
    .data = &r_debug_plugin_vmi,
    .version = R2_VERSION
};
#endif
