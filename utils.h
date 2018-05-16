#ifndef UTILS_H
#define UTILS_H

#include <r_debug.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include "io_vmi.h"

void print_event(vmi_event_t *event);
bool vaddr_equal(vmi_instance_t vmi, addr_t vaddr1, addr_t vaddr2);
char* dtb_to_pname(vmi_instance_t vmi, addr_t dtb);
bool attach_new_process(RDebug *dbg);
bool is_target_process(RIOVmi *rio_vmi, const char *proc_name, uint64_t dtb);

#endif // !UTILS_h
