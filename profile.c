#include <r_lib.h>

#include "profile.h"

addr_t static get_kernel_base(vmi_instance_t vmi, json_object *root)
{
    addr_t kernel_base;
    status_t status;

    // get $CONSTANTS
    json_object* constants = NULL;
    if (!json_object_object_get_ex(root, "$CONSTANTS", &constants))
        goto outerr;

    // get PsActiveProcessHead
    json_object* process_head = NULL;
    if (!json_object_object_get_ex(constants, "PsActiveProcessHead", &process_head))
        goto outerr;

    // get PsActiveProcessHead rva;
    addr_t process_head_rva = json_object_get_int64(process_head);

    // translate PsActiveProcessHead with vmi_translate
    addr_t process_head_addr;
    status = vmi_translate_ksym2v(vmi, "PsActiveProcessHead", &process_head_addr);
    if (status == VMI_FAILURE)
        goto outerr;

    // get kernel base address
    kernel_base = process_head_addr - process_head_rva;

    return kernel_base;

outerr:
    eprintf("Fail to get kernel base\n");
    return 0;
}

bool static load_symbols_section(RIO *io, json_object *root,
                                 const char *section_name, addr_t kernel_base)
{
    json_object* section = NULL;
    if (!json_object_object_get_ex(root, section_name, &section))
        goto outerr;

    addr_t symbol_addr;
    char cmd[2048];
    json_object_object_foreach(section, key, val) {
        // skip symbols starting with str:
        if (!strncmp(key, "str:", strlen("str:")))
            continue;

        // skip symbols containing an @
        if (strchr(key, '@'))
            continue;

        symbol_addr = kernel_base + json_object_get_int64(val);
        // printf("symbol: %s, addr: 0x%lx\n", key, symbol_addr);
        bzero(cmd, 2048);
        snprintf(cmd, 2048, "f rekall.%s = 0x%lx\n", key, symbol_addr);
        io->cb_printf(cmd);
    }

    return true;
outerr:
    eprintf("Cannot load section %s\n", section_name);
    return false;
}

bool load_symbols(RIO *io, vmi_instance_t vmi)
{
    const char* profile_path = NULL;
    json_object* root = NULL;
    addr_t kernel_base;

    // get rekall profile
    profile_path = vmi_get_rekall_path(vmi);
    if (!profile_path)
    {
        eprintf("Libvmi config has no Rekall profile path\n");
        return false;
    }

    // load as json
    root = json_object_from_file(profile_path);
    if (!root)
        goto outerr;

    // get kernel base
    kernel_base = get_kernel_base(vmi, root);
    if (!kernel_base)
        goto outerr;

    if (!load_symbols_section(io, root, "$CONSTANTS", kernel_base))
        goto outerr;

    if (!load_symbols_section(io, root, "$FUNCTIONS", kernel_base))
        goto outerr;

    if (root)
        json_object_put(root);
    return true;

outerr:
    eprintf("Error while parsing JSON Rekall profile\n");
    if (root)
        json_object_put(root);
    return false;
}
