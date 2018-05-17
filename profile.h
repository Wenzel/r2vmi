#ifndef PROFILE_H
#define PROFILE_H

#include <r_io.h>
#include <json-c/json.h>

#include "io_vmi.h"

bool load_symbols(RIO *io, vmi_instance_t vmi);

#endif // PROFILE_H
