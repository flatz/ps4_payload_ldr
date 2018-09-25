#pragma once

#include "common.h"

#define SYS_supercall 394
#define SYS_gain_privileges 410
#define SYS_dynlib_get_info 593

int syscall(int num, ...);
