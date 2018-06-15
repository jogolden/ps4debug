/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#ifndef KSDK_H
#define KSDK_H

#include <stdint.h>
#include <stdarg.h>

#include "sparse.h"
#include "ksdk_util.h"
#include "ksdk_bsd.h"

#define __Xfast_syscall 0x1C0

#define KFUNC(slide, name, ret, args) \
    extern ret (*name) args
#define KDATA(slide, name, type) \
    extern type* name
#include "ksdk.inc"
#undef KFUNC
#undef KDATA

uint64_t get_kbase();
void init_ksdk();

#endif /* KSDK_H */
