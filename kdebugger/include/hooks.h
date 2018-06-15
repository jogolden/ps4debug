// golden
// 6/12/2018
//

#ifndef _HOOKS_H
#define _HOOKS_H

#include <ksdk.h>
#include "proc.h"

#define __sysent 0x107C610

TYPE_BEGIN(struct sysent, 0x30);
TYPE_FIELD(uint32_t sy_narg, 0x00);
TYPE_FIELD(void *sy_call, 0x08);
TYPE_FIELD(uint16_t sy_auevent, 0x10);
TYPE_FIELD(uint64_t sy_systrace_args_func, 0x18);
TYPE_FIELD(uint32_t sy_entry, 0x20);
TYPE_FIELD(uint32_t sy_return, 0x24);
TYPE_FIELD(uint32_t sy_flags, 0x28);
TYPE_FIELD(uint32_t sy_thrcnt, 0x2C);
TYPE_END();

extern struct sysent *sysents;

// custom syscall 107
struct sys_proc_read_args {
    uint64_t pid;
    uint64_t address;
    void *data;
    uint64_t length;
};
int sys_proc_read(struct thread *td, struct sys_proc_read_args *uap);

// custom syscall 108
struct sys_proc_write_args {
    uint64_t pid;
    uint64_t address;
    void *data;
    uint64_t length;
};
int sys_proc_write(struct thread *td, struct sys_proc_write_args *uap);

// custom syscall 109
#define SYS_PROC_CMD_ALLOC      1
#define SYS_PROC_CMD_FREE       2
#define SYS_PROC_CMD_PROTECT    3
#define SYS_PROC_VM_MAP         4
#define SYS_PROC_CMD_CALL       5
struct sys_proc_cmd_args {
    uint64_t pid;
    uint64_t cmd;
    void *data;
};
int sys_proc_cmd(struct thread *td, struct sys_proc_cmd_args *uap);

// custom syscall 110
struct sys_kern_base_args {
    uint64_t *kbase;
};
int sys_kern_base(struct thread *td, struct sys_kern_base_args *uap);

// custom syscall 111
struct sys_kern_read_args {
    uint64_t address;
    void *data;
    uint64_t length;
};
int sys_kern_read(struct thread *td, struct sys_kern_read_args *uap);

// custom syscall 112
struct sys_kern_write_args {
    uint64_t address;
    void *data;
    uint64_t length;
};
int sys_kern_write(struct thread *td, struct sys_kern_write_args *uap);

int install_hooks();

#endif
