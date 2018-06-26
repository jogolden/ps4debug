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
struct proc_list_entry {
    char p_comm[32];
    int pid;
}  __attribute__((packed));

struct sys_proc_list_args {
    struct proc_list_entry *procs;
    uint64_t *num;
};
int sys_proc_list(struct thread *td, struct sys_proc_list_args *uap);

// custom syscall 108
struct sys_proc_rw_args {
    uint64_t pid;
    uint64_t address;
    void *data;
    uint64_t length;
    uint64_t write;
};
int sys_proc_rw(struct thread *td, struct sys_proc_rw_args *uap);

// custom syscall 109
#define SYS_PROC_ALLOC      1
#define SYS_PROC_FREE       2
#define SYS_PROC_PROTECT    3
#define SYS_PROC_VM_MAP     4
#define SYS_PROC_INSTALL    5
#define SYS_PROC_CALL       6
struct sys_proc_vm_map_args {
    struct proc_vm_map_entry *maps;
    uint64_t num;
} __attribute__((packed));

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
struct sys_kern_rw_args {
    uint64_t address;
    void *data;
    uint64_t length;
    uint64_t write;
};
int sys_kern_rw(struct thread *td, struct sys_kern_rw_args *uap);

// custom syscall 112
#define SYS_CONSOLE_CMD_REBOOT       1
struct sys_console_cmd_args {
    uint64_t cmd;
    void *data;
};
int sys_console_cmd(struct thread *td, struct sys_console_cmd_args *uap);

// custom syscall 129
struct sys_console_print_args {
    char *str;
};
int sys_console_print(struct thread *td, struct sys_console_print_args *uap);

int install_hooks();

#endif
