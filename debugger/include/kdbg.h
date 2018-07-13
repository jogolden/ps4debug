// golden
// 6/12/2018
//

#ifndef _KDEBUGGER_H
#define _KDEBUGGER_H

#include <ps4.h>
#include <stdarg.h>

// custom syscall 107
struct proc_list_entry {
    char p_comm[32];
    int pid;
}  __attribute__((packed));
void sys_proc_list(struct proc_list_entry *procs, uint64_t *num);

// custom syscall 108
void sys_proc_rw(uint64_t pid, uint64_t address, void *data, uint64_t length, uint64_t write);

// custom syscall 109
#define SYS_PROC_ALLOC      1
#define SYS_PROC_FREE       2
#define SYS_PROC_PROTECT    3
#define SYS_PROC_VM_MAP     4
#define SYS_PROC_INSTALL    5
#define SYS_PROC_CALL       6
struct proc_vm_map_entry {
	char name[32];
	uint64_t start;
	uint64_t end;
	uint64_t offset;
	uint16_t prot;
} __attribute__((packed));
struct sys_proc_vm_map_args {
    struct proc_vm_map_entry *maps;
    uint64_t num;
} __attribute__((packed));
void sys_proc_cmd(uint64_t pid, uint64_t cmd, void *data);

// custom syscall 110
void sys_kern_base(uint64_t *kbase);

// custom syscall 111
void sys_kern_rw(uint64_t address, void *data, uint64_t length, uint64_t write);

// custom syscall 112
#define SYS_CONSOLE_CMD_REBOOT       1
#define SYS_CONSOLE_CMD_PRINT        2
void sys_console_cmd(uint64_t cmd, void *data);

#define uprintf(fmt, ...) { char buffer[256]; snprintf(buffer, 256, fmt, ##__VA_ARGS__); sys_console_cmd(SYS_CONSOLE_CMD_PRINT, buffer); }

#endif
