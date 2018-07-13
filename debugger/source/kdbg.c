// golden
// 6/12/2018
//

#include "kdbg.h"

// custom syscall 107
void sys_proc_list(struct proc_list_entry *procs, uint64_t *num) {
    syscall(107, procs, num);
}

// custom syscall 108
void sys_proc_rw(uint64_t pid, uint64_t address, void *data, uint64_t length, uint64_t write) {
    syscall(108, pid, address, data, length, write);
}

// custom syscall 109
#define SYS_PROC_CMD_ALLOC      1
#define SYS_PROC_CMD_FREE       2
#define SYS_PROC_CMD_PROTECT    3
#define SYS_PROC_VM_MAP         4
#define SYS_PROC_CMD_CALL       5
void sys_proc_cmd(uint64_t pid, uint64_t cmd, void *data) {
    syscall(109, pid, cmd, data);
}

// custom syscall 110
void sys_kern_base(uint64_t *kbase) {
    syscall(110, kbase);
}

// custom syscall 111
void sys_kern_rw(uint64_t address, void *data, uint64_t length, uint64_t write) {
    syscall(111, address, data, length, write);
}

// custom syscall 112
void sys_console_cmd(uint64_t cmd, void *data) {
    syscall(112, cmd, data);
}
