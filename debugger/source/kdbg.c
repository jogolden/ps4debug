// golden
// 6/12/2018
//

#include "kdbg.h"

void prefault(void *address, size_t size) {
    for(uint64_t i = 0; i < size; i++) {
        volatile uint8_t c;
        (void)c;
        
        c = ((char *)address)[i];
    }
}

void *pfmalloc(size_t size) {
    void *p = malloc(size);
    prefault(p, size);
    return p;
}

void hexdump(void *data, size_t size) {
    unsigned char *p;
    int i;

    p = (unsigned char *)data;

    for(i = 0; i < size; i++) {
        uprintf("%02X ", *p++);
        if(!(i % 16) && i != 0) {
            uprintf("\n");
        }
    }

    uprintf("\n");
}

// custom syscall 107
int sys_proc_list(struct proc_list_entry *procs, uint64_t *num) {
    return syscall(107, procs, num);
}

// custom syscall 108
int sys_proc_rw(uint64_t pid, uint64_t address, void *data, uint64_t length, uint64_t write) {
    return syscall(108, pid, address, data, length, write);
}

// custom syscall 109
#define SYS_PROC_CMD_ALLOC      1
#define SYS_PROC_CMD_FREE       2
#define SYS_PROC_CMD_PROTECT    3
#define SYS_PROC_VM_MAP         4
#define SYS_PROC_CMD_CALL       5
int sys_proc_cmd(uint64_t pid, uint64_t cmd, void *data) {
    return syscall(109, pid, cmd, data);
}

// custom syscall 110
int sys_kern_base(uint64_t *kbase) {
    return syscall(110, kbase);
}

// custom syscall 111
int sys_kern_rw(uint64_t address, void *data, uint64_t length, uint64_t write) {
    return syscall(111, address, data, length, write);
}

// custom syscall 112
int sys_console_cmd(uint64_t cmd, void *data) {
    return syscall(112, cmd, data);
}
