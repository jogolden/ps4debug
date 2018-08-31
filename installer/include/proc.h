// golden
// 6/12/2018
//

#ifndef _PROC_H
#define _PROC_H

#include <ksdk.h>
#include "rpcasm.h"
#include "elf.h"

#define PAGE_SIZE 0x4000

struct proc_vm_map_entry {
    char name[32];
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint16_t prot;
} __attribute__((packed));

struct proc *proc_find_by_name(const char *name);
struct proc *proc_find_by_pid(int pid);
int proc_get_vm_map(struct proc *p, struct proc_vm_map_entry **entries, uint64_t *num_entries);

int proc_rw_mem(struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n, int write);
int proc_read_mem(struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n);
int proc_write_mem(struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n);
int proc_allocate(struct proc*p, void **address, uint64_t size);
int proc_deallocate(struct proc *p, void *address, uint64_t size);
int proc_mprotect(struct proc *p, void *address, void *end, int new_prot);
int proc_create_thread(struct proc *p, uint64_t address);
int proc_map_elf(struct proc *p, void *elf, void *exec);
int proc_relocate_elf(struct proc *p, void *elf, void *exec);
int proc_load_elf(struct proc *p, void *elf, uint64_t *elfbase, uint64_t *entry);

#endif
