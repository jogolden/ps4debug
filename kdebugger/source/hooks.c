// golden
// 6/12/2018
//

#include "hooks.h"

inline void write_jmp(uint64_t address, uint64_t destination) {
    // absolute jump
    *(uint8_t *)(address) = 0xFF;
    *(uint8_t *)(address + 1) = 0x25;
    *(uint8_t *)(address + 2) = 0x00;
    *(uint8_t *)(address + 3) = 0x00;
    *(uint8_t *)(address + 4) = 0x00;
    *(uint8_t *)(address + 5) = 0x00;
    *(uint64_t *)(address + 6) = destination;
}

int sys_proc_list(struct thread *td, struct sys_proc_list_args *uap) {
    struct proc *p;
    int num;
    int r;

    r = 0;

    if(!uap->num) {
        r = 1;
        goto finish;
    }

    if(!uap->procs) {
        // count
        num = 0;
        p = *allproc;
        do {
            num++;
        } while ((p = p->p_forw));
        
        *uap->num = num;
    } else {
        // fill structure
        num = *uap->num;
        p = *allproc;
        for (int i = 0; i < num; i++) {
            memcpy(uap->procs[i].p_comm, p->p_comm, sizeof(uap->procs[i].p_comm));
            uap->procs[i].pid = p->pid;

            if (!(p = p->p_forw)) {
                break;
            }
        }
    }

finish:
    td->td_retval[0] = r;
    return r;
}

int sys_proc_rw(struct thread *td, struct sys_proc_rw_args *uap) {
    struct proc *p;
    int r;

    r = 1;

    p = proc_find_by_pid(uap->pid);
    if(p) {
        r = proc_rw_mem(p, (void *)uap->address, uap->length, uap->data, 0, uap->write);
    }
    
    td->td_retval[0] = r;
    return r;
}

int sys_proc_alloc_handle(struct proc *p, struct sys_proc_alloc_args *args) {
    uint64_t address;

    if(proc_allocate(p, (void **)&address, args->length)) {
        return 1;
    }

    args->address = address;
    
    return 0;
}

int sys_proc_free_handle(struct proc *p, struct sys_proc_free_args *args) {
    return proc_deallocate(p, (void *)args->address, args->length);
}

int sys_proc_protect_handle(struct proc *p, struct sys_proc_protect_args *args) {
    return proc_mprotect(p, (void *)args->address, args->length, args->prot);
}

int sys_proc_vm_map_handle(struct proc *p, struct sys_proc_vm_map_args *args) {
    struct vmspace *vm;
    struct vm_map *map;
    struct vm_map_entry *entry;

    vm = p->p_vmspace;
    map = &vm->vm_map;

    vm_map_lock_read(map);

    if(!args->maps) {
        args->num = map->nentries;
    } else {
        if(vm_map_lookup_entry(map, NULL, &entry)) {
            vm_map_unlock_read(map);
            return 1;
        }

        for (int i = 0; i < args->num; i++) {
            args->maps[i].start = entry->start;
            args->maps[i].end = entry->end;
            args->maps[i].offset = entry->offset;
            args->maps[i].prot = entry->prot & (entry->prot >> 8);
            memcpy(args->maps[i].name, entry->name, sizeof(args->maps[i].name));
            
            if(!(entry = entry->next)) {
                break;
            }
        }
    }

    vm_map_unlock_read(map);

    return 0;
}

int sys_proc_install_handle(struct proc *p, struct sys_proc_install_args *args) {
    void *stubaddr;
    uint64_t stubsize = sizeof(rpcstub);
    stubsize += (PAGE_SIZE - (stubsize % PAGE_SIZE));

    // allocate memory for the stub
    if(proc_allocate(p, &stubaddr, stubsize)) {
        return 1;
    }

    // write the actual stub
    if(proc_write_mem(p, stubaddr, sizeof(rpcstub), (void *)rpcstub, NULL)) {
        return 1;
    }

    // load stub
    uint64_t stubentryaddr = (uint64_t)stubaddr + *(uint64_t *)(rpcstub + 4);
    if(proc_create_thread(p, stubentryaddr)) {
        return 1;
    }

    args->stubentryaddr = (uint64_t)stubaddr;

    return 0;
}

int sys_proc_call_handle(struct proc *p, struct sys_proc_call_args *args) {

    uint64_t rpcstub = args->rpcstub;
    // write registers
    // these two structures are basically 1:1 (it is hackey but meh)
    uint64_t regsize = offsetof(struct rpcstub_header, rpc_rax) - offsetof(struct rpcstub_header, rpc_rip);
    if (proc_write_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_rip)), regsize, &args->rip, NULL)) {
        return 1;
    }

    // trigger call
    uint8_t go = 1;
    if (proc_write_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_go)), sizeof(go), &go, NULL)) {
        return 1;
    }

    // check until done
    uint8_t done = 0;
    while (!done) {
        if (proc_read_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_done)), sizeof(done), &done, NULL)) {
            return 1;
        }
    }

    // write done to be zero
    done = 0;
    if (proc_write_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_done)), sizeof(done), &done, NULL)) {
        return 1;
    }

    // return value
    uint64_t rax = 0;
    if (proc_read_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_rax)), sizeof(rax), &rax, NULL)) {
        return 1;
    }

    args->rax = rax;

    return 0;
}

int sys_proc_elf_handle(struct proc *p, struct sys_proc_elf_args *args) {
    struct proc_vm_map_entry *entries;
    uint64_t num_entries;
    uint64_t entry;

    // load the elf into the process
    if(proc_load_elf(p, args->elf, NULL, &entry)) {
        return 1;
    }

    // change main executable protection in process to rwx
    if(proc_get_vm_map(p, &entries, &num_entries)) {
        return 1;
    }

    for (int i = 0; i < num_entries; i++) {
        if (entries[i].prot != (PROT_READ | PROT_EXEC)) {
            continue;
        }

        if (!memcmp(entries[i].name, "executable", 10)) {
            proc_mprotect(p, (void *)entries[i].start, (uint64_t)(entries[i].end - entries[i].start), VM_PROT_ALL);
            break;
        }
    }

    // launch the elf in a new thread
    if(proc_create_thread(p, entry)) {
        return 1;
    }

    return 0;
}

int sys_proc_info_handle(struct proc *p, struct sys_proc_info_args *args) {
    args->pid = p->pid;
    memcpy(args->name, p->p_comm, sizeof(args->name));
    memcpy(args->path, p->path, sizeof(args->path));
    memcpy(args->titleid, p->titleid, sizeof(args->titleid));
    memcpy(args->contentid, p->contentid, sizeof(args->contentid));
    return 0;
}

int sys_proc_thrinfo_handle(struct proc *p, struct sys_proc_thrinfo_args *args) {
    struct thread *thr;

    TAILQ_FOREACH(thr, &p->p_threads, td_plist) {
        if(thr->tid == args->lwpid) {
            args->priority = thr->td_priority;
            memcpy(args->name, thr->td_name, sizeof(args->name));
            break;
        }
    }

    if(thr && thr->tid == args->lwpid) {
        return 0;
    }

    return 1;
}

int sys_proc_cmd(struct thread *td, struct sys_proc_cmd_args *uap) {
    struct proc *p;
    int r;

    p = proc_find_by_pid(uap->pid);
    if(!p) {
        r = 1;
        goto finish;
    }

    switch(uap->cmd) {
        case SYS_PROC_ALLOC:
            r = sys_proc_alloc_handle(p, (struct sys_proc_alloc_args *)uap->data);
            break;
        case SYS_PROC_FREE:
            r = sys_proc_free_handle(p, (struct sys_proc_free_args *)uap->data);
            break;
        case SYS_PROC_PROTECT:
            r = sys_proc_protect_handle(p, (struct sys_proc_protect_args *)uap->data);
            break;
        case SYS_PROC_VM_MAP:
            r = sys_proc_vm_map_handle(p, (struct sys_proc_vm_map_args *)uap->data);
            break;
        case SYS_PROC_INSTALL:
            r = sys_proc_install_handle(p, (struct sys_proc_install_args *)uap->data);
            break;
        case SYS_PROC_CALL:
            r = sys_proc_call_handle(p, (struct sys_proc_call_args *)uap->data);
            break;
        case SYS_PROC_ELF:
            r = sys_proc_elf_handle(p, (struct sys_proc_elf_args *)uap->data);
            break;
        case SYS_PROC_INFO:
            r = sys_proc_info_handle(p, (struct sys_proc_info_args *)uap->data);
            break;
        case SYS_PROC_THRINFO:
            r = sys_proc_thrinfo_handle(p, (struct sys_proc_thrinfo_args *)uap->data);
            break;
        default:
            r = 1;
            break;
    }

finish:
    td->td_retval[0] = r;
    return r;
}

int sys_kern_base(struct thread *td, struct sys_kern_base_args *uap) {
    *uap->kbase = get_kbase();
    td->td_retval[0] = 0;
    return 0;
}

int sys_kern_rw(struct thread *td, struct sys_kern_rw_args *uap) {
    if(uap->write) {
        cpu_disable_wp();
        memcpy((void *)uap->address, uap->data, uap->length);
        cpu_enable_wp();
    } else {
        memcpy(uap->data, (void *)uap->address, uap->length);
    }

    td->td_retval[0] = 0;
    return 0;
}

int sys_console_cmd(struct thread *td, struct sys_console_cmd_args *uap) {
    switch(uap->cmd) {
        case SYS_CONSOLE_CMD_REBOOT:
            kern_reboot(0);
            break;
        case SYS_CONSOLE_CMD_PRINT:
            if(uap->data) {
                printf("[ps4debug] %s\n", uap->data);
            }
            break;
        case SYS_CONSOLE_CMD_JAILBREAK: {
            struct ucred* cred;
            struct filedesc* fd;
            struct thread *td;

            td = curthread();
            fd = td->td_proc->p_fd;
            cred = td->td_proc->p_ucred;

            cred->cr_uid = 0;
            cred->cr_ruid = 0;
            cred->cr_rgid = 0;
            cred->cr_groups[0] = 0;
            cred->cr_prison = *prison0;
            fd->fd_rdir = fd->fd_jdir = *rootvnode;
            break;
        }
    }

    td->td_retval[0] = 0;
    return 0;
}

void hook_trap_fatal(struct trapframe *tf) {
    // print registers
    const char regnames[15][8] = { "rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax", "rbx", "rbp", "r10", "r11", "r12", "r13", "r14", "r15" };
    for(int i = 0; i < 15; i++) {
        uint64_t rv = *(uint64_t *)((uint64_t)tf + (sizeof(uint64_t) * i));
        printf("    %s %llX %i\n", regnames[i], rv, rv);
    }
    printf("    rip %llX %i\n", tf->tf_rip, tf->tf_rip);
    printf("    rsp %llX %i\n", tf->tf_rsp, tf->tf_rsp);

    uint64_t sp = 0;
    if ((tf->tf_rsp & 3) == 3) {
        sp = *(uint64_t *)(tf + 1);
    } else {
        sp = (uint64_t)(tf + 1);
    }

    // stack backtrace
    uint64_t kernbase = get_kbase();
    printf("kernelbase: 0x%llX\n", kernbase);
    uint64_t backlog = 128;
    printf("stack backtrace (0x%llX):\n", sp);
    for (int i = 0; i < backlog; i++) {
        uint64_t sv = *(uint64_t *)((sp - (backlog * sizeof(uint64_t))) + (i * sizeof(uint64_t)));
        if (sv > kernbase) {
            printf("    %i <kernbase>+0x%llX\n", i, sv - kernbase);
        }
    }

    kern_reboot(4);
}

void install_syscall(uint32_t n, void *func) {
    struct sysent *p = &sysents[n];
    memset(p, NULL, sizeof(struct sysent));
    p->sy_narg = 8;
    p->sy_call = func;
    p->sy_thrcnt = 1;
}

int install_hooks() {
    cpu_disable_wp();

    // trap_fatal hook
    uint64_t kernbase = get_kbase();
    memcpy((void *)(kernbase + 0x1718D8), "\x4C\x89\xE7", 3); // mov rdi, r12
    write_jmp(kernbase + 0x1718DB, (uint64_t)hook_trap_fatal);

    // proc
    install_syscall(107, sys_proc_list);
    install_syscall(108, sys_proc_rw);
    install_syscall(109, sys_proc_cmd);

    // kern
    install_syscall(110, sys_kern_base);
    install_syscall(111, sys_kern_rw);

    // console
    install_syscall(112, sys_console_cmd);

    cpu_enable_wp();

    return 0;
}
