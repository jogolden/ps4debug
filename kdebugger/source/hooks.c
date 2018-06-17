// golden
// 6/12/2018
//

#include "hooks.h"

struct sysent *sysents;

int sys_proc_list(struct thread *td, struct sys_proc_list_args *uap) {
    struct proc *p;
    int num;

    if(!uap->num) {
        return 1;
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

    return 0;
}

int sys_proc_rw(struct thread *td, struct sys_proc_rw_args *uap) {
    struct proc *p;

    p = proc_find_by_pid(uap->pid);
    if(p) {
        return proc_rw_mem(p, (void *)uap->address, uap->length, uap->data, 0, uap->write);
    }
    
    return 0;
}

// alloc
// free
// protect

int sys_proc_vm_map_handle(struct proc *p, struct sys_proc_vm_map_args *args) {
    struct vmspace *vm;
	struct vm_map *map;
    struct vm_map_entry *entry;

    vm = p->p_vmspace;
    map = &vm->vm_map;

    if(!args->num && !args->maps) {
        args->num = map->nentries;
        return 0;
    }

    if(args->maps) {
        vm_map_lock_read(map);
        vm_map_lookup_entry(map, NULL, &entry);

        for (int i = 0; i < args->num; i++) {
            args->maps[i].start = entry->start;
            args->maps[i].end = entry->end;
            args->maps[i].offset = entry->offset;
            args->maps[i].prot = entry->prot & (entry->prot >> 8);
            memcpy(args->maps[i].name, entry->name, sizeof(args->maps[i].name));

            if (!(entry = entry->next)) {
                break;
            }
        }
        vm_map_unlock_read(map);
        return 0;
    }

    return 1;
}

// install
// call

int sys_proc_cmd(struct thread *td, struct sys_proc_cmd_args *uap) {
    struct proc *p;

    p = proc_find_by_pid(uap->pid);
    if(!p) {
        return 1;
    }

    switch(uap->cmd) {
        case SYS_PROC_ALLOC:
            __asm("int 3");
            break;
        case SYS_PROC_FREE:
            __asm("int 3");
            break;
        case SYS_PROC_PROTECT:
            __asm("int 3");
            break;
        case SYS_PROC_VM_MAP:
            return sys_proc_vm_map_handle(p, (struct sys_proc_vm_map_args *)uap->data);
        case SYS_PROC_INSTALL:
            __asm("int 3");
            break;
        case SYS_PROC_CALL:
            __asm("int 3");
            break;
    }

    return 1;
}

int sys_kern_base(struct thread *td, struct sys_kern_base_args *uap) {
    *uap->kbase = get_kbase();
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

    return 0;
}

int sys_console_cmd(struct thread *td, struct sys_console_cmd_args *uap) {
    switch(uap->cmd) {
        case SYS_CONSOLE_CMD_REBOOT:
            kern_reboot(0);
            break;
    }

    return 0;
}

int sys_console_print(struct thread *td, struct sys_console_print_args *uap) {
    if(uap->str) {
        printf("%s\n", uap->str);
    }

    return 0;
}

int install_hooks() {
    uint64_t kernbase = get_kbase();
    sysents = (void *)(kernbase + __sysent);

    cpu_disable_wp();

    struct sysent *_proc_list = &sysents[107];
    memset(_proc_list, 0, sizeof(struct sysent));
    _proc_list->sy_narg = 5;
    _proc_list->sy_call = sys_proc_list;
    _proc_list->sy_thrcnt = 1;

    struct sysent *_proc_rw = &sysents[108];
    memset(_proc_rw, 0, sizeof(struct sysent));
    _proc_rw->sy_narg = 5;
    _proc_rw->sy_call = sys_proc_rw;
    _proc_rw->sy_thrcnt = 1;

    struct sysent *_proc_cmd = &sysents[109];
    memset(_proc_cmd, 0, sizeof(struct sysent));
    _proc_cmd->sy_narg = 5;
    _proc_cmd->sy_call = sys_proc_cmd;
    _proc_cmd->sy_thrcnt = 1;

    struct sysent *_kern_base = &sysents[110];
    memset(_kern_base, 0, sizeof(struct sysent));
    _kern_base->sy_narg = 5;
    _kern_base->sy_call = sys_kern_base;
    _kern_base->sy_thrcnt = 1;

    struct sysent *_kern_rw = &sysents[111];
    memset(_kern_rw, 0, sizeof(struct sysent));
    _kern_rw->sy_narg = 5;
    _kern_rw->sy_call = sys_kern_rw;
    _kern_rw->sy_thrcnt = 1;
    
    struct sysent *_console_cmd = &sysents[112];
    memset(_console_cmd, 0, sizeof(struct sysent));
    _console_cmd->sy_narg = 5;
    _console_cmd->sy_call = sys_console_cmd;
    _console_cmd->sy_thrcnt = 1;

    struct sysent *_console_print = &sysents[129];
    memset(_console_print, 0, sizeof(struct sysent));
    _console_print->sy_narg = 5;
    _console_print->sy_call = sys_console_print;
    _console_print->sy_thrcnt = 1;

    cpu_enable_wp();

    return 0;
}
