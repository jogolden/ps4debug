// golden
// 6/12/2018
//

#include "hooks.h"

struct sysent *sysents;

int sys_proc_list(struct thread *td, struct sys_proc_list_args *uap) {
    struct proc *p;

    
    return 1;
}

int sys_proc_rw(struct thread *td, struct sys_proc_rw_args *uap) {
    struct proc *p;

    p = proc_find_by_pid(uap->pid);
    if(p) {
        return proc_rw_mem(p, (void *)uap->address, uap->length, uap->data, 0, uap->write);
    }
    
    return 1;
}

int sys_proc_cmd(struct thread *td, struct sys_proc_cmd_args *uap) {
    struct proc *p;

    p = proc_find_by_pid(uap->pid);
    if(!p) {
        return 1;
    }

    // todo
    __asm("int 3");

    switch(uap->cmd) {
        case SYS_PROC_CMD_ALLOC:
        break;
        case SYS_PROC_CMD_FREE:
        break;
        case SYS_PROC_CMD_PROTECT:
        break;
        case SYS_PROC_VM_MAP:
        break;
        case SYS_PROC_CMD_CALL:
        break;
    }

    return 0;
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

    cpu_enable_wp();

    return 0;
}
