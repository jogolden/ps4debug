// golden
// 6/12/2018
//

#include "hooks.h"

struct sysent *sysents;

int sys_proc_read(struct thread *td, struct sys_proc_read_args *uap) {
    struct proc *p;
    uint64_t n;

    p = proc_find_by_pid(uap->pid);
    if(p) {
        return proc_write_mem(p, (void *)uap->address, uap->length, uap->data, &n);
    }
    
    return 1;
}

int sys_proc_write(struct thread *td, struct sys_proc_write_args *uap) {
    struct proc *p;
    uint64_t n;

    p = proc_find_by_pid(uap->pid);
    if(p) {
        return proc_read_mem(p, (void *)uap->address, uap->length, uap->data, &n);
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

int sys_kern_read(struct thread *td, struct sys_kern_read_args *uap) {
    memcpy(uap->data, (void *)uap->address, uap->length);
    return 0;
}

int sys_kern_write(struct thread *td, struct sys_kern_write_args *uap) {
    cpu_disable_wp();
    memcpy((void *)uap->address, uap->data, uap->length);
    cpu_enable_wp();
    return 0;
}

int install_hooks() {
    uint64_t kernbase = get_kbase();
    sysents = (void *)(kernbase + __sysent);

    cpu_disable_wp();

    struct sysent *_proc_read = &sysents[107];
    memset(_proc_read, 0, sizeof(struct sysent));
    _proc_read->sy_narg = 5;
    _proc_read->sy_call = sys_proc_read;
    _proc_read->sy_thrcnt = 1;

    struct sysent *_proc_write = &sysents[108];
    memset(_proc_write, 0, sizeof(struct sysent));
    _proc_write->sy_narg = 5;
    _proc_write->sy_call = sys_proc_write;
    _proc_write->sy_thrcnt = 1;

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

    struct sysent *_kern_read = &sysents[111];
    memset(_kern_read, 0, sizeof(struct sysent));
    _kern_read->sy_narg = 5;
    _kern_read->sy_call = sys_kern_read;
    _kern_read->sy_thrcnt = 1;
    
    struct sysent *_kern_write = &sysents[112];
    memset(_kern_write, 0, sizeof(struct sysent));
    _kern_write->sy_narg = 5;
    _kern_write->sy_call = sys_kern_write;
    _kern_write->sy_thrcnt = 1;

    cpu_enable_wp();

    return 0;
}
