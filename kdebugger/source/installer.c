// golden
// 6/12/2018
//

#include "installer.h"

// todo: clean up and refactor rpc_proc_load

extern uint8_t bdbg[];
extern int32_t cbdbg;

int load_payload(struct proc *p) {
	int r;

    struct vmspace *vm = p->p_vmspace;
	struct vm_map *map = &vm->vm_map;

	vm_map_lock(map);
	r = vm_map_insert(map, NULL, NULL, 0x926200000, 0x926200000 + 0x300000, VM_PROT_ALL, VM_PROT_ALL, 0);
	vm_map_unlock(map);

	if(r) {
		return r;
	}

    return proc_write_mem(p, (void *)0x926200000, cbdbg, bdbg, 0);
}

int exec_payload(struct proc *p) {
    return proc_create_thread(p, 0x926200000);
}

int install_debugger() {
    struct proc *p;

    p = proc_find_by_name("SceShellCore");
    if(!p) {
        return 1;
    }

    if(load_payload(p)) {
        return 1;
    }

    if(exec_payload(p)) {
        return 1;
    }

    return 0;
}
