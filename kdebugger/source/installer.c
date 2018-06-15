// golden
// 6/12/2018
//

#include "installer.h"

// todo: clean up and refactor rpc_proc_load

extern uint8_t bdbg[];
extern int32_t cbdbg;

int load_payload(struct proc *p) {
    struct vmspace *vm = p->p_vmspace;
	struct vm_map *map = &vm->vm_map;

	vm_map_lock(map);
	vm_map_insert(map, NULL, NULL, 0x926200000, 0x926200000 + 0x300000, VM_PROT_ALL, VM_PROT_ALL, 0);
	vm_map_unlock(map);

    return proc_write_mem(p, (void *)0x926200000, cbdbg, bdbg, 0);
}

int rpc_proc_load(struct proc *p, uint64_t address) {
	void *rpcldraddr = NULL;
	void *stackaddr = NULL;
	struct proc_vm_map_entry *entries = NULL;
	uint64_t num_entries = 0;
	uint64_t n = 0;
	int r = 0;

	uint64_t ldrsize = sizeof(rpcldr);
	ldrsize += (PAGE_SIZE - (ldrsize % PAGE_SIZE));
	
	uint64_t stacksize = 0x80000;

	// allocate rpc ldr
	r = proc_allocate(p, &rpcldraddr, ldrsize);
	if (r) {
		goto error;
	}

	// allocate stack
	r = proc_allocate(p, &stackaddr, stacksize);
	if (r) {
		goto error;
	}

	// write loader
	r = proc_write_mem(p, rpcldraddr, sizeof(rpcldr), (void *)rpcldr, &n);
	if (r) {
		goto error;
	}

	// patch suword_lwpid
	// has a check to see if child_tid/parent_tid is in kernel memory, and it in so patch it
	uint64_t kernbase = get_kbase();
    cpu_disable_wp();
	uint16_t *suword_lwpid1 = (uint16_t *)(kernbase + 0x1EA9D2);
	uint16_t *suword_lwpid2 = (uint16_t *)(kernbase + 0x1EA9E1);
	*suword_lwpid1 = 0x9090;
	*suword_lwpid2 = 0x9090;
    cpu_enable_wp();

	// donor thread
	struct thread *thr = TAILQ_FIRST(&p->p_threads);

	// find libkernel base
	r = proc_get_vm_map(p, &entries, &num_entries);
	if (r) {
		goto error;
	}

	// offsets are for 5.05 libraries
	// todo: write patch finder

	// libkernel.sprx
	// 0x12AA0 scePthreadCreate
	// 0x84C20 thr_initial

	// libkernel_web.sprx
	// 0x98C0 scePthreadCreate
	// 0x84C20 thr_initial

	// libkernel_sys.sprx
	// 0x135D0 scePthreadCreate
	// 0x89030 thr_initial

	uint64_t _scePthreadAttrInit = 0, _scePthreadAttrSetstacksize = 0, _scePthreadCreate = 0, _thr_initial = 0;
	for (int i = 0; i < num_entries; i++) {
		if (entries[i].prot != (PROT_READ | PROT_EXEC)) {
			continue;
		}

		if (!memcmp(entries[i].name, "libkernel.sprx", 14)) {
			_scePthreadAttrInit = entries[i].start + 0x12660;
			_scePthreadAttrSetstacksize = entries[i].start + 0x12680;
			_scePthreadCreate = entries[i].start + 0x12AA0;
			_thr_initial = entries[i].start + 0x84C20;
			break;
		}
		if (!memcmp(entries[i].name, "libkernel_web.sprx", 18))
		{
			_scePthreadAttrInit = entries[i].start + 0x1E730;
			_scePthreadAttrSetstacksize = entries[i].start + 0xFA80;
			_scePthreadCreate = entries[i].start + 0x98C0;
			_thr_initial = entries[i].start + 0x84C20;
			break;
		}
		if (!memcmp(entries[i].name, "libkernel_sys.sprx", 18)) {
			_scePthreadAttrInit = entries[i].start + 0x13190;
			_scePthreadAttrSetstacksize = entries[i].start + 0x131B0;
			_scePthreadCreate = entries[i].start + 0x135D0;
			_thr_initial = entries[i].start + 0x89030;
			break;
		}
	}

	if (!_scePthreadAttrInit) {
		goto error;
	}

	// write variables
	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, stubentry), sizeof(address), (void *)&address, &n);
	if (r) {
		goto error;
	}

	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrInit), sizeof(_scePthreadAttrInit), (void *)&_scePthreadAttrInit, &n);
	if (r) {
		goto error;
	}

	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrSetstacksize), sizeof(_scePthreadAttrSetstacksize), (void *)&_scePthreadAttrSetstacksize, &n);
	if (r) {
		goto error;
	}

	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadCreate), sizeof(_scePthreadCreate), (void *)&_scePthreadCreate, &n);
	if (r) {
		goto error;
	}

	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, thr_initial), sizeof(_thr_initial), (void *)&_thr_initial, &n);
	if (r) {
		goto error;
	}

	// execute loader
	uint64_t ldrentryaddr = (uint64_t)rpcldraddr + *(uint64_t *)(rpcldr + 4);
	r = create_thread(thr, NULL, (void *)ldrentryaddr, NULL, stackaddr, stacksize, NULL, NULL, NULL, 0, NULL);
	if (r) {
		goto error;
	}

	// wait until loader is done
	uint8_t ldrdone = 0;
	while (!ldrdone) {
		r = proc_read_mem(p, (void *)(rpcldraddr + offsetof(struct rpcldr_header, ldrdone)), sizeof(ldrdone), &ldrdone, &n);
		if (r) {
			goto error;
		}
	}

error:
	if (entries) {
        free(entries, M_TEMP);
	}

	if (rpcldraddr) {
		proc_deallocate(p, rpcldraddr, ldrsize);
	}

	if (stackaddr) {
		proc_deallocate(p, stackaddr, stacksize);
	}

	return r;
}

int exec_payload(struct proc *p) {
    return rpc_proc_load(p, 0x926200000);
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
