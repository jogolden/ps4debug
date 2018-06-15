// golden
// 6/12/2018
//

#include "proc.h"

struct proc *proc_find_by_name(const char *name) {
	struct proc *p;

	if (!name) {
		return NULL;
	}

	p = *allproc;
	do {
		if (!memcmp(p->p_comm, name, strlen(name))) {
			return p;
		}
	} while ((p = p->p_forw));

	return NULL;
}

struct proc *proc_find_by_pid(int pid) {
	struct proc *p;

	p = *allproc;
	do {
		if (p->pid == pid) {
			return p;
		}
	} while ((p = p->p_forw));

	return NULL;
}

int proc_get_vm_map(struct proc *p, struct proc_vm_map_entry **entries, uint64_t *num_entries) {
	struct proc_vm_map_entry *info = NULL;
	struct vm_map_entry *entry = NULL;
	int r = 0;

	struct vmspace *vm = p->p_vmspace;
	struct vm_map *map = &vm->vm_map;

	vm_map_lock_read(map);

	int num = map->nentries;
	if (!num) {
		goto error;
	}

	r = vm_map_lookup_entry(map, NULL, &entry);
	if(r) {
		goto error;
	}

	info = (struct proc_vm_map_entry *)malloc(num * sizeof(struct proc_vm_map_entry), M_TEMP, 2);
	if (!info) {
		r = 1;
		goto error;
	}

	for (int i = 0; i < num; i++) {
		info[i].start = entry->start;
		info[i].end = entry->end;
		info[i].offset = entry->offset;
		info[i].prot = entry->prot & (entry->prot >> 8);
		memcpy(info[i].name, entry->name, sizeof(info[i].name));

		if (!(entry = entry->next)) {
			break;
		}
	}

error:
	vm_map_unlock_read(map);

	if (entries) {
		*entries = info;
	}

	if (num_entries) {
		*num_entries = num;
	}

	return 0;
}

int proc_rw_mem(struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n, int write) {
	struct thread *td = curthread();
	struct iovec iov;
	struct uio uio;
	int r = 0;

	if (!p) {
		return 1;
	}

	if (size == 0) {
		if (n) {
			*n = 0;
		}

		return 0;
	}

	memset(&iov, NULL, sizeof(iov));
	iov.iov_base = (uint64_t)data;
	iov.iov_len = size;

	memset(&uio, NULL, sizeof(uio));
	uio.uio_iov = (uint64_t)&iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = (uint64_t)ptr;
	uio.uio_resid = (uint64_t)size;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = write ? UIO_WRITE : UIO_READ;
	uio.uio_td = td;

	r = proc_rwmem(p, &uio);

	if (n) {
		*n = (uint64_t)((uint64_t)size - uio.uio_resid);
	}

	return r;
}

inline int proc_read_mem(struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n) {
	return proc_rw_mem(p, ptr, size, data, n, 0);
}

inline int proc_write_mem(struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n) {
	return proc_rw_mem(p, ptr, size, data, n, 1);
}

int proc_allocate(struct proc *p, void **address, uint64_t size) {
	uint64_t addr = NULL;
	int r = 0;

	if (!address) {
		r = 1;
		goto error;
	}

	struct vmspace *vm = p->p_vmspace;
	struct vm_map *map = &vm->vm_map;

	vm_map_lock(map);

	r = vm_map_findspace(map, NULL, size, &addr);
	if (r) {
		vm_map_unlock(map);
		goto error;
	}

	r = vm_map_insert(map, NULL, NULL, addr, addr + size, VM_PROT_ALL, VM_PROT_ALL, 0);

	vm_map_unlock(map);

	if (r) {
		goto error;
	}

	if (address) {
		*address = (void *)addr;
	}

error:
	return r;
}

int proc_deallocate(struct proc *p, void *address, uint64_t size) {
	int r = 0;

	struct vmspace *vm = p->p_vmspace;
	struct vm_map *map = &vm->vm_map;

	vm_map_lock(map);

	r = vm_map_delete(map, (uint64_t)address, (uint64_t)address + size);

	vm_map_unlock(map);

	return r;
}

int proc_mprotect(struct proc *p, void *address, void *end, int new_prot) {
	int r = 0;

	uint64_t addr = (uint64_t)address;
	uint64_t addrend = (uint64_t)end;

	struct vmspace *vm = p->p_vmspace;
	struct vm_map *map = &vm->vm_map;

	// update the max prot then set new prot
	r = vm_map_protect(map, addr, addrend, new_prot, 1);
	if (r) {
		return r;
	}

	r = vm_map_protect(map, addr, addrend, new_prot, 0);
	
	return r;
}
