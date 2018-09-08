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
    uint64_t alignedSize = (size + 0x3FFFull) & ~0x3FFFull;

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

    r = vm_map_insert(map, NULL, NULL, addr, addr + alignedSize, VM_PROT_ALL, VM_PROT_ALL, 0);

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
    uint64_t alignedSize = (size + 0x3FFFull) & ~0x3FFFull;

    struct vmspace *vm = p->p_vmspace;
    struct vm_map *map = &vm->vm_map;

    vm_map_lock(map);

    r = vm_map_delete(map, (uint64_t)address, (uint64_t)address + alignedSize);

    vm_map_unlock(map);

    return r;
}

int proc_mprotect(struct proc *p, void *address, uint64_t size, int new_prot) {
    int r = 0;

    uint64_t alignedSize = (size + 0x3FFFull) & ~0x3FFFull;
    uint64_t addr = (uint64_t)address;
    uint64_t addrend = addr + alignedSize;

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

int proc_create_thread(struct proc *p, uint64_t address) {
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

    // donor thread
    struct thread *thr = TAILQ_FIRST(&p->p_threads);

    // find libkernel base
    r = proc_get_vm_map(p, &entries, &num_entries);
    if (r) {
        goto error;
    }

    // offsets are for 5.05 libraries

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
    // note: do not enter in the pid information as it expects it to be stored in userland
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

int proc_map_elf(struct proc *p, void *elf, void *exec) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    struct Elf64_Phdr *phdr = elf_pheader(ehdr);
    if (phdr) {
        // use segments
        for (int i = 0; i < ehdr->e_phnum; i++) {
            struct Elf64_Phdr *phdr = elf_segment(ehdr, i);

            if (phdr->p_filesz) {
                proc_write_mem(p, (void *)((uint8_t *)exec + phdr->p_paddr), phdr->p_filesz, (void *)((uint8_t *)elf + phdr->p_offset), NULL);
            }
        }
    } else {
        // use sections
        for (int i = 0; i < ehdr->e_shnum; i++) {
            struct Elf64_Shdr *shdr = elf_section(ehdr, i);

            if (!(shdr->sh_flags & SHF_ALLOC)) {
                continue;
            }

            if (shdr->sh_size) {
                proc_write_mem(p, (void *)((uint8_t *)exec + shdr->sh_addr), shdr->sh_size, (void *)((uint8_t *)elf + shdr->sh_offset), NULL);
            }
        }
    }

    return 0;
}

int proc_relocate_elf(struct proc *p, void *elf, void *exec) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        struct Elf64_Shdr *shdr = elf_section(ehdr, i);

        // check table
        if (shdr->sh_type == SHT_REL) {
            // process each entry in the table
            for (int j = 0; j < shdr->sh_size / shdr->sh_entsize; j++) {
                struct Elf64_Rela *reltab = &((struct Elf64_Rela *)((uint64_t)ehdr + shdr->sh_offset))[j];
                uint8_t **ref = (uint8_t **)((uint8_t *)exec + reltab->r_offset);
                uint8_t *value = NULL;

                switch (ELF64_R_TYPE(reltab->r_info)) {
                case R_X86_64_RELATIVE:
                    // *ref = (uint8_t *)exec + reltab->r_addend;
                    value = (uint8_t *)exec + reltab->r_addend;
                    proc_write_mem(p, ref, sizeof(value), (void *)&value, NULL);
                    break;
                case R_X86_64_64:
                case R_X86_64_JUMP_SLOT:
                case R_X86_64_GLOB_DAT:
                    // not supported
                    break;
                }
            }
        }
    }

    return 0;
}

int proc_load_elf(struct proc *p, void *elf, uint64_t *elfbase, uint64_t *entry) {
    void *elfaddr = NULL;
    uint64_t msize = 0;
    int r = 0;

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    r = elf_mapped_size(elf, &msize);
    if (r) {
        goto error;
    }

    // resize to pages
    msize += (PAGE_SIZE - (msize % PAGE_SIZE));

    // allocate
    r = proc_allocate(p, &elfaddr, msize);
    if (r) {
        goto error;
    }

    // map
    r = proc_map_elf(p, elf, elfaddr);
    if (r) {
        goto error;
    }

    // relocate
    r = proc_relocate_elf(p, elf, elfaddr);
    if (r) {
        goto error;
    }

    if (elfbase) {
        *elfbase = (uint64_t)elfaddr;
    }

    if (entry) {
        *entry = (uint64_t)elfaddr + ehdr->e_entry;
    }

error:
    return r;
}
