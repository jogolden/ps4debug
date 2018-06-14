// golden
// 6/12/2018
//

/* functions */
KFUNC(0x1C0, Xfast_syscall, void, (void));
KFUNC(0x1EA710, copyin, int, (const void *uaddr, void *kaddr, uint64_t len));
KFUNC(0x1EA630, copyout, int, (const void *kaddr, void *uaddr, uint64_t len));
KFUNC(0x436040, printf, int, (const char *fmt, ... ));
KFUNC(0x4360B0, vprintf, int, (const char *fmt, va_list arg));
KFUNC(0x10E250, malloc, void *, (uint64_t size, void *type, int flags));
KFUNC(0x10E460, free, void, (void *addr, void *type));
KFUNC(0x1EA530, memcpy, void *, (void *dest, const void *src, uint64_t num));
KFUNC(0x3205C0, memset, void *, (void *ptr, int value, uint64_t num));
KFUNC(0x50AC0, memcmp, int, (const void *ptr1, const void *ptr2, uint64_t num));
KFUNC(0xFCC80, kmem_alloc, void *, (struct vm_map *map, uint64_t size));
KFUNC(0x3B71A0, strlen, uint64_t, (const char *str));
KFUNC(0x3FB920, pause, void, (const char *wmesg, int timo));
KFUNC(0x138360, kthread_add, int, (void (*func)(void *), void *arg, struct proc *procp, struct thread **newtdpp, int flags, int pages, const char *fmt, ...));
KFUNC(0x138640, kthread_exit, void, (void));
KFUNC(0x31EE00, sched_prio, void, (struct thread *td, uint16_t prio));
KFUNC(0x31F150, sched_add, void, (struct thread *td, uint64_t cpuset));
KFUNC(0x3FBC40, kern_yield, void, (uint64_t p));
KFUNC(0x234BA0, fill_regs, int, (struct thread *td, struct reg *rg));
KFUNC(0x234CD0, set_regs, int, (struct thread *td, struct reg *rg));
KFUNC(0x1BE1F0, create_thread, int, (struct thread * td, uint64_t ctx, void (*start_func)(void *), void *arg, char *stack_base, uint64_t stack_size, char *tls_base, long *child_tid, long *parent_tid, uint64_t flags, uint64_t rtp));
KFUNC(0x137DF0, kproc_create, int, (void (*func)(void *), void *arg, struct proc **newpp, int flags, int pages, const char *fmt, ...));
KFUNC(0x138CC0, kthread_set_affinity, void, (const char *tdname, uint64_t prio, uint64_t cpuset, uint64_t unknown)); // custom name
KFUNC(0x138A60, kthread_suspend_check, void, (void));
KFUNC(0x138B70, kproc_kthread_add, int, (void (*func)(void *), void *arg, struct proc **procptr, struct thread **tdptr, int flags, int pages, char * procname, const char *fmt, ...));
KFUNC(0xF5BB0, sx_init_flags, void, (struct sx *sx, const char *description, int opts));
KFUNC(0xF5E10, sx_xlock, void, (struct sx *sx));
KFUNC(0xF5FD0, sx_xunlock, void, (struct sx *sx));
KFUNC(0x402780, mtx_init, void, (struct mtx *mutex, const char *name, const char *type, int opts));
KFUNC(0x402100, mtx_lock_spin_flags, void, (struct mtx *mutex, int flags));
KFUNC(0x4022C0, mtx_unlock_spin_flags, void, (struct mtx *mutex, int flags));
KFUNC(0x401CD0, mtx_lock_sleep, void, (struct mtx *mutex, int flags));
KFUNC(0x401FA0, mtx_unlock_sleep, void, (struct mtx *mutex, int flags));
KFUNC(0x10D390, kern_reboot, int, (int magic));
KFUNC(0x19F140, vm_map_lock_read, void, (struct vm_map *map));
KFUNC(0x19F760, vm_map_lookup_entry, int, (struct vm_map *map, uint64_t address, struct vm_map_entry **entries));
KFUNC(0x19F190, vm_map_unlock_read, void, (struct vm_map *map));
KFUNC(0x19EF90, vmspace_acquire_ref, struct vmspace *, (struct proc *p));
KFUNC(0x19EDC0, vmspace_free, void, (struct vmspace *vm));
KFUNC(0x1A19D0, vm_map_delete, int, (struct vm_map *map, uint64_t start, uint64_t end));
KFUNC(0x1A3A50, vm_map_protect, int, (struct vm_map * map, uint64_t start, uint64_t end, int new_prot, uint64_t set_max));
KFUNC(0x1A1F60, vm_map_findspace, int, (struct vm_map * map, uint64_t start, uint64_t length, uint64_t *addr));
KFUNC(0x1A0280, vm_map_insert, int, (struct vm_map * map, uint64_t object, uint64_t offset, uint64_t start, uint64_t end, int prot, int max, int cow));
KFUNC(0x19EFF0, vm_map_lock, void, (struct vm_map * map));
KFUNC(0x19F060, vm_map_unlock, void, (struct vm_map * map));
KFUNC(0x30D150, proc_rwmem, int, (struct proc *p, struct uio *uio));

/* data */
KDATA(0x19ECEB0, disable_console_output, uint8_t *);
KDATA(0x14B4110, M_TEMP, void);
KDATA(0x1AC60E0, kernel_map, void);
KDATA(0x10986a0, prison0, void *);
KDATA(0x22C1A70, rootvnode, void *);
KDATA(0x2382FF8, allproc, struct proc *);
