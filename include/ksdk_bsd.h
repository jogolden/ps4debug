/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#ifndef KSDK_BSD_H
#define KSDK_BSD_H

/* constants */
#define DT_DIR      0x0004
#define DT_REG      0x0008

#define M_NOWAIT    0x0001
#define M_WAITOK    0x0002
#define M_ZERO      0x0100

#define	VM_PROT_NONE		0x00
#define VM_PROT_READ		0x01
#define VM_PROT_WRITE		0x02
#define VM_PROT_EXECUTE		0x04
#define VM_PROT_DEFAULT		(VM_PROT_READ | VM_PROT_WRITE)
#define VM_PROT_ALL			(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
#define VM_PROT_NO_CHANGE	0x08
#define VM_PROT_COPY		0x10
#define VM_PROT_WANTS_COPY	0x10

#define PROT_READ			VM_PROT_READ
#define PROT_WRITE			VM_PROT_WRITE
#define PROT_EXEC			VM_PROT_EXECUTE
#define PROT_NONE			VM_PROT_NONE

#define	TRACEBUF	struct qm_trace trace;

#define	TAILQ_FIRST(head) ((head)->tqh_first)
#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	TAILQ_HEAD(name, type)									\
struct name {													\
	struct type *tqh_first;										\
	struct type **tqh_last;										\
	TRACEBUF													\
}

#define	TAILQ_ENTRY(type)											\
struct {															\
	struct type *tqe_next;											\
	struct type **tqe_prev;											\
	TRACEBUF														\
}

#define	LIST_ENTRY(type)											\
struct {															\
	struct type *le_next;											\
	struct type **le_prev;											\
}

#define	TAILQ_FOREACH(var, head, field)				\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);										\
(var) = TAILQ_NEXT((var), field))

struct qm_trace {
	char * lastfile;
	int lastline;
	char * prevfile;
	int prevline;
};

struct trapframe {
	uint64_t tf_rdi;	// 0x00
	uint64_t tf_rsi;	// 0x08
	uint64_t tf_rdx;	// 0x10
	uint64_t tf_rcx;	// 0x18
	uint64_t tf_r8;		// 0x20
	uint64_t tf_r9;		// 0x28
	uint64_t tf_rax;	// 0x30
	uint64_t tf_rbx;	// 0x38
	uint64_t tf_rbp;	// 0x40
	uint64_t tf_r10;	// 0x48
	uint64_t tf_r11;	// 0x50
	uint64_t tf_r12;	// 0x58
	uint64_t tf_r13;	// 0x60
	uint64_t tf_r14;	// 0x68
	uint64_t tf_r15;	// 0x70
	uint32_t tf_trapno;	// 0x78
	uint16_t tf_fs;		// 0x7C
	uint16_t tf_gs;		// 0x7E
	uint64_t tf_addr;	// 0x80
	uint32_t tf_flags;	// 0x88
	uint16_t tf_es;		// 0x8C
	uint16_t tf_ds;		// 0x8E
	uint64_t tf_err;	// 0x90
	uint64_t tf_rip;	// 0x98
	uint64_t tf_cs;		// 0xA0
	uint64_t tf_rflags;	// 0xA8
	uint64_t tf_rsp;	// 0xB0
	uint64_t tf_ss;		// 0xB8
};

struct reg {
	uint64_t r_r15;
	uint64_t r_r14;
	uint64_t r_r13;
	uint64_t r_r12;
	uint64_t r_r11;
	uint64_t r_r10;
	uint64_t r_r9;
	uint64_t r_r8;
	uint64_t r_rdi;
	uint64_t r_rsi;
	uint64_t r_rbp;
	uint64_t r_rbx;
	uint64_t r_rdx;
	uint64_t r_rcx;
	uint64_t r_rax;
	uint32_t r_trapno;
	uint16_t r_fs; // 0x7C
	uint16_t r_gs; // 0x7E
	uint32_t r_err;
	uint16_t r_es;
	uint16_t r_ds;
	uint64_t r_rip;
	uint64_t r_cs;
	uint64_t r_rflags;
	uint64_t r_rsp;
	uint64_t r_ss;
};

struct timeval {
	uint64_t tv_sec;		/* seconds */
	uint64_t tv_usec;	/* and microseconds */
};

enum uio_rw {
	UIO_READ,
	UIO_WRITE
};

enum uio_seg {
	UIO_USERSPACE,		/* from user data space */
	UIO_SYSSPACE,		/* from system space */
	UIO_USERISPACE		/* from user I space */
};

struct iovec {
	uint64_t iov_base;
	uint64_t iov_len;
};

TYPE_BEGIN(struct uio, 0x30);
TYPE_FIELD(uint64_t uio_iov, 0);
TYPE_FIELD(uint32_t uio_iovcnt, 8);
TYPE_FIELD(uint64_t uio_offset, 0x10);
TYPE_FIELD(uint64_t uio_resid, 0x18);
TYPE_FIELD(uint32_t uio_segflg, 0x20);
TYPE_FIELD(uint32_t uio_rw, 0x24);
TYPE_FIELD(struct thread *uio_td, 0x28);
TYPE_END();

struct lock_object {
	const char* lo_name;
	uint32_t lo_flags;
	uint32_t lo_data;
	void* lo_witness;
};

struct mtx {
	struct lock_object lock_object;
	volatile void* mtx_lock;
};

struct sx {
	struct lock_object lock_object;
	volatile uintptr_t sx_lock;
};

TYPE_BEGIN(struct vm_map_entry, 0xC0);
TYPE_FIELD(struct vm_map_entry *prev, 0);
TYPE_FIELD(struct vm_map_entry *next, 8);
TYPE_FIELD(struct vm_map_entry *left, 0x10);
TYPE_FIELD(struct vm_map_entry *right, 0x18);
TYPE_FIELD(uint64_t start, 0x20);
TYPE_FIELD(uint64_t end, 0x28);
TYPE_FIELD(uint64_t offset, 0x50);
TYPE_FIELD(uint16_t prot, 0x5C);
TYPE_FIELD(char name[32], 0x8D);
TYPE_END();

TYPE_BEGIN(struct vm_map, 0x178);
TYPE_FIELD(struct vm_map_entry header, 0);
TYPE_FIELD(struct sx lock, 0xB8);
TYPE_FIELD(struct mtx system_mtx, 0xD8);
TYPE_FIELD(int nentries, 0x100);
TYPE_END();

TYPE_BEGIN(struct vmspace, 0x250);
TYPE_FIELD(struct vm_map vm_map, 0);
// maybe I will add more later just for documentation purposes
TYPE_END();

struct auditinfo_addr {
	uint8_t useless[184];
};

struct ucred {
	uint32_t cr_ref;					// reference count		0x0000
	uint32_t cr_uid;					// effective user id	0x0004
	uint32_t cr_ruid;					// real user id			0x0008
	uint32_t useless2;					// 						0x000C
	uint32_t useless3;					//
	uint32_t cr_rgid;					// real group id
	uint32_t useless4;					//
	void *useless5;						//
	void *useless6;						//
	void *cr_prison;					// jail(2)				0x0030
	void *useless7;						//
	uint32_t useless8;					//
	void *useless9[2];					//
	void *useless10;					//
	struct auditinfo_addr cr_audit;		//
	uint32_t *cr_groups;				// groups
	uint32_t useless12;					//
};

struct filedesc {
	void *useless1[3];
	void *fd_rdir;
	void *fd_jdir;
};

TYPE_BEGIN(struct proc, 0x800); // XXX: random, don't use directly without fixing it
TYPE_FIELD(struct proc *p_forw, 0);
TYPE_FIELD(TAILQ_HEAD(, thread) p_threads, 0x10);
TYPE_FIELD(struct ucred *p_ucred, 0x40);
TYPE_FIELD(struct filedesc *p_fd, 0x48);
TYPE_FIELD(int pid, 0xB0);
TYPE_FIELD(struct vmspace *p_vmspace, 0x168);
TYPE_FIELD(char p_comm[32], 0x44C);
TYPE_END();

TYPE_BEGIN(struct thread, 0x3D8); // XXX: random, don't use directly without fixing it
TYPE_FIELD(struct mtx *volatile td_lock, 0);
TYPE_FIELD(struct proc *td_proc, 8);
TYPE_FIELD(TAILQ_ENTRY(thread) td_plist, 0x10);
TYPE_FIELD(int tid, 0x88);
TYPE_FIELD(int td_pinned, 0x12C);
TYPE_FIELD(struct ucred *td_ucred, 0x130);
TYPE_FIELD(char td_name[32], 0x284);
TYPE_FIELD(uint64_t td_retval[2], 0x398);
TYPE_FIELD(uint16_t td_priority, 0x380);
TYPE_END();

#endif /* KSDK_BSD_H */
