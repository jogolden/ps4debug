// golden
// 6/12/2018
//

#ifndef _DEBUG_H
#define _DEBUG_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"
#include "ptrace.h"

#define MAX_BREAKPOINTS 10

struct debug_breakpoint {
    uint32_t enabled;
    uint64_t address;
    uint8_t original;
};

struct __reg64 {
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
    uint16_t r_fs;
    uint16_t r_gs;
    uint32_t r_err;
    uint16_t r_es;
    uint16_t r_ds;
    uint64_t r_rip;
    uint64_t r_cs;
    uint64_t r_rflags;
    uint64_t r_rsp;
    uint64_t r_ss;
};

struct __fpreg64 {
    uint64_t fpr_env[4];
    uint8_t	fpr_acc[8][16];
    uint8_t	fpr_xacc[16][16];
    uint64_t fpr_spare[12];
};

struct __dbreg64 {
    uint64_t dr[16];	/* debug registers */
    /* Index 0-3: debug address registers */
    /* Index 4-5: reserved */
    /* Index 6: debug status */
    /* Index 7: debug control */
    /* Index 8-15: reserved */
};

struct debug_interrupt_packet {
    uint32_t lwpid;
    uint32_t status;
    char tdname[40];
    struct __reg64 reg64;
    struct __fpreg64 fpreg64;
    struct __dbreg64 dbreg64;
} __attribute__((packed));
#define DEBUG_INTERRUPT_PACKET_SIZE         0x360

#define	DBREG_DR7_DISABLE       0x00
#define	DBREG_DR7_LOCAL_ENABLE  0x01
#define	DBREG_DR7_GLOBAL_ENABLE 0x02

#define	DBREG_DR7_LEN_1     0x00	/* 1 byte length */
#define	DBREG_DR7_LEN_2     0x01
#define	DBREG_DR7_LEN_4     0x03
#define	DBREG_DR7_LEN_8     0x02

#define	DBREG_DR7_EXEC      0x00	/* break on execute       */
#define	DBREG_DR7_WRONLY    0x01	/* break on write         */
#define	DBREG_DR7_RDWR      0x03	/* break on read or write */

#define	DBREG_DR7_MASK(i) ((uint64_t)(0xf) << ((i) * 4 + 16) | 0x3 << (i) * 2)
#define	DBREG_DR7_SET(i, len, access, enable) ((uint64_t)((len) << 2 | (access)) << ((i) * 4 + 16) | (enable) << (i) * 2)
#define	DBREG_DR7_GD        0x2000
#define	DBREG_DR7_ENABLED(d, i)	(((d) & 0x3 << (i) * 2) != 0)
#define	DBREG_DR7_ACCESS(d, i)	((d) >> ((i) * 4 + 16) & 0x3)
#define	DBREG_DR7_LEN(d, i)	((d) >> ((i) * 4 + 18) & 0x3)

#define	DBREG_DRX(d,x) ((d)->dr[(x)]) /* reference dr0 - dr7 by register number */

#define DBG_PORT 755

struct debug_context {
    int pid;
    struct sockaddr_in client;
    int clientfd;
    struct debug_breakpoint breakpoints[MAX_BREAKPOINTS];
};

extern struct debug_context dbgctx;

int debug_attach_handle(int fd, struct cmd_packet *packet);
int debug_detach_handle(int fd, struct cmd_packet *packet);
int debug_breakpt_handle(int fd, struct cmd_packet *packet);
int debug_watchpt_handle(int fd, struct cmd_packet *packet);
int debug_threads_handle(int fd, struct cmd_packet *packet);
int debug_stopthr_handle(int fd, struct cmd_packet *packet);
int debug_resumethr_handle(int fd, struct cmd_packet *packet);
int debug_getregs_handle(int fd, struct cmd_packet *packet);
int debug_setregs_handle(int fd, struct cmd_packet *packet);
int debug_getfregs_handle(int fd, struct cmd_packet *packet);
int debug_setfregs_handle(int fd, struct cmd_packet *packet);
int debug_getdbregs_handle(int fd, struct cmd_packet *packet);
int debug_setdbregs_handle(int fd, struct cmd_packet *packet);
int debug_start_run_handle(int fd, struct cmd_packet *packet);

int connect_debugger();
void debug_cleanup();

int debug_handle(int fd, struct cmd_packet *packet);

#endif
