// golden
// 6/12/2018
//

#ifndef _DEBUG_H
#define _DEBUG_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"
#include "ptrace.h"

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

/* Contents of each x87 floating point accumulator */
struct fpacc87 {
    uint8_t fp_bytes[10];
};

/* Contents of each SSE extended accumulator */
struct xmmacc {
    uint8_t xmm_bytes[16];
};

/* Contents of the upper 16 bytes of each AVX extended accumulator */
struct ymmacc {
    uint8_t ymm_bytes[16];
};

struct envxmm {
    uint16_t en_cw; /* control word (16bits) */
    uint16_t en_sw; /* status word (16bits) */
    uint8_t en_tw; /* tag word (8bits) */
    uint8_t en_zero;
    uint16_t en_opcode; /* opcode last executed (11 bits ) */
    uint64_t en_rip; /* floating point instruction pointer */
    uint64_t en_rdp; /* floating operand pointer */
    uint32_t en_mxcsr; /* SSE sontorol/status register */
    uint32_t en_mxcsr_mask; /* valid bits in mxcsr */
};

struct savefpu {
    struct envxmm sv_env;
    struct {
        struct fpacc87 fp_acc;
        uint8_t fp_pad[6]; /* padding */
    } sv_fp[8];
    struct xmmacc sv_xmm[16];
    uint8_t sv_pad[96];
} __attribute__((aligned(16)));

struct xstate_hdr {
    uint64_t xstate_bv;
    uint8_t xstate_rsrv0[16];
    uint8_t xstate_rsrv[40];
};

struct savefpu_xstate {
    struct xstate_hdr sx_hd;
    struct ymmacc sx_ymm[16];
};

struct savefpu_ymm {
    struct envxmm sv_env;
    struct {
        struct fpacc87 fp_acc;
        int8_t fp_pad[6];   /* padding */
    } sv_fp[8];
    struct xmmacc sv_xmm[16];
    uint8_t sv_pad[96];
    struct savefpu_xstate sv_xstate;
} __attribute__((aligned(64)));

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
    struct savefpu_ymm savefpu;
    struct __dbreg64 dbreg64;
} __attribute__((packed));
#define DEBUG_INTERRUPT_PACKET_SIZE         0x4A0

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

#define DEBUG_PORT 755

extern int g_debugging;
extern struct server_client *curdbgcli;
extern struct debug_context *curdbgctx;

int debug_attach_handle(int fd, struct cmd_packet *packet);
int debug_detach_handle(int fd, struct cmd_packet *packet);
int debug_breakpt_handle(int fd, struct cmd_packet *packet);
int debug_watchpt_handle(int fd, struct cmd_packet *packet);
int debug_threads_handle(int fd, struct cmd_packet *packet);
int debug_stopthr_handle(int fd, struct cmd_packet *packet);
int debug_resumethr_handle(int fd, struct cmd_packet *packet);
int debug_getregs_handle(int fd, struct cmd_packet *packet);
int debug_setregs_handle(int fd, struct cmd_packet *packet);
int debug_getfpregs_handle(int fd, struct cmd_packet *packet);
int debug_setfpregs_handle(int fd, struct cmd_packet *packet);
int debug_getdbregs_handle(int fd, struct cmd_packet *packet);
int debug_setdbregs_handle(int fd, struct cmd_packet *packet);
int debug_stopgo_handle(int fd, struct cmd_packet *packet);
int debug_thrinfo_handle(int fd, struct cmd_packet *packet);
int debug_singlestep_handle(int fd, struct cmd_packet *packet);

int connect_debugger(struct debug_context *dbgctx, struct sockaddr_in *client);
void debug_cleanup(struct debug_context *dbgctx);

int debug_handle(int fd, struct cmd_packet *packet);

#endif
