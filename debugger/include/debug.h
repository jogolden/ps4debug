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
#define MAX_WATCHPOINTS 4

struct debug_breakpoint {
    uint32_t enabled;
    uint64_t address;
    uint8_t original;
};

struct debug_watchpoint {
    uint64_t address;
    uint32_t width; // 1/2/4/8
};

struct __reg64 {
    int64_t	r_r15;
    int64_t	r_r14;
    int64_t	r_r13;
    int64_t	r_r12;
    int64_t	r_r11;
    int64_t	r_r10;
    int64_t	r_r9;
    int64_t	r_r8;
    int64_t	r_rdi;
    int64_t	r_rsi;
    int64_t	r_rbp;
    int64_t	r_rbx;
    int64_t	r_rdx;
    int64_t	r_rcx;
    int64_t	r_rax;
    uint32_t r_trapno;
    uint16_t r_fs;
    uint16_t r_gs;
    uint32_t r_err;
    uint16_t r_es;
    uint16_t r_ds;
    int64_t	r_rip;
    int64_t	r_cs;
    int64_t	r_rflags;
    int64_t	r_rsp;
    int64_t	r_ss;
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

extern int dbg_pid;
extern struct debug_breakpoint breakpoints[MAX_BREAKPOINTS];
extern struct debug_watchpoint watchpoints[MAX_WATCHPOINTS];

int debug_attach_handle(int fd, struct cmd_packet *packet);
int debug_detach_handle(int fd, struct cmd_packet *packet);
int debug_breakpt_handle(int fd, struct cmd_packet *packet);
int debug_watchpt_handle(int fd, struct cmd_packet *packet);
int debug_threads_handle(int fd, struct cmd_packet *packet);
int debug_stopthr_handle(int fd, struct cmd_packet *packet);
int debug_resumethr_handle(int fd, struct cmd_packet *packet);
int debug_getregs_handle(int fd, struct cmd_packet *packet);
int debug_getfregs_handle(int fd, struct cmd_packet *packet);
int debug_getdbregs_handle(int fd, struct cmd_packet *packet);
int debug_setregs_handle(int fd, struct cmd_packet *packet);
int debug_setfregs_handle(int fd, struct cmd_packet *packet);
int debug_setdbregs_handle(int fd, struct cmd_packet *packet);

// todo: registers

void *debug_monitor_thread(void *arg);
void start_debug();

int debug_handle(int fd, struct cmd_packet *packet);

#endif
