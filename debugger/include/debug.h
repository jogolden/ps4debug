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
// todo: registers

void *debug_monitor_thread(void *arg);
void start_debug();

int debug_handle(int fd, struct cmd_packet *packet);

#endif
