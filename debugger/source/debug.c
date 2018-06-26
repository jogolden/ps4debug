// golden
// 6/12/2018
//

#include "debug.h"

int dbg_pid;
int dbg_fd;
struct debug_breakpoint breakpoints[MAX_BREAKPOINTS];
struct debug_watchpoint watchpoints[MAX_WATCHPOINTS];

int add_breakpt(struct debug_breakpoint *breakpt) {
    for(int i = 0; i < MAX_BREAKPOINTS; i++) {
        if(!breakpoints[i].valid) {
            memcpy(&breakpoints[i], breakpt, sizeof(struct debug_breakpoint));
            breakpoints[i].valid = 0;
            return 0;
        }
    }

    return 1;
}

int remove_breakpt(struct debug_breakpoint *breakpt) {
    for(int i = 0; i < MAX_BREAKPOINTS; i++) {
        if(breakpoints[i].address == breakpt->address) {
            breakpoints[i].valid = 0;
            return 0;
        }
    }

    return 1;
}

int debug_attach_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_attach_packet *ap;

    ap = (struct cmd_debug_attach_packet *)packet->data;

    if(ap) {
        ptrace(PT_ATTACH, ap->pid, NULL, NULL);
        ptrace(PT_CONTINUE, ap->pid, (void *)1, NULL);

        dbg_pid = ap->pid;
        dbg_fd = fd;

        net_send_status(fd, CMD_SUCCESS);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);

    return 1;
}

int debug_detach_handle(int fd, struct cmd_packet *packet) {
    if(dbg_pid != -1) {
        ptrace(PT_DETACH, dbg_pid, NULL, NULL);
        dbg_pid = -1;
        dbg_fd = -1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_breakpt_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_breakpt_packet *bp;
    struct debug_breakpoint dbgbp;
    uint8_t int3;
    uint8_t original;

    bp = (struct cmd_debug_breakpt_packet *)packet->data;
    
    if (dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!bp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    dbgbp.valid = 1;
    dbgbp.address = bp->address;

    if(bp->remove) {
        if(remove_breakpt(&dbgbp)) {
            net_send_status(fd, CMD_ERROR);
            return 0;
        }
    } else {
        // read original byte
        // write 0xCC to process
        // call wait4 on process
        // wait until trap -> debug_monitor_thread
        
        sys_proc_rw(dbg_pid, bp->address, &original, 1, 0);
        dbgbp.original = original;

        int3 = 0xCC;
        sys_proc_rw(dbg_pid, bp->address, &int3, 1, 1);

        if(add_breakpt(&dbgbp)) {
            net_send_status(fd, CMD_ERROR);
            return 0;
        }
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_watchpt_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_watchpt_packet *wp;

    wp = (struct cmd_debug_watchpt_packet *)packet->data;
    
    if (dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    // use debug registers
    if(!wp) {
        net_send_status(fd, CMD_SUCCESS);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_threads_handle(int fd, struct cmd_packet *packet) {
    void *lwpids;
    int nlwps;
    int r;
    int size;

    if (dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    nlwps = ptrace(PT_GETNUMLWPS, dbg_pid, NULL, 0);

    if(nlwps == -1) {
        net_send_status(fd, CMD_ERROR);
        return 0;
    }

    // i assume the lwpid_t is 32 bits wide
    size = nlwps * sizeof(uint32_t);
    lwpids = malloc(size);
    
    r = ptrace(PT_GETLWPLIST, dbg_pid, lwpids, nlwps);
    
    if(r == -1) {
        net_send_status(fd, CMD_ERROR);
        return 0;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &nlwps, sizeof(nlwps));
    net_send_data(fd, lwpids, size);

    free(lwpids);

    return 0;
}

int debug_stopthr_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_stopthr_packet *sp;
    int r;

    sp = (struct cmd_debug_stopthr_packet *)packet->data;

    if(dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!sp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    r = ptrace(PT_SUSPEND, sp->lwpid, NULL, 0);
    if(r == -1) {
        net_send_status(fd, CMD_ERROR);
        return 0;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_resumethr_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_resumethr_packet *rp;
    int r;

    rp = (struct cmd_debug_resumethr_packet *)packet->data;

    if(dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    r = ptrace(PT_RESUME, rp->lwpid, NULL, 0);
    if(r == -1) {
        net_send_status(fd, CMD_ERROR);
        return 0;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_getregs_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_getregs_packet *rp;
    struct __reg64 reg64;
    int r;

    rp = (struct cmd_debug_getregs_packet *)packet->data;

    if (dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }
    
    r = ptrace(PT_GETREGS, rp->lwpid, &reg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &reg64, sizeof(struct __reg64));

    return 0;
}

int debug_getfregs_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_getregs_packet *rp;
    struct __fpreg64 fpreg64;
    int r;

    rp = (struct cmd_debug_getregs_packet *)packet->data;

    if (dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }
    
    if(!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    r = ptrace(PT_GETFPREGS, rp->lwpid, &fpreg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &fpreg64, sizeof(struct __fpreg64));

    return 0;
}

int debug_getdbregs_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_getregs_packet *rp;
    struct __dbreg64 dbreg64;
    int r;

    rp = (struct cmd_debug_getregs_packet *)packet->data;

    if (dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    r = ptrace(PT_GETDBREGS, rp->lwpid, &dbreg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }
    
    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &dbreg64, sizeof(struct __dbreg64));

    return 0;
}

int debug_setregs_handle(int fd, struct cmd_packet *packet) {
    struct __reg64 *reg64;
    int r;

    if (dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    reg64 = (struct __reg64 *)packet->data;
    if (!reg64) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    r = ptrace(PT_SETREGS, dbg_pid, reg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_setfregs_handle(int fd, struct cmd_packet *packet) {
    struct __fpreg64 *fpreg64;
    int r;

    if (dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    fpreg64 = (struct __fpreg64 *)packet->data;
    if (!fpreg64) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    r = ptrace(PT_SETFPREGS, dbg_pid, fpreg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_setdbregs_handle(int fd, struct cmd_packet *packet) {
    struct __dbreg64 *dbreg64;
    int r;

    if (dbg_pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    dbreg64 = (struct __dbreg64 *)packet->data;
    if (!dbreg64) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }
    
    r = ptrace(PT_SETDBREGS, dbg_pid, dbreg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

void *debug_monitor_thread(void *arg) {
    int status;

    while(1) {
        scePthreadYield();

        if(dbg_pid != -1) {
            if(wait4(dbg_pid, &status, WNOHANG, NULL)) {
                uprintf("debug_monitor_thread caught status %X", status);

                // for breakpoint
                // write og byte
                // single step
                // write 0xCC
                // signal debugger somehow
                // send info to client

                // for watchpoint
                // send info to client
            }
        }

        sceKernelUsleep(40000);
    }
}

void start_debug() {
    dbg_pid = dbg_fd = -1;
    
    memset(breakpoints, NULL, sizeof(breakpoints));
    memset(watchpoints, NULL, sizeof(watchpoints));

    ScePthread thread;
    scePthreadCreate(&thread, NULL, debug_monitor_thread, NULL, "dbgmonitor");
}

int debug_handle(int fd, struct cmd_packet *packet) {
    switch(packet->cmd) {
        case CMD_DEBUG_ATTACH:
            return debug_attach_handle(fd, packet);
        case CMD_DEBUG_DETACH:
            return debug_detach_handle(fd, packet);
        case CMD_DEBUG_BREAKPT:
            return debug_breakpt_handle(fd, packet);
        case CMD_DEBUG_WATCHPT:
            return debug_watchpt_handle(fd, packet);
        case CMD_DEBUG_THREADS:
            return debug_threads_handle(fd, packet);
        case CMD_DEBUG_STOPTHR:
            return debug_stopthr_handle(fd, packet);
        case CMD_DEBUG_RESUMETHR:
            return debug_resumethr_handle(fd, packet);
        case CMD_DEBUG_GETREGS:
            return debug_getregs_handle(fd, packet);
        case CMD_DEBUG_GETFREGS:
            return debug_getfregs_handle(fd, packet);
        case CMD_DEBUG_GETDBGREGS:
            return debug_getdbregs_handle(fd, packet);
        case CMD_DEBUG_SETREGS:
            return debug_setregs_handle(fd, packet);
        case CMD_DEBUG_SETFREGS:
            return debug_setfregs_handle(fd, packet);
        case CMD_DEBUG_SETDBGREGS:
            return debug_setdbregs_handle(fd, packet);

            // todo: registers
            /*
                case SINGLE_STEP:
                case STEP_OVER:
                case PAUSE
                case CONTINUE
                case SUSPEND
                case RESUME
             */
        default:
            return 1;
    }
}