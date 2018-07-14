// golden
// 6/12/2018
//

#include "debug.h"

struct debug_context dbgctx;

int debug_attach_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_attach_packet *ap;

    ap = (struct cmd_debug_attach_packet *)packet->data;

    if(ap) {
        ptrace(PT_ATTACH, ap->pid, NULL, NULL);
        ptrace(PT_CONTINUE, ap->pid, (void *)1, NULL);

        dbgctx.pid = ap->pid;
        memset(dbgctx.breakpoints, NULL, sizeof(dbgctx.breakpoints));

        net_send_status(fd, CMD_SUCCESS);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);

    return 1;
}

int debug_detach_handle(int fd, struct cmd_packet *packet) {
    if(dbgctx.pid != -1) {
        ptrace(PT_DETACH, dbgctx.pid, NULL, NULL);
        dbgctx.pid = -1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_breakpt_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_breakpt_packet *bp;
    uint8_t int3;
    uint8_t original;

    bp = (struct cmd_debug_breakpt_packet *)packet->data;
    
    if (dbgctx.pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!bp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if(bp->index < 0 && bp->index >= MAX_BREAKPOINTS) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct debug_breakpoint *breakpoint = &dbgctx.breakpoints[bp->index];

    if(bp->enabled) {
        breakpoint->enabled = 1;
        breakpoint->address = bp->address;

        sys_proc_rw(dbgctx.pid, breakpoint->address, &original, 1, 0);
        breakpoint->original = original;

        int3 = 0xCC;
        sys_proc_rw(dbgctx.pid, breakpoint->address, &int3, 1, 1);
    } else {
        breakpoint->enabled = 0;
        breakpoint->address = NULL;
        sys_proc_rw(dbgctx.pid, breakpoint->address, &breakpoint->original, 1, 0);
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_watchpt_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_watchpt_packet *wp;

    wp = (struct cmd_debug_watchpt_packet *)packet->data;
    
    if (dbgctx.pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!wp) {
        net_send_status(fd, CMD_SUCCESS);
        return 1;
    }

    // todo: change the debug registers accordingly

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_threads_handle(int fd, struct cmd_packet *packet) {
    void *lwpids;
    int nlwps;
    int r;
    int size;

    if (dbgctx.pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    nlwps = ptrace(PT_GETNUMLWPS, dbgctx.pid, NULL, 0);

    if(nlwps == -1) {
        net_send_status(fd, CMD_ERROR);
        return 0;
    }

    // i assume the lwpid_t is 32 bits wide
    size = nlwps * sizeof(uint32_t);
    lwpids = malloc(size);
    
    r = ptrace(PT_GETLWPLIST, dbgctx.pid, lwpids, nlwps);
    
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

    if(dbgctx.pid == -1) {
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

    if(dbgctx.pid == -1) {
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

    if (dbgctx.pid == -1) {
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

    if (dbgctx.pid == -1) {
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

    if (dbgctx.pid == -1) {
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

    if (dbgctx.pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    reg64 = (struct __reg64 *)packet->data;
    if (!reg64) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    r = ptrace(PT_SETREGS, dbgctx.pid, reg64, NULL);
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

    if (dbgctx.pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    fpreg64 = (struct __fpreg64 *)packet->data;
    if (!fpreg64) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    r = ptrace(PT_SETFPREGS, dbgctx.pid, fpreg64, NULL);
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

    if (dbgctx.pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    dbreg64 = (struct __dbreg64 *)packet->data;
    if (!dbreg64) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }
    
    r = ptrace(PT_SETDBREGS, dbgctx.pid, dbreg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_start_run_handle(int fd, struct cmd_packet *packet) {
    int r;
    int status;

    if (dbgctx.pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    while(1) {
        //scePthreadYield();

        if(dbgctx.pid != -1) {
            r = net_recv_data(fd, &status, sizeof(uint32_t), 0);

            // check if disconnected
            if (errno) {
                break;
            }

            if(r == sizeof(uint32_t)) {
                if(r == CMD_DEBUG_STOP_RUN) {
                    break;
                }
            }

            if(wait4(dbgctx.pid, &status, WNOHANG, NULL)) {
                uprintf("debug_monitor caught status %X", status);
                
                char buffer[100];
                snprintf(buffer, sizeof(buffer), "status %s", status);
                net_send_data(fd, buffer, sizeof(buffer));

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

    return 0;
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
        case CMD_DEBUG_START_RUN: {
            // once the debugger is started, this will now recv
            return debug_start_run_handle(fd, packet);
        }
        case CMD_DEBUG_STOP_RUN: {
            // this command is actuall just sent to the debugger raw (recieved above in function debug_start_run_handle)
            return 0;
        }
            // stop the debugger

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