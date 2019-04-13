// golden
// 6/12/2018
//

#include "debug.h"

int g_debugging;
struct server_client *curdbgcli;
struct debug_context *curdbgctx;

int debug_attach_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_attach_packet *ap;
    int r;

    if(g_debugging) {
        net_send_status(fd, CMD_ALREADY_DEBUG);
        return 1;
    }

    ap = (struct cmd_debug_attach_packet *)packet->data;

    if(ap) {
        r = ptrace(PT_ATTACH, ap->pid, NULL, NULL);
        if(r) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }

        r = ptrace(PT_CONTINUE, ap->pid, (void *)1, NULL);
        if(r) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }

        // connect to server
        r = connect_debugger(curdbgctx, &curdbgcli->client);
        if(r) {
            uprintf("could not connect to server");
            net_send_status(fd, CMD_ERROR);
            return 1;
        }

        curdbgcli->debugging = 1;
        curdbgctx->pid = ap->pid;

        uprintf("debugger is attached");

        net_send_status(fd, CMD_SUCCESS);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);

    return 1;
}

int debug_detach_handle(int fd, struct cmd_packet *packet) {
    debug_cleanup(curdbgctx);

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_breakpt_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_breakpt_packet *bp;
    uint8_t int3;

    bp = (struct cmd_debug_breakpt_packet *)packet->data;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!bp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if(bp->index >= MAX_BREAKPOINTS) {
        net_send_status(fd, CMD_INVALID_INDEX);
        return 1;
    }

    struct debug_breakpoint *breakpoint = &curdbgctx->breakpoints[bp->index];

    if(bp->enabled) {
        breakpoint->enabled = 1;
        breakpoint->address = bp->address;

        sys_proc_rw(curdbgctx->pid, breakpoint->address, &breakpoint->original, 1, 0);

        int3 = 0xCC;
        sys_proc_rw(curdbgctx->pid, breakpoint->address, &int3, 1, 1);
    } else {
        sys_proc_rw(curdbgctx->pid, breakpoint->address, &breakpoint->original, 1, 1);

        breakpoint->enabled = 0;
        breakpoint->address = NULL;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_watchpt_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_watchpt_packet *wp;
    struct __dbreg64 *dbreg64;
    uint32_t *lwpids;
    int nlwps;
    int r;
    int size;

    wp = (struct cmd_debug_watchpt_packet *)packet->data;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!wp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if(wp->index >= MAX_WATCHPOINTS) {
        net_send_status(fd, CMD_INVALID_INDEX);
        return 1;
    }

    // get the threads
    nlwps = ptrace(PT_GETNUMLWPS, curdbgctx->pid, NULL, 0);
    size = nlwps * sizeof(uint32_t);
    lwpids = (uint32_t *)pfmalloc(size);
    if(!lwpids) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    r = ptrace(PT_GETLWPLIST, curdbgctx->pid, (void *)lwpids, nlwps);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        goto finish;
    }

    dbreg64 = (struct __dbreg64 *)&curdbgctx->watchdata;

    // setup the watchpoint
    dbreg64->dr[7] &= ~DBREG_DR7_MASK(wp->index);
    if(wp->enabled) {
        dbreg64->dr[wp->index] = wp->address;
        dbreg64->dr[7] |= DBREG_DR7_SET(wp->index, wp->length, wp->breaktype, DBREG_DR7_LOCAL_ENABLE | DBREG_DR7_GLOBAL_ENABLE);
    } else {
        dbreg64->dr[wp->index] = NULL;
        dbreg64->dr[7] |= DBREG_DR7_SET(wp->index, NULL, NULL, DBREG_DR7_DISABLE);
    }

    //uprintf("dr%i: %llX dr7: %llX", wp->index, wp->address, dbreg64->dr[7]);

    // for each current lwpid edit the watchpoint
    for(int i = 0; i < nlwps; i++) {
        r = ptrace(PT_SETDBREGS, lwpids[i], dbreg64, NULL);
        if (r == -1 && errno) {
            net_send_status(fd, CMD_ERROR);
            goto finish;
        }
    }

    net_send_status(fd, CMD_SUCCESS);

finish:
    free(lwpids);

    return r;
}

int debug_threads_handle(int fd, struct cmd_packet *packet) {
    void *lwpids;
    int nlwps;
    int r;
    int size;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    nlwps = ptrace(PT_GETNUMLWPS, curdbgctx->pid, NULL, 0);

    if(nlwps == -1) {
        net_send_status(fd, CMD_ERROR);
        return 0;
    }

    // i assume the lwpid_t is 32 bits wide
    size = nlwps * sizeof(uint32_t);
    lwpids = pfmalloc(size);
    if(!lwpids) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    r = ptrace(PT_GETLWPLIST, curdbgctx->pid, lwpids, nlwps);

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

    if(curdbgctx->pid == 0) {
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

    if(curdbgctx->pid == 0) {
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

    if (curdbgctx->pid == 0) {
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

int debug_getfpregs_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_getregs_packet *rp;
    struct savefpu_ymm savefpu;
    int r;

    rp = (struct cmd_debug_getregs_packet *)packet->data;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    r = ptrace(PT_GETFPREGS, rp->lwpid, &savefpu, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &savefpu, sizeof(struct savefpu_ymm));

    return 0;
}

int debug_getdbregs_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_getregs_packet *rp;
    struct __dbreg64 dbreg64;
    int r;

    rp = (struct cmd_debug_getregs_packet *)packet->data;

    if (curdbgctx->pid == 0) {
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
    struct cmd_debug_setregs_packet *sp;
    struct __reg64 reg64;
    int r;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    sp = (struct cmd_debug_setregs_packet *)packet->data;
    if (!sp) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_recv_data(fd, &reg64, sp->length, 1);

    r = ptrace(PT_SETREGS, curdbgctx->pid, &reg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_setfpregs_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_setregs_packet *sp;
    struct savefpu_ymm *fpregs;
    int r;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    sp = (struct cmd_debug_setregs_packet *)packet->data;
    if (!sp) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_recv_data(fd, &fpregs, sp->length, 1);

    r = ptrace(PT_SETFPREGS, curdbgctx->pid, fpregs, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_setdbregs_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_setregs_packet *sp;
    struct __dbreg64 dbreg64;
    int r;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    sp = (struct cmd_debug_setregs_packet *)packet->data;

    if (!sp) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_recv_data(fd, &dbreg64, sp->length, 1);

    r = ptrace(PT_SETDBREGS, curdbgctx->pid, &dbreg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_stopgo_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_stopgo_packet *sp;
    int signal;
    int r;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    sp = (struct cmd_debug_stopgo_packet *)packet->data;

    if(!sp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    signal = NULL;

    if(sp->stop == 1) {
        signal = SIGSTOP;
    } else if(sp->stop == 2) {
        signal = SIGKILL;
    }

    r = ptrace(PT_CONTINUE, curdbgctx->pid, (void *)1, signal);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debug_thrinfo_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_thrinfo_packet *tp;
    struct cmd_debug_thrinfo_response resp;
    struct sys_proc_thrinfo_args args;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    tp = (struct cmd_debug_thrinfo_packet *)packet->data;

    if(!tp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    args.lwpid = tp->lwpid;
    sys_proc_cmd(curdbgctx->pid, SYS_PROC_THRINFO, &args);
    
    resp.lwpid = args.lwpid;
    resp.priority = args.priority;
    memcpy(resp.name, args.name, sizeof(resp.name));

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &resp, CMD_DEBUG_THRINFO_RESPONSE_SIZE);

    return 0;
}

int debug_singlestep_handle(int fd, struct cmd_packet *packet) {
    int r;

    if (curdbgctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    r = ptrace(PT_STEP, curdbgctx->pid, (void *)1, 0);
    if(r) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }
    
    net_send_status(fd, CMD_SUCCESS);
    
    return 0;
}

int connect_debugger(struct debug_context *dbgctx, struct sockaddr_in *client) {
    struct sockaddr_in server;
    int r;

    // we are now debugging
    g_debugging = 1;

    // connect to server
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = client->sin_addr.s_addr;
    server.sin_port = sceNetHtons(DEBUG_PORT);
    memset(server.sin_zero, NULL, sizeof(server.sin_zero));

    dbgctx->dbgfd = sceNetSocket("interrupt", AF_INET, SOCK_STREAM, 0);
    if(dbgctx->dbgfd <= 0) {
        return 1;
    }

    r = sceNetConnect(dbgctx->dbgfd, (struct sockaddr *)&server, sizeof(server));
    if(r) {
        return 1;
    }

    return 0;
}

void debug_cleanup(struct debug_context *dbgctx) {
    struct __dbreg64 dbreg64;
    uint32_t *lwpids;
    int nlwps;
    int r;

    // clean up stuff
    curdbgcli->debugging = 0;

    // delete references
    g_debugging = 0;
    curdbgcli = NULL;
    curdbgctx = NULL;

    // disable all breakpoints
    for(int i = 0; i < MAX_BREAKPOINTS; i++) {
        sys_proc_rw(dbgctx->pid, dbgctx->breakpoints[i].address, &dbgctx->breakpoints[i].original, 1, 1);
    }

    // reset all debug registers
    nlwps = ptrace(PT_GETNUMLWPS, dbgctx->pid, NULL, 0);
    lwpids = (uint32_t *)pfmalloc(nlwps * sizeof(uint32_t));
    if(lwpids) {
        memset(&dbreg64, NULL, sizeof(struct __dbreg64));

        r = ptrace(PT_GETLWPLIST, dbgctx->pid, (void *)lwpids, nlwps);
        if(!r) {
            for(int i = 0; i < nlwps; i++) {
                ptrace(PT_SETDBREGS, lwpids[i], &dbreg64, NULL);
            }
        }

        free(lwpids);
    }

    ptrace(PT_CONTINUE, dbgctx->pid, (void *)1, NULL);
    ptrace(PT_DETACH, dbgctx->pid, NULL, NULL);

    sceNetSocketClose(dbgctx->dbgfd);
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
        case CMD_DEBUG_SETREGS:
            return debug_setregs_handle(fd, packet);
        case CMD_DEBUG_GETFPREGS:
            return debug_getfpregs_handle(fd, packet);
        case CMD_DEBUG_SETFPREGS:
            return debug_setfpregs_handle(fd, packet);
        case CMD_DEBUG_GETDBGREGS:
            return debug_getdbregs_handle(fd, packet);
        case CMD_DEBUG_SETDBGREGS:
            return debug_setdbregs_handle(fd, packet);
        case CMD_DEBUG_STOPGO:
            return debug_stopgo_handle(fd, packet);
        case CMD_DEBUG_THRINFO:
            return debug_thrinfo_handle(fd, packet);
        case CMD_DEBUG_SINGLESTEP:
            return debug_singlestep_handle(fd, packet);
        default:
            return 1;
    }
}