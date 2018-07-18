// golden
// 6/12/2018
//

#include "debug.h"

struct debug_context dbgctx;

int connect_client() {
    struct sockaddr_in server;

    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = dbgctx.client.sin_addr.s_addr;
    server.sin_port = sceNetHtons(DBG_PORT);
    memset(server.sin_zero, NULL, sizeof(server.sin_zero));

    dbgctx.clientfd = sceNetSocket("dbgclient", AF_INET, SOCK_STREAM, 0);
    if(dbgctx.clientfd <= 0) {
        return 1;
    }

    errno = NULL;
    int r = sceNetConnect(dbgctx.clientfd, (struct sockaddr *)&server, sizeof(server));
    if(r) {
        return 1;
    }

    return 0;
}

int debug_attach_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_attach_packet *ap;
    int r;

    ap = (struct cmd_debug_attach_packet *)packet->data;

    if(ap) {
        r = ptrace(PT_ATTACH, ap->pid, NULL, NULL);
        if(r) {
            uprintf("[ps4debug] ptrace PT_ATTACH failed");
            net_send_status(fd, CMD_ERROR);
            return 1;    
        }

        //wait4(ap->pid, NULL, NULL, NULL);
        r = ptrace(PT_CONTINUE, ap->pid, (void *)1, NULL);
        if(r) {
            uprintf("[ps4debug] ptrace PT_CONTINUE failed");
            net_send_status(fd, CMD_ERROR);
            return 1;    
        }

        dbgctx.pid = ap->pid;
        memset(dbgctx.breakpoints, NULL, sizeof(dbgctx.breakpoints));

        // connect to server
        r = connect_client();
        if(r) {
            uprintf("[ps4debug] could not connect to server");
            net_send_status(fd, CMD_ERROR);
            return 1;    
        }

        uprintf("[ps4debug] debugger is attached");

        net_send_status(fd, CMD_SUCCESS);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);

    return 1;
}

int debug_detach_handle(int fd, struct cmd_packet *packet) {
    debug_cleanup();

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
    struct __dbreg64 dbreg64;
    uint32_t *lwpids;
    int nlwps;
    int r;
    int size;

    wp = (struct cmd_debug_watchpt_packet *)packet->data;
    
    if (dbgctx.pid == -1) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if(!wp) {
        net_send_status(fd, CMD_SUCCESS);
        return 1;
    }

    // get the threads

    nlwps = ptrace(PT_GETNUMLWPS, dbgctx.pid, NULL, 0);
    size = nlwps * sizeof(uint32_t);
    lwpids = (uint32_t *)malloc(size);
    
    r = ptrace(PT_GETLWPLIST, dbgctx.pid, (void *)lwpids, nlwps);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    // get the current dr7
    // todo: find a better way? we just use the first one

    r = ptrace(PT_GETDBREGS, lwpids[0], &dbreg64, NULL);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    // setup the watchpoint
    dbreg64.dr[7] &= ~DBREG_DR7_MASK(wp->index);
    if(wp->enabled) {
        dbreg64.dr[wp->index] = wp->address;
        dbreg64.dr[7] |= DBREG_DR7_SET(wp->index, wp->length, wp->breaktype, DBREG_DR7_LOCAL_ENABLE | DBREG_DR7_GLOBAL_ENABLE);
    } else {
        dbreg64.dr[wp->index] = NULL;
        dbreg64.dr[7] |= DBREG_DR7_SET(wp->index, NULL, NULL, DBREG_DR7_DISABLE);
    }

    uprintf("[ps4debug] dr%i: %llX dr7: %llX", wp->index, wp->address, dbreg64.dr[7]);

    // for each current lwpid edit the watchpoint
    for(int i = 0; i < nlwps; i++) {
        r = ptrace(PT_SETDBREGS, lwpids[i], &dbreg64, NULL);
        if (r == -1 && errno) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }
    }

    net_send_status(fd, CMD_SUCCESS);
    free(lwpids);

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

int debug_stopgo_handle(int fd, struct cmd_packet *packet) {
    struct cmd_debug_stopgo_packet *sp;
    int signal;
    int r;

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
    
    r = ptrace(PT_CONTINUE, dbgctx.pid, (void *)1, signal);
    if (r == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

void debug_cleanup() {
    struct __dbreg64 dbreg64;
    uint32_t *lwpids;
    int nlwps;
    int r;

    if(dbgctx.pid != -1) {
        // reset all debug registers
        nlwps = ptrace(PT_GETNUMLWPS, dbgctx.pid, NULL, 0);
        lwpids = (uint32_t *)malloc(nlwps * sizeof(uint32_t));

        memset(&dbreg64, NULL, sizeof(struct __dbreg64));

        r = ptrace(PT_GETLWPLIST, dbgctx.pid, (void *)lwpids, nlwps);
        if(!r) {
            for(int i = 0; i < nlwps; i++) {
                ptrace(PT_SETDBREGS, lwpids[i], &dbreg64, NULL);
            }
        }

        free(lwpids);

        ptrace(PT_CONTINUE, dbgctx.pid, (void *)1, NULL);
        ptrace(PT_DETACH, dbgctx.pid, NULL, NULL);
        sceNetSocketClose(dbgctx.clientfd);
        dbgctx.pid = dbgctx.clientfd = -1;
    }
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
        case CMD_DEBUG_GETFREGS:
            return debug_getfregs_handle(fd, packet);
        case CMD_DEBUG_SETFREGS:
            return debug_setfregs_handle(fd, packet);
        case CMD_DEBUG_GETDBGREGS:
            return debug_getdbregs_handle(fd, packet);
        case CMD_DEBUG_SETDBGREGS:
            return debug_setdbregs_handle(fd, packet);
        case CMD_DEBUG_STOPGO:
            return debug_stopgo_handle(fd, packet);

        // TOOD: implement more commands
        // single stepping etc
        default:
            return 1;
    }
}