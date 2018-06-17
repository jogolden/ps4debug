// golden
// 6/12/2018
//

#include "debug.h"

int dbg_pid;
int dbg_fd;
struct debug_breakpoint breakpoints[MAX_BREAKPOINTS];
struct debug_watchpoint watchpoints[MAX_WATCHPOINTS];

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

int debug_getregs_handle(int fd, struct cmd_packet *packet) {
    //check the pid if already assigned, we can call PT_VM_TIMESTAMP to be more precisely.
    if (dbg_pid == -1)
    {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    //clear the errno before calling the function to disambiguate, sometimes ptrace return -1 for success or 0 for most successful operations.
    //calling the ptrace and check if errno has assigned, Successful calls never set errno; once set, it remains until another error occurs.

    errno = 0;
    struct __reg64 reg64;
    ptrace(PT_GETREGS, dbg_pid, &reg64, NULL);
    if (errno != 0)
    {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }
    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &reg64, sizeof(struct __reg64));
    return 0;
}
int debug_getfregs_handle(int fd, struct cmd_packet *packet) {
    //check the pid if already assigned, we can call PT_TIMESTAMP to be more precisely.
    if (dbg_pid == -1)
    {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    //clear the errno before calling the function to disambiguate, sometimes ptrace return -1 for success or 0 for most successful operations.
    //calling the ptrace and check if errno has assigned, Successful calls never set errno; once set, it remains until another error occurs.

    errno = 0;
    struct __fpreg64 fpreg64;
    ptrace(PT_GETFPREGS, dbg_pid, &fpreg64, NULL);
    if (errno != 0)
    {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }
    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &fpreg64, sizeof(struct __fpreg64));
    return 0;
}
int debug_getdbregs_handle(int fd, struct cmd_packet *packet) {
    //check the pid if already assigned, we can call PT_TIMESTAMP to be more precisely.
    if (dbg_pid == -1)
    {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    //clear the errno before calling the function to disambiguate, sometimes ptrace return -1 for success or 0 for most successful operations.
    //calling the ptrace and check if errno has assigned, Successful calls never set errno; once set, it remains until another error occurs.

    errno = 0;
    struct __dbreg64 dbreg64;
    ptrace(PT_GETDBREGS, dbg_pid, &dbreg64, NULL);
    if (errno != 0)
    {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }
    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &dbreg64, sizeof(struct __dbreg64));
    return 0;
}

int debug_setregs_handle(int fd, struct cmd_packet *packet) {
    //check the pid if already assigned, we can call PT_TIMESTAMP to be more precisely.
    if (dbg_pid == -1)
    {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    //todo: need more suggestions
    return 0;
}
int debug_breakpt_handle(int fd, struct cmd_packet *packet) {
    // read original byte
    // write 0xCC to process
    // call wait4 on process
    // wait until trap -> debug_monitor_thread
    return 0;
}

int debug_watchpt_handle(int fd, struct cmd_packet *packet) {
    // use debug registers
    return 0;
}

int debug_threads_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int debug_stopthr_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int debug_resumethr_handle(int fd, struct cmd_packet *packet) {
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

            // todo: registers
            /*
            case CMD_DEBUG_SETREGS:
            case CMD_DEBUG_SETFREGS:
            case CMD_DEBUG_SETDBGREGS:*/
        default:
            return 1;
    }
}