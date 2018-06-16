// golden
// 6/12/2018
//

#include "debug.h"

int debug_attach_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int debug_detach_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int debug_stop_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int debug_resume_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int debug_breakpt_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int debug_watchpt_handle(int fd, struct cmd_packet *packet) {
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

// todo: registers

int debug_handle(int fd, struct cmd_packet *packet) {
    switch(packet->cmd) {
        case CMD_DEBUG_ATTACH:
            return debug_attach_handle(fd, packet);
        case CMD_DEBUG_DETACH:
            return debug_detach_handle(fd, packet);
        case CMD_DEBUG_STOP:
            return debug_stop_handle(fd, packet);
        case CMD_DEBUG_RESUME:
            return debug_resume_handle(fd, packet);
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

        // todo: registers
        /*case CMD_DEBUG_GETREGS:
        case CMD_DEBUG_SETREGS:
        case CMD_DEBUG_GETFREGS:
        case CMD_DEBUG_SETFREGS:
        case CMD_DEBUG_GETDBGREGS:
        case CMD_DEBUG_SETDBGREGS:*/
    }

    return 1;
}
