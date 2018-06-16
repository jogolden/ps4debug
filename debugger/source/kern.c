// golden
// 6/12/2018
//

#include "kern.h"

int kern_base_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int kern_read_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int kern_write_handle(int fd, struct cmd_packet *packet) {
    return 0;
}

int kern_handle(int fd, struct cmd_packet *packet) {
    switch(packet->cmd) {
        case CMD_KERN_BASE:
            return kern_base_handle(fd, packet);
        case CMD_KERN_READ:
            return kern_read_handle(fd, packet);
        case CMD_KERN_WRITE:
            return kern_write_handle(fd, packet);
    }

    return 1;
}
