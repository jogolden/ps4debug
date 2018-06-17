// golden
// 6/12/2018
//

#include "console.h"

int console_reboot_handle(int fd, struct cmd_packet *packet) {
    sys_console_cmd(SYS_CONSOLE_CMD_REBOOT, NULL);
    return 1;
}

int console_print_handle(int fd, struct cmd_packet *packet) {
    struct cmd_console_print_packet *pp;
    void *data;

    pp = (struct cmd_console_print_packet *)packet->data;

    if(pp) {
        data = malloc(pp->length);
        net_recv_data(fd, data, pp->length, 1);
        sys_console_print(data);
        net_send_status(fd, CMD_SUCCESS);
        free(data);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);

    return 1;
}

int console_handle(int fd, struct cmd_packet *packet) {
    switch(packet->cmd) {
        case CMD_CONSOLE_REBOOT:
            return console_reboot_handle(fd, packet);
        case CMD_CONSOLE_END:
            // todo: handle ending ps4debug correctly
            return 1;
        case CMD_CONSOLE_PRINT:
            return console_print_handle(fd, packet);
    }


    return 0;
}
