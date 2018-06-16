// golden
// 6/12/2018
//

#include "console.h"

int console_handle(int fd, struct cmd_packet *packet) {
    net_send_data(fd, "hello", 5);

    return 0;
}
