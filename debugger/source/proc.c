// golden
// 6/12/2018
//

#include "proc.h"

void proc_handle(int fd, struct cmd_packet *packet) {
    net_send_data(fd, "hello", 5);
}
