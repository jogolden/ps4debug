// golden
// 6/12/2018
//

#ifndef _CONSOLE_H
#define _CONSOLE_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"
#include "debug.h"

int console_reboot_handle(int fd, struct cmd_packet *packet);
int console_print_handle(int fd, struct cmd_packet *packet);
int console_notify_handle(int fd, struct cmd_packet *packet);
int console_info_handle(int fd, struct cmd_packet *packet);

int console_handle(int fd, struct cmd_packet *packet);

#endif
