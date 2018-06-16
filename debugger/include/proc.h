// golden
// 6/12/2018
//

#ifndef _PROC_H
#define _PROC_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"

int proc_list_handle(int fd, struct cmd_packet *packet);
int proc_read_handle(int fd, struct cmd_packet *packet);
int proc_write_handle(int fd, struct cmd_packet *packet);
int proc_info_handle(int fd, struct cmd_packet *packet);
int proc_install_handle(int fd, struct cmd_packet *packet);
int proc_call_handle(int fd, struct cmd_packet *packet);
int proc_protect_handle(int fd, struct cmd_packet *packet);

int proc_handle(int fd, struct cmd_packet *packet);

#endif
