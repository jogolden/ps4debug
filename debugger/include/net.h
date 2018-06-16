// golden
// 6/12/2018
//

#ifndef _NET_H
#define _NET_H

#include <ps4.h>

#define NET_MAX_LENGTH      4096

int net_send_data(int fd, void *data, int length);
int net_recv_data(int fd, void *data, int length, int force);
int net_send_status(int fd, uint32_t status);

#endif
