// golden
// 6/12/2018
//

#ifndef _NET_H
#define _NET_H

#include <ps4.h>

#define NET_MAX_LENGTH      4096

#define NET_STATUS_SUCCESS  0x80000001
#define NET_STATUS_ERROR    0x80000002

#define NET_FATAL_STATUS(s) ((s >> 28) == 15)

int net_send_data(int fd, void *data, int length);
int net_recv_data(int fd, void *data, int length);
int net_send_status(int fd, uint32_t status);

#endif
