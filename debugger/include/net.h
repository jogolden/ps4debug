// golden
// 6/12/2018
//

#ifndef _NET_H
#define _NET_H

#include <ps4.h>
#include "errno.h"

#define NET_MAX_LENGTH      4096

// I would like to move away from the stupid sony wrapper functions
// They do not always return what I expect and I want to use straight syscalls

int net_send_data(int fd, void *data, int length);
int net_recv_data(int fd, void *data, int length, int force);
int net_send_status(int fd, uint32_t status);

#endif
