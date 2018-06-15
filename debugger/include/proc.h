// golden
// 6/12/2018
//

#ifndef _PROC_H
#define _PROC_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"

void proc_handle(int fd, struct cmd_packet *packet);

#endif
