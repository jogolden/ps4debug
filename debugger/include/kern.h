// golden
// 6/12/2018
//

#ifndef _KERN_H
#define _KERN_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"

void kern_handle(int fd, struct cmd_packet *packet);

#endif
