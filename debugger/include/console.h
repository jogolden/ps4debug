// golden
// 6/12/2018
//

#ifndef _CONSOLE_H
#define _CONSOLE_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"

int console_handle(int fd, struct cmd_packet *packet);

#endif
