// golden
// 6/12/2018
//

#ifndef _SERVER_H
#define _SERVER_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"

#include "proc.h"
#include "debug.h"
#include "kern.h"
#include "console.h"

#define SERVER_IN               IN_ADDR_ANY
#define SERVER_PORT             744

// this will block
void configure_socket(int fd, int buffersize);
void start_server();

#endif
