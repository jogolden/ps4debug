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
#define SERVER_MAXCLIENTS       8

extern struct server_client servclients[SERVER_MAXCLIENTS];

struct server_client *alloc_client();
void free_client(struct server_client *svc);
void configure_socket(int fd);
int start_server();

#endif
