// golden
// 6/12/2018
//

#include "server.h"

struct debug_server dbgsrv;

int add_client(int client) {
    int idx = -1;
    for(int i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if(dbgsrv.clients[i] == -1) {
            idx = i;
            break;
        }
    }

    if(idx != -1) {
        dbgsrv.clients[idx] = client;
        return 0;
    }

    return 1;
}

void remove_client(int client) {
    for(int i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if(dbgsrv.clients[i] == client) {
            dbgsrv.clients[i] = -1;
            break;
        }
    }
}

void reset_clients() {
    for(int i = 0; i < SERVER_MAX_CLIENTS; i++) {
        dbgsrv.clients[i] = -1;
    }
}

int cmd_handler(int fd, struct cmd_packet *packet) {
	if (!VALID_CMD(packet->cmd)) {
		return 1;
	}

    if(VALID_PROC_CMD(packet->cmd)) {
        proc_handle(fd, packet);
    } else if(VALID_DEBUG_CMD(packet->cmd)) {
        debug_handle(fd, packet);
    } else if(VALID_KERN_CMD(packet->cmd)) {
        kern_handle(fd, packet);
    } else if(VALID_CONSOLE_CMD(packet->cmd)) {
        console_handle(fd, packet);
    }

    return 0;
}

void *client_thread(void *arg) {
    int r, fd;
    struct cmd_packet packet;
    uint32_t length;
    uint8_t *data;

    fd = (uint64_t)(void *)arg;

    while(dbgsrv.run_server) {
        r = net_recv_data(fd, &packet, CMD_PACKET_SIZE);
        if (!r) {
			// check if disconnected
			if (errno == 0) {
				goto error;
			}

			continue;
		}
        
        // invalid packet
		if (packet.magic != PACKET_MAGIC) {
			continue;
		}

		// mismatch received size
		if (r != CMD_PACKET_SIZE) {
			continue;
		}

        length = packet.datalen;
		if (length) {
			// allocate data
			data = (uint8_t *)malloc(length);
			if (!data) {
				goto error;
			}

			// recv data
			r = net_recv_data(fd, data, length);
			if (!r) {
				goto error;
			}

			// set data
			packet.data = data;
		} else {
			packet.data = 0;
		}

        // check crc if there is one
        if(packet.crc) {
            if(packet.crc != crc32(0, data, length)) {
                goto error;
            }
        }

		// handle the packet
		r = cmd_handler(fd, &packet);

    	if (data) {
			free(data);
			data = 0;
		}

		// check cmd handler error (or end cmd)
		if (r) {
			goto error;
		}

        sceKernelUsleep(300000);
    }

error:
    sceNetSocketClose(fd);

    return 0;
}

void *server_thread(void *arg) {
    while(dbgsrv.run_server) {
        int clsock = sceNetAccept(dbgsrv.servsock, NULL, NULL);
        if(add_client(clsock)) {
            net_send_status(clsock, NET_STATUS_ERROR);
            sceNetSocketClose(clsock);
        } else {
            int flag = 1;
            sceNetSetsockopt(clsock, SOL_SOCKET, SO_NBIO, (char *)&flag, sizeof(int));

            ScePthread thread;
            scePthreadCreate(&thread, NULL, client_thread, (void *)(uint64_t)clsock, "dbgclient");
        }

        sceKernelUsleep(600000);
    }

    return 0;
}

void start_server() {
    // reset server
    memset(&dbgsrv, 0, sizeof(struct debug_server));
    reset_clients();

    // server structure
    dbgsrv.server.sin_len = sizeof(dbgsrv.server);
    dbgsrv.server.sin_family = AF_INET;
    dbgsrv.server.sin_addr.s_addr = SERVER_IN;
    dbgsrv.server.sin_port = sceNetHtons(SERVER_PORT);
    memset(dbgsrv.server.sin_zero, 0, sizeof(dbgsrv.server.sin_zero));

    // start up server
    dbgsrv.servsock = sceNetSocket("dbgsock", AF_INET, SOCK_STREAM, 0);

    int flag = 1;
	sceNetSetsockopt(dbgsrv.servsock, SOL_SOCKET, SO_NBIO, (char *)&flag, sizeof(int));

    sceNetBind(dbgsrv.servsock, (struct sockaddr *)&dbgsrv.server, sizeof(dbgsrv.server));

    sceNetListen(dbgsrv.servsock, 16);

    dbgsrv.run_server = 1;

    ScePthread servthr;
    scePthreadCreate(&servthr, NULL, server_thread, NULL, "dbgserver");
}

void stop_server() {
    // close clients
    for(int i = 0; i < SERVER_MAX_CLIENTS; i++) {
        if(dbgsrv.clients[i] != -1) {
            sceNetSocketClose(dbgsrv.clients[i]);
        }
    }

    // close socket
    sceNetSocketClose(dbgsrv.servsock);

    // reset server
    memset(&dbgsrv, 0, sizeof(struct debug_server));
    reset_clients();
}
