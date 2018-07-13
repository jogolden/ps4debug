// golden
// 6/12/2018
//

#include "server.h"

int cmd_handler(int fd, struct cmd_packet *packet) {
	if (!VALID_CMD(packet->cmd)) {
		return 1;
	}

    uprintf("[ps4debug] cmd_handler %X", packet->cmd);

    if(VALID_PROC_CMD(packet->cmd)) {
        return proc_handle(fd, packet);
    } else if(VALID_DEBUG_CMD(packet->cmd)) {
        return debug_handle(fd, packet);
    } else if(VALID_KERN_CMD(packet->cmd)) {
        return kern_handle(fd, packet);
    } else if(VALID_CONSOLE_CMD(packet->cmd)) {
        return console_handle(fd, packet);
    }

    return 0;
}

int handle_client(int fd) {
    struct cmd_packet packet;
    uint32_t length;
    void *data;
    int r;

    while(1) {
        sceKernelUsleep(50000);

        errno = NULL;
        r = net_recv_data(fd, &packet, CMD_PACKET_SIZE, 0);

        // check if disconnected
        if (errno) {
            goto error;
        }

        // if we didnt recieve anything just try again
        if (!r) {
			continue;
		}

        uprintf("[ps4debug] client packet %i", fd);

        // invalid packet
		if (packet.magic != PACKET_MAGIC) {
            uprintf("[ps4debug] invalid packet magic %X!", packet.magic);
			continue;
		}

		// mismatch received size
		if (r != CMD_PACKET_SIZE) {
            uprintf("[ps4debug] invalid recieve size %i!", r);
			continue;
		}

        length = packet.datalen;
		if (length) {
			// allocate data
			data = malloc(length);
			if (!data) {
				goto error;
			}

            uprintf("[ps4debug] recieving data length %i", length);

			// recv data
			r = net_recv_data(fd, data, length, 1);
			if (!r) {
				goto error;
			}

			// set data
			packet.data = data;
		} else {
			packet.data = NULL;
		}

        // check crc if there is one
        if(packet.crc != crc32(0, data, length)) {
            //goto error;
        }

		// handle the packet
		r = cmd_handler(fd, &packet);

    	if (data) {
			free(data);
			data = NULL;
		}

		// check cmd handler error
		if (r) {
			goto error;
		}
    }

error:
    uprintf("[ps4debug] client disconnected %i", fd);
    sceNetSocketClose(fd);

    return 0;
}

void start_server() {
    struct sockaddr_in server;
    int serv, fd, flag;

    uprintf("[ps4debug] server started");

    // server structure
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = SERVER_IN;
    server.sin_port = sceNetHtons(SERVER_PORT);
    memset(server.sin_zero, 0, sizeof(server.sin_zero));

    // start up server
    serv = sceNetSocket("dbgsock", AF_INET, SOCK_STREAM, 0);

    flag = 1;
	sceNetSetsockopt(serv, SOL_SOCKET, SO_NBIO, (char *)&flag, sizeof(int));
    
    flag = 1;
    sceNetSetsockopt(serv, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    sceNetBind(serv, (struct sockaddr *)&server, sizeof(server));

    sceNetListen(serv, 2);

    while(1) {
        //scePthreadYield();

        errno = NULL;
        fd = sceNetAccept(serv, NULL, NULL);
        if(fd > -1 && !errno) {
            uprintf("[ps4debug] accepted a client");

            flag = 1;
            sceNetSetsockopt(fd, SOL_SOCKET, SO_NBIO, (char *)&flag, sizeof(int));
            
            flag = 1;
            sceNetSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

            // this will block until the client disconnects
            handle_client(fd);
        }

        sceKernelSleep(1);
    }
}
