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

int check_debug_interrupt(int fd) {
    uint8_t lwpinfo[512]; // I allocate more since I actually dont know the size
    int status;

    if(wait4(dbgctx.pid, &status, WNOHANG, NULL)) {
        if(WSTOPSIG(status) == SIGSTOP) {
            return 0;
        }

        uprintf("wait4 caught status 0x%X signal %i", status, WSTOPSIG(status));

        struct debug_interrupt_packet *resp = (struct debug_interrupt_packet *)malloc(sizeof(struct debug_interrupt_packet));
        if(!resp) {
            return 1;
        }

        // todo: actually map this structure lol
        ptrace(PT_LWPINFO, dbgctx.pid, lwpinfo, 0x98);

        memset(resp, NULL, sizeof(struct debug_interrupt_packet));

        resp->lwpid = *(uint32_t *)lwpinfo;
        resp->status = status;
        
        memcpy(resp->tdname, (void *)(lwpinfo + 0x80), 40);

        ptrace(PT_GETREGS, resp->lwpid, &resp->reg64, NULL);
        //ptrace(PT_GETFPREGS, resp->lwpid, &resp->fpreg64, NULL);
        //ptrace(PT_GETDBREGS, resp->lwpid, &resp->dbreg64, NULL);
        
        net_send_data(dbgctx.clientfd, resp, sizeof(struct debug_interrupt_packet));

        free(resp);
    }

    return 0;
}

int handle_client(int fd, struct sockaddr_in *client) {
    struct cmd_packet packet;
    uint32_t length;
    void *data;
    int r;

    // setup debug context client data
    dbgctx.pid = dbgctx.clientfd = -1;
    memcpy(&dbgctx.client, client, sizeof(struct sockaddr_in));

    while(1) {
        sceKernelUsleep(30000);
        
        if(dbgctx.pid != -1 && dbgctx.clientfd > 0) {
            if(check_debug_interrupt(fd)) {
                goto error;
            }
        }


        memset(&packet, NULL, CMD_PACKET_SIZE);
        r = net_recv_data(fd, &packet, CMD_PACKET_SIZE, 0);

        // if we didnt recieve anything just try again
        if (!r) {
            // check if disconnected
            if (errno == ECONNRESET) {
                goto error;
            }

			continue;
		}

        uprintf("[ps4debug] client packet");

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
        //if(packet.crc != crc32(0, data, length)) {
            //goto error;
        //}

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
    uprintf("[ps4debug] client disconnected errno: %i", errno);
    sceNetSocketClose(fd);

    // if there is a dbgctx then release it
    // just like detach, we should clean this up
    debug_cleanup();

    return 0;
}

void start_server() {
    struct sockaddr_in server;
    struct sockaddr_in client;
    int serv, fd, flag;
    unsigned int len = sizeof(client);

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

    sceNetListen(serv, 4);

    while(1) {
        scePthreadYield();

        errno = NULL;
        fd = sceNetAccept(serv, (struct sockaddr *)&client, &len);
        if(fd > -1 && !errno) {
            uprintf("[ps4debug] accepted a client");
            //uprintf("data sizes: %X %X %X", sizeof(struct __reg64), sizeof(struct __fpreg64), sizeof(struct __dbreg64));

            flag = 1;
            sceNetSetsockopt(fd, SOL_SOCKET, SO_NBIO, (char *)&flag, sizeof(int));
            
            flag = 1;
            sceNetSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

            // this will block until the client disconnects
            handle_client(fd, &client);
        }

        sceKernelSleep(1);
    }
}
