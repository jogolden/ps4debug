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

int check_debug_interrupt() {
    char lwpinfo[0x98];
    struct debug_interrupt_packet *resp;
    struct debug_breakpoint *breakpoint;
    uint8_t int3;
    int status;
    int signal;
    int r;

    // todo: more checks
    if(wait4(dbgctx.pid, &status, WNOHANG, NULL)) {
        signal = WSTOPSIG(status);

        uprintf("[ps4debug] check_debug_interrupt signal %i", signal);

        if(signal == SIGSTOP) {
            uprintf("[ps4debug] passed on a SIGSTOP");
            return 0;
        } else if(signal == SIGKILL) {
            // the process will die
            ptrace(PT_CONTINUE, dbgctx.pid, (void *)1, SIGKILL);
            
            // tiny cleanup, since process is dead now do not call debug_cleanup()
            sceNetSocketClose(dbgctx.clientfd);
            dbgctx.pid = dbgctx.clientfd = -1;
            
            uprintf("[ps4debug] sent final SIGKILL");
            return 0;
        }

        resp = (struct debug_interrupt_packet *)malloc(DEBUG_INTERRUPT_PACKET_SIZE);
        if(!resp) {
            uprintf("[ps4debug] could not allocate interrupt response");
            return 1;
        }

        // todo: make structure
        ptrace(PT_LWPINFO, dbgctx.pid, lwpinfo, 0x98);

        memset(resp, NULL, DEBUG_INTERRUPT_PACKET_SIZE);

        char *cast = (char *)lwpinfo;
        resp->lwpid = *(uint32_t *)cast;
        resp->status = status;
        
        memcpy(resp->tdname, (char *)(lwpinfo + 0x80), sizeof(resp->tdname));

        ptrace(PT_GETREGS, resp->lwpid, &resp->reg64, NULL);
        //ptrace(PT_GETFPREGS, resp->lwpid, &resp->fpreg64, NULL);
        //ptrace(PT_GETDBREGS, resp->lwpid, &resp->dbreg64, NULL);
        
        // if it is a software breakpoint we need to handle it accordingly
        breakpoint = NULL;
        for(int i = 0; i < MAX_BREAKPOINTS; i++) {
            if(dbgctx.breakpoints[i].address == resp->reg64.r_rip - 1) {
                breakpoint = &dbgctx.breakpoints[i];
                break;
            }
        }

        if(breakpoint) {
            uprintf("[ps4debug] dealing with software breakpoint");
            uprintf("[ps4debug] breakpoint: %llX %X", breakpoint->address, breakpoint->original);

            // write old instruction
            sys_proc_rw(dbgctx.pid, breakpoint->address, &breakpoint->original, 1, 1);

            // todo: clean this up

            resp->reg64.r_rip -= 1;
            ptrace(PT_SETREGS, resp->lwpid, &resp->reg64, NULL);

            ptrace(PT_STEP, resp->lwpid, (void *)1, NULL);
            
            while(!wait4(dbgctx.pid, &status, WNOHANG, NULL)) {
                sceKernelUsleep(40000);
            }

            //uprintf("waited for signal %i", WSTOPSIG(status));

            int3 = 0xCC;
            sys_proc_rw(dbgctx.pid, breakpoint->address, &int3, 1, 1);
        } else {
            uprintf("[ps4debug] dealing with hardware breakpoint");
        }
        
        r = net_send_data(dbgctx.clientfd, resp, DEBUG_INTERRUPT_PACKET_SIZE);
        if(r != DEBUG_INTERRUPT_PACKET_SIZE) {
            uprintf("[ps4debug] net_send_data failed %i %i", r, errno);
        }
        
        uprintf("[ps4debug] check_debug_interrupt interrupt data sent");

        free(resp);
    }

    return 0;
}

int handle_client(int fd, struct sockaddr_in *client) {
    struct cmd_packet packet;
    uint32_t rsize;
    uint32_t length;
    void *data;
    int r;

    // setup debug context client data
    dbgctx.pid = dbgctx.clientfd = -1;
    memcpy(&dbgctx.client, client, sizeof(struct sockaddr_in));

    // setup time val for select
    struct timeval tv;
    memset(&tv, NULL, sizeof(tv));
    tv.tv_usec = 8000;

    while(1) {
        // do a select
        fd_set sfd;
        FD_ZERO(&sfd);
        FD_SET(fd, &sfd);
        errno = NULL;
        net_select(FD_SETSIZE, &sfd, NULL, NULL, &tv);

        // check if we can recieve
        if(FD_ISSET(fd, &sfd)) {
            // zero out
            memset(&packet, NULL, CMD_PACKET_SIZE);

            // recieve our data
            rsize = net_recv_data(fd, &packet, CMD_PACKET_SIZE, 0);

            // if we didnt recieve hmm
            if (rsize <= 0) {
                goto error;
            }

            // check if disconnected
            if (errno == ECONNRESET) {
                goto error;
            }
        } else {
            // if we have a valid debugger context then check for interrupt
            // this does not block, as wait is called with option WNOHANG
            if(dbgctx.pid != -1 && dbgctx.clientfd != -1) {
                if(check_debug_interrupt()) {
                    goto error;
                }
            }

            sceKernelUsleep(30000);
            continue;
        }

        uprintf("[ps4debug] client packet recieved");

        // invalid packet
		if (packet.magic != PACKET_MAGIC) {
            uprintf("[ps4debug] invalid packet magic %X!", packet.magic);
			continue;
		}

		// mismatch received size
		if (rsize != CMD_PACKET_SIZE) {
            uprintf("[ps4debug] invalid recieve size %i!", rsize);
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

void configure_socket(int fd, int buffersize) {
    int flag;

    flag = 1;
    sceNetSetsockopt(fd, SOL_SOCKET, SO_NBIO, (char *)&flag, sizeof(flag));

    flag = 1;
    sceNetSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));

    flag = 1;
    sceNetSetsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char *)&flag, sizeof(flag));

    flag = 0;
    sceNetSetsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&flag, sizeof(flag));
    
    //flag = 0;
    //sceNetSetsockopt(fd, SOL_SOCKET, SO_USELOOPBACK, (char *)&flag, sizeof(flag));

    if(buffersize) {
        flag = NET_MAX_LENGTH;
        sceNetSetsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&flag, sizeof(flag));
        
        flag = NET_MAX_LENGTH;
        sceNetSetsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&flag, sizeof(flag));
    }
}

void start_server() {
    struct sockaddr_in server;
    struct sockaddr_in client;
    int serv, fd;
    unsigned int len = sizeof(client);

    uprintf("[ps4debug] server started");

    // server structure
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = SERVER_IN;
    server.sin_port = sceNetHtons(SERVER_PORT);
    memset(server.sin_zero, 0, sizeof(server.sin_zero));

    // start up server
    // todo: error checking
    serv = sceNetSocket("debugserver", AF_INET, SOCK_STREAM, 0);
    configure_socket(serv, 0);
    sceNetBind(serv, (struct sockaddr *)&server, sizeof(server));
    sceNetListen(serv, 4);

    while(1) {
        scePthreadYield();

        errno = NULL;
        fd = sceNetAccept(serv, (struct sockaddr *)&client, &len);
        if(fd > -1 && !errno) {
            uprintf("[ps4debug] accepted a new client");

            configure_socket(fd, 1);
            handle_client(fd, &client);
        }

        sceKernelSleep(1);
    }
}
