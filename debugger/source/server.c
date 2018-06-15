// golden
// 6/12/2018
//

#include "server.h"

struct sockaddr_in server;
int servsock;

int run_server;

void client_thread(void *arg) {
    int clsock = (void *)arg;

    while(run_server) {


        sceKernelUsleep(10000);
    }
}

void server_thread(void) {
    while(run_server) {
        int clsock = sceNetAccept(servsock, NULL, NULL);

        ScePthread thread;
        scePthreadCreate(&thread, NULL, client_thread, (void *)clsock, "dbgclient");

        sceKernelUsleep(40000);
    }
}

void start_server() {
    // server structure
	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = SERVER_IN;
	server.sin_port = sceNetHtons(SERVER_PORT);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));

    // start up server
	servsock = sceNetSocket("dbgsock", AF_INET, SOCK_STREAM, 0);

	sceNetBind(servsock, (struct sockaddr *)&server, sizeof(server));

	sceNetListen(servsock, 16);

    run_server = 1;

    ScePthread servthr;
    scePthreadCreate(&servthr, NULL, server_thread, NULL, "dbgserver");
}

void stop_server() {
    run_server = 0;
    sceNetSocketClose(servsock);
}
