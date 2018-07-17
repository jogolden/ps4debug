// golden
// 6/12/2018
//

#include <ps4.h>
#include "ptrace.h"
#include "server.h"
#include "debug.h"

int _main(void) {
	initKernel();
	initLibc();
	initPthread();
	initNetwork();
	initSysUtil();

	// just a little notify
	sceSysUtilSendSystemNotificationWithText(222, "ps4debug loaded!");
	sceSysUtilSendSystemNotificationWithText(222, "golden <3");

	// jailbreak current thread
	sys_console_cmd(SYS_CONSOLE_CMD_JAILBREAK, NULL);

	// start the server, this will block
	start_server();

	return 0;
}