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
	
	// this blocks
	start_server();

	return 0;
}