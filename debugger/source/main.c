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

    // sleep a few seconds
    // maybe lower our thread priority?
    sceKernelSleep(2);

    // just a little notify
    sceSysUtilSendSystemNotificationWithText(222, "ps4debug by golden");
    
    // jailbreak current thread
    sys_console_cmd(SYS_CONSOLE_CMD_JAILBREAK, NULL);

    // updates
    mkdir("/update/PS4UPDATE.PUP", 0777);
    mkdir("/update/PS4UPDATE.PUP.net.temp", 0777);

    // start the server, this will block
    start_server();

    return 0;
}