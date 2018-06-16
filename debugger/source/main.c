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
	
	start_debug();
	start_server();
    
	return 0;
}