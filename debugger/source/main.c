// golden
// 6/12/2018
//

#include <ps4.h>
#include "ptrace.h"
#include "server.h"

int _main(void) {
	initKernel();
	initLibc();
	initPthread();
	initNetwork();

	start_server();
    
	return 0;
}