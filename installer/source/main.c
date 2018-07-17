// golden
// 6/12/2018
//

#include "syscall.h"
#include "installer.h"

int _main(void) {
	syscall(11, runinstaller);
	return 0;
}
