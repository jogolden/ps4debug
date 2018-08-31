// golden
// 6/12/2018
//

#include "syscall.h"
#include "installer.h"

int _main(void) {
    return syscall(11, runinstaller);
}
