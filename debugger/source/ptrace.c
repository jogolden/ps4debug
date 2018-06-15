// golden
// 6/12/2018
//

#include "ptrace.h"

int ptrace(int req, int pid, void *addr, int data) {
    return syscall(11, req, pid, addr, data);
}
