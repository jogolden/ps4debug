// golden
// 6/12/2018
//

#include "ptrace.h"

int ptrace(int req, int pid, void *addr, int data) {
    return syscall(26, req, pid, addr, data);
}

int wait4(int wpid, int *status, int options, void *rusage) {
    return syscall(7, wpid, status, options, rusage);
}
