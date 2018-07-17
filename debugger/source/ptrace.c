// golden
// 6/12/2018
//

#include "ptrace.h"

int ptrace(int req, int pid, void *addr, int data) {
	int r;

<<<<<<< HEAD
	errno = NULL;
=======
    errno = NULL;

    errno = NULL;

    r = syscall(26, req, pid, addr, data);
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7

	r = syscall(26, req, pid, addr, data);

	uprintf
	    ("ptrace(req %i, pid %i, addr 0x%llX, data 0x%X) = %i (errno %i)",
	    req, pid, addr, data, r, errno);

	return r;
}

int wait4(int wpid, int *status, int options, void *rusage) {
	return syscall(7, wpid, status, options, rusage);
}
