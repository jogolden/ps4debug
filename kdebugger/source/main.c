// golden
// 6/12/2018
//

#include <ksdk.h>
#include "hooks.h"
#include "installer.h"

void jailbreak() {
	struct ucred *cred;
	struct filedesc *fd;
	struct thread *td;

	td = curthread();
	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *prison0;
	fd->fd_rdir = fd->fd_jdir = *rootvnode;
}

void kpatches() {
	cpu_disable_wp();

	uint64_t kernbase = get_kbase();

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t *) (kernbase + 0x7673E0) = 0xC3;

	// patch vm_map_protect check
	memcpy((void *)(kernbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t *) (kernbase + 0x30D9AA) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void *)(kernbase + 0x30DE01), "\xE9\xD0\x00\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t *) (kernbase + 0x194875) = 0x9090;

	// remove suspicious unmount message
	memcpy((void *)(kernbase + 0x1E028D), "\xEB\x4A", 2);

	// remove suspicious unmount message
	memcpy((void *)(kernbase + 0x1E028D), "\xEB\x4A", 2);

	// remove suspicious unmount message
	memcpy((void *)(kernbase + 0x1E028D), "\xEB\x4A", 2);

	cpu_enable_wp();
}

void _main(void) {
	init_ksdk();

	jailbreak();
	kpatches();

	*disable_console_output = 0;

	printf("[ps4debug] kdebugger loaded\n");
	printf("[ps4debug] kernel base 0x%llX\n", get_kbase());

	if(install_hooks()) {
		printf("[ps4debug] failed to install hooks\n");
		return;
	}
<<<<<<< HEAD
<<<<<<< HEAD

=======
	
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
=======
	
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
	if(install_debugger()) {
		printf("[ps4debug] failed to install debugger\n");
		return;
	}

	printf("[ps4debug] hooks and debugger installed\n");
}
