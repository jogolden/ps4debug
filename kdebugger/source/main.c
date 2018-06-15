// golden
// 6/12/2018
//

#include <ksdk.h>
#include "hooks.h"
#include "installer.h"

void jailbreak() {
	struct ucred* cred;
	struct filedesc* fd;
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
	*(uint8_t *)(kernbase + 0x7673E0) = 0xC3;

	// patch vm_map_protect check
	memcpy((void *)(kernbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace, thanks 2much4u
    *(uint8_t *)(kernbase + 0x30D9AA) = 0xEB;

	// patch ASLR, thanks 2much4u
	*(uint16_t *)(kernbase + 0x194875) = 0x9090;

    cpu_enable_wp();
}

void _main(void) {
    init_ksdk();

    jailbreak();
    kpatches();

    cpu_disable_wp();
    *disable_console_output = 0;
    cpu_enable_wp();

	printf("[ps4debug] kdebugger loaded\n");

    install_hooks();
    install_debugger();

    printf("[ps4debug] hooks and debugger installed\n");
}
