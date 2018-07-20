// golden
// 6/12/2018
//

#include <ksdk.h>
#include "hooks.h"
#include "installer.h"

void kpatches() {
	cpu_disable_wp();

	uint64_t kernbase = get_kbase();

	// patch memcpy first
	*(uint8_t *)(kernbase + 0x1EA53D) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void *)(kernbase + 0x11730), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void *)(kernbase + 0x117B0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void *)(kernbase + 0x117C0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t *)(kernbase + 0x7673E0) = 0xC3;

	// self patches
	memcpy((void *)(kernbase + 0x13F03F), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void *)(kernbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t *)(kernbase + 0x30D9AA) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void *)(kernbase + 0x30DE01), "\xE9\xD0\x00\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t *)(kernbase + 0x194875) = 0x9090;

	cpu_enable_wp();
}

int _main(void) {
	init_ksdk();

	kpatches();

	*disable_console_output = NULL;

	printf("[ps4debug] kernel base 0x%llX\n", get_kbase());

	if(install_hooks()) {
		printf("[ps4debug] failed to install hooks\n");
		return 1;
	}
	
	if(install_debugger()) {
		printf("[ps4debug] failed to install debugger\n");
		return 1;
	}

	printf("[ps4debug] kdebugger hooks and debugger loaded\n");

	return 0;
}
