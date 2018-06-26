// golden
// 6/12/2018
//

#include "installer.h"

extern uint8_t bkdbg[];
extern int32_t cbkdbg;

int runinstaller() {
    init_ksdk();
    uint64_t kernbase = get_kbase();

    cpu_disable_wp();
    *disable_console_output = 0;
    cpu_enable_wp();

	printf("[ps4debug] installer loaded\n");
	printf("[ps4debug] loading kdebugger...\n");
    
	uint64_t msize = 0;
	if (elf_mapped_size(bkdbg, &msize)) {
		printf("[ps4debug] invalid kdebugger elf!\n");
		return 1;
	}

	int s = (msize + 0x3FFFull) & ~0x3FFFull;

	cpu_disable_wp();
	*(uint8_t *)(kernbase + __kmem_alloc_p1) = VM_PROT_ALL;
	*(uint8_t *)(kernbase + __kmem_alloc_p2) = VM_PROT_ALL;
	cpu_enable_wp();

	void *payloadbase = (void *)kmem_alloc(*kernel_map, s);

	cpu_disable_wp();
	*(uint8_t *)(kernbase + __kmem_alloc_p1) = VM_PROT_DEFAULT;
	*(uint8_t *)(kernbase + __kmem_alloc_p2) = VM_PROT_DEFAULT;
	cpu_enable_wp();

	if(!payloadbase) {
		printf("[ps4debug] could not allocate memory for kdebugger!\n");
		return 1;
	}

	// load the elf
	int r = 0;
	int (*payload_entry)(void *p);

	if ((r = load_elf(bkdbg, cbkdbg, payloadbase, msize, (void **)&payload_entry))) {
		printf("[ps4debug] could not load kdebugger elf!\n");
		return 1;
	}

	// call entry
	if (payload_entry(NULL)) {
		return 1;
	}

    return 0;
}
