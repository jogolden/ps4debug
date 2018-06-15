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
    
	uint64_t msize = 0;
	if (elf_mapped_size(bkdbg, &msize)) {
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

	// load the elf
	int r = 0;
	int (*payload_entry)(void *p);

	if ((r = load_elf(bkdbg, cbkdbg, payloadbase, msize, (void **)&payload_entry))) {
		return 1;
	}

	// call entry
	if (payload_entry(NULL)) {
		return 1;
	}

    return 0;
}
