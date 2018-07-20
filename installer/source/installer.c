// golden
// 6/12/2018
//

#include "installer.h"

extern uint8_t bkdbg[];
extern int32_t cbkdbg;

void *allocate_rwx_memory(uint64_t size) {
	uint64_t alignedSize = (size + 0x3FFFull) & ~0x3FFFull;
	uint64_t kernbase = get_kbase();

	cpu_disable_wp();
	*(uint8_t *)(kernbase + __kmem_alloc_p1) = VM_PROT_ALL;
	*(uint8_t *)(kernbase + __kmem_alloc_p2) = VM_PROT_ALL;
	cpu_enable_wp();

	void *memory = (void *)kmem_alloc(*kernel_map, alignedSize);

	cpu_disable_wp();
	*(uint8_t *)(kernbase + __kmem_alloc_p1) = VM_PROT_DEFAULT;
	*(uint8_t *)(kernbase + __kmem_alloc_p2) = VM_PROT_DEFAULT;
	cpu_enable_wp();

	return memory;
}

int runinstaller() {
    init_ksdk();

    *disable_console_output = 0;

	printf("[ps4debug] loading kdebugger...\n");
    
	uint64_t mapsize = 0;
	if (elf_mapped_size(bkdbg, &mapsize)) {
		printf("[ps4debug] invalid kdebugger elf!\n");
		return 1;
	}

	void *payloadbase = allocate_rwx_memory(mapsize);

	if(!payloadbase) {
		printf("[ps4debug] could not allocate memory for kdebugger!\n");
		return 1;
	}

	// load the elf
	int (*payload_entry)(void *p);

	if (load_elf(bkdbg, cbkdbg, payloadbase, mapsize, (void **)&payload_entry)) {
		printf("[ps4debug] could not load kdebugger elf!\n");
		return 1;
	}

	// call entry
	if (payload_entry(NULL)) {
		return 1;
	}

    return 0;
}
