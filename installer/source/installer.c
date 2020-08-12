// golden
// 6/12/2018
//

#include "installer.h"

extern uint8_t kernelelf[];
extern int32_t kernelelf_size;

extern uint8_t debuggerbin[];
extern int32_t debuggerbin_size;

void ascii_art() {
    printf("\n\n");
    printf("                _____     .___    ___.                 \n");
    printf("______  ______ /  |  |  __| _/____\\_ |__  __ __  ____  \n");
    printf("\\____ \\/  ___//   |  |_/ __ |/ __ \\| __ \\|  |  \\/ ___\\ \n");
    printf("|  |_> >___ \\/    ^   / /_/ \\  ___/| \\_\\ \\  |  / /_/  >\n");
    printf("|   __/____  >____   |\\____ |\\___  >___  /____/\\___  / \n");
    printf("|__|       \\/     |__|     \\/    \\/    \\/     /_____/  \n");
    printf("                                                       \n");
}

void patch_kernel() {
    cpu_disable_wp();

    uint64_t kernbase = get_kbase();

    // patch memcpy first
    *(uint8_t *)(kernbase + 0x003C15BD) = 0xEB;

    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void *)(kernbase + 0x00233BD0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrHasMmapSelfCapability
    memcpy((void *)(kernbase + 0x00233C40), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void *)(kernbase + 0x00233C50), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t *)(kernbase + 0x00784120) = 0xC3;

    // self patches
    memcpy((void *)(kernbase + 0x000AD2E4), "\x31\xC0\x90\x90\x90", 5);

    // patch vm_map_protect check
    memcpy((void *)(kernbase + 0x00451DB8), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace
    *(uint8_t *)(kernbase + 0x0010F879) = 0xEB;
    memcpy((void *)(kernbase + 0x10FD22), "\xE9\xE2\x02\x00\x00", 5);

	// disable ASLR
    *(uint8_t *)(kernbase + 0x003CECE1) = 0xEB;

    // patch kmem_alloc
    *(uint8_t *)(kernbase + 0x002507F5) = VM_PROT_ALL;
    *(uint8_t *)(kernbase + 0x00250803) = VM_PROT_ALL;

    cpu_enable_wp();
}

void *rwx_alloc(uint64_t size) {
    uint64_t alignedSize = (size + 0x3FFFull) & ~0x3FFFull;
    return (void *)kmem_alloc(*kernel_map, alignedSize);
}

int load_kdebugger() {
    uint64_t mapsize;
    void *kmemory;
    int (*payload_entry)(void *p);

    // calculate mapped size
    if (elf_mapped_size(kernelelf, &mapsize)) {
        printf("[ps4debug] invalid kdebugger elf!\n");
        return 1;
    }
    
    // allocate memory
    kmemory = rwx_alloc(mapsize);
    if(!kmemory) {
        printf("[ps4debug] could not allocate memory for kdebugger!\n");
        return 1;
    }

    // load the elf
    if (load_elf(kernelelf, kernelelf_size, kmemory, mapsize, (void **)&payload_entry)) {
        printf("[ps4debug] could not load kdebugger elf!\n");
        return 1;
    }

    // call entry
    if (payload_entry(NULL)) {
        return 1;
    }

    return 0;
}

int load_debugger() {
    struct proc *p;
    struct vmspace *vm;
    struct vm_map *map;
    int r;

    p = proc_find_by_name("SceShellCore");
    if(!p) {
        printf("[ps4debug] could not find SceShellCore process!\n");
        return 1;
    }

    vm = p->p_vmspace;
    map = &vm->vm_map;

    // allocate some memory
    vm_map_lock(map);
    r = vm_map_insert(map, NULL, NULL, PAYLOAD_BASE, PAYLOAD_BASE + 0x400000, VM_PROT_ALL, VM_PROT_ALL, 0);
    vm_map_unlock(map);
    if(r) {
        printf("[ps4debug] failed to allocate payload memory!\n");
        return r;
    }

    // write the payload
    r = proc_write_mem(p, (void *)PAYLOAD_BASE, debuggerbin_size, debuggerbin, NULL);
    if(r) {
        printf("[ps4debug] failed to write payload!\n");
        return r;
    }

    // create a thread
    r = proc_create_thread(p, PAYLOAD_BASE);
    if(r) {
        printf("[ps4debug] failed to create payload thread!\n");
        return r;
    }

    return 0;
}

int runinstaller() {
    init_ksdk();

    //// enable uart
    *disable_console_output = 0;

    ascii_art();

    // patch the kernel
    printf("[ps4debug] patching kernel...\n");
    patch_kernel();

    printf("[ps4debug] loading kdebugger...\n");

    if(load_kdebugger()) {
        return 1;
    }

    printf("[ps4debug] loading debugger...\n");

    if(load_debugger()) {
        return 1;
    }

    printf("[ps4debug] ps4debug created by golden\n");
    
    return 0;
}
