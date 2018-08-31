// golden
// 6/12/2018
//

#include "elf.h"

int elf_mapped_size(void *elf, uint64_t *msize) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    // check magic
    if (memcmp(ehdr->e_ident, ElfMagic, 4)) {
        return 1;
    }

    uint64_t s = 0;

    struct Elf64_Phdr *phdr = elf_pheader(ehdr);
    if (phdr) {
        // use segments
        for (int i = 0; i < ehdr->e_phnum; i++) {
            struct Elf64_Phdr *phdr = elf_segment(ehdr, i);

            uint64_t delta = phdr->p_paddr + phdr->p_memsz;
            if (delta > s) {
                s = delta;
            }
        }
    } else {
        // use sections
        for (int i = 0; i < ehdr->e_shnum; i++) {
            struct Elf64_Shdr *shdr = elf_section(ehdr, i);

            uint64_t delta = shdr->sh_addr + shdr->sh_size;
            if (delta > s) {
                s = delta;
            }
        }
    }

    if (msize) {
        *msize = s;
    }

    return 0;
}