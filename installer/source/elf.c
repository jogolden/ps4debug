// golden
// 6/12/2018
//

#include "elf.h"

int elf_mapped_size(void *elf, uint64_t *msize) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    // check magic
    if (memcmp(ehdr->e_ident, ElfMagic, 4)) {
        return LDR_INVALID_ELF;
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

    return LDR_SUCCESS;
}

int map_elf(void *elf, void *exec) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    struct Elf64_Phdr *phdr = elf_pheader(ehdr);
    if (phdr) {
        // use segments
        for (int i = 0; i < ehdr->e_phnum; i++) {
            struct Elf64_Phdr *phdr = elf_segment(ehdr, i);

            if (phdr->p_filesz) {
                memcpy((uint8_t *)exec + phdr->p_paddr, (uint8_t *)elf + phdr->p_offset, phdr->p_filesz);
            }

            if (phdr->p_memsz - phdr->p_filesz) {
                memset((uint8_t *)exec + phdr->p_paddr + phdr->p_filesz, NULL, phdr->p_memsz - phdr->p_filesz);
            }
        }
    } else {
        // use sections
        for (int i = 0; i < ehdr->e_shnum; i++) {
            struct Elf64_Shdr *shdr = elf_section(ehdr, i);

            if (!(shdr->sh_flags & SHF_ALLOC)) {
                continue;
            }

            if (shdr->sh_size) {
                memcpy((uint8_t *)exec + shdr->sh_addr, (uint8_t *)elf + shdr->sh_offset, shdr->sh_size);
            }
        }
    }

    return LDR_SUCCESS;
}

int relocate_elf(void *elf, void *exec) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        struct Elf64_Shdr *shdr = elf_section(ehdr, i);

        // check table
        if (shdr->sh_type == SHT_REL) {
            // process each entry in the table
            for (int j = 0; j < shdr->sh_size / shdr->sh_entsize; j++) {
                struct Elf64_Rela *reltab = &((struct Elf64_Rela *)((uint64_t)ehdr + shdr->sh_offset))[j];
                uint8_t **ref = (uint8_t **)((uint8_t *)exec + reltab->r_offset);

                switch (ELF64_R_TYPE(reltab->r_info)) {
                case R_X86_64_RELATIVE:
                    *ref = (uint8_t *)exec + reltab->r_addend;
                    break;
                case R_X86_64_64:
                case R_X86_64_JUMP_SLOT:
                case R_X86_64_GLOB_DAT:
                    // not supported
                    break;
                }
            }
        }
    }

    return LDR_SUCCESS;
}

int load_elf(void *elf, uint64_t size, void *exec, uint64_t msize, void **entry) {
    // check arguments
    if (!elf || !exec || !size || !msize) {
        return LDR_INVALID_ELF;
    }

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    // check magic
    if (memcmp(ehdr->e_ident, ElfMagic, 4)) {
        return LDR_INVALID_ELF;
    }

    // only support relocatable elfs rn lol
    if (ehdr->e_type != ET_REL && ehdr->e_type != ET_DYN) {
        return LDR_INVALID_ELF;
    }

    uint64_t s = 0;
    if (elf_mapped_size(elf, &s)) {
        return LDR_SIZE_ERROR;
    }

    if (s > msize) {
        return LDR_SIZE_ERROR;
    }

    if (map_elf(elf, exec)) {
        return LDR_MAP_ERROR;
    }

    if (relocate_elf(elf, exec)) {
        return LDR_RELOC_ERROR;
    }

    if (entry) {
        *entry = (void *)((uint64_t)exec + ehdr->e_entry);
    }

    return LDR_SUCCESS;
}
