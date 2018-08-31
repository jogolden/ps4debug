OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

ENTRY(_start)

PHDRS
{
    headers PT_LOAD PHDRS;
    text PT_LOAD;
    data PT_LOAD;
    bss PT_LOAD;
}

SECTIONS
{
    . = SIZEOF_HEADERS;
    
    .text : {
        *(.text)
    } :text
    
    .rodata : {
        *(.rodata)
        *(.rodata.*)
    } :text
    
    .data : {
        *(.data)
        *(.got)
        *(.got.*)
    } :data
    
    .bss : {
        *(.bss)
        *(COMMON)
    } :bss
}
