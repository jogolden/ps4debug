.section .rodata

    .global kernelelf
    .type   kernelelf, @object
    .align  4
kernelelf:
    .incbin "../kdebugger/kdebugger.elf"
kernelelfend:
    .global kernelelf_size
    .type   kernelelf_size, @object
    .align  4
kernelelf_size:
    .int    kernelelfend - kernelelf
    
    .global debuggerbin
    .type   debuggerbin, @object
    .align  4
debuggerbin:
    .incbin "../debugger/debugger.bin"
debuggerbinend:
    .global debuggerbin_size
    .type   debuggerbin_size, @object
    .align  4
debuggerbin_size:
    .int    debuggerbinend - debuggerbin
