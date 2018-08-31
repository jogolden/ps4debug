.intel_syntax noprefix

.extern __error

.text

.globl syscall
syscall:
    xor rax, rax

.globl syscall_macro
syscall_macro:
    mov r10, rcx
    syscall
    ret
