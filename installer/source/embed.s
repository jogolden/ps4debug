.section .rodata
	.global bkdbg
	.type   bkdbg, @object
	.align  4
bkdbg:
	.incbin "../kdebugger/kdebugger.elf"
bkdbge:
	.global cbkdbg
	.type   cbkdbg, @object
	.align  4
cbkdbg:
	.int    bkdbge - bkdbg
	