.section .rodata
	.global bdbg
	.type   bdbg, @object
	.align  4
bdbg:
	.incbin "../debugger/debugger.bin"
bdbge:
	.global cbdbg
	.type   cbdbg, @object
	.align  4
cbdbg:
	.int    bdbge - bdbg
	