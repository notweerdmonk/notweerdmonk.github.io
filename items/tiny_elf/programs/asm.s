.global _start
.text

_start:
movl $4, %eax
xorl %ebx, %ebx
movl $msg, %ecx
movl $len, %edx
int $0x80

movl $1, %eax
xorl %ebx, %ebx
int $0x80

.data
msg:
.asciz "hello, world\n"
.equ len, . - msg
