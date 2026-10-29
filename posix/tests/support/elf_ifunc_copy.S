/* A fixed root requests COPY of data whose provider still needs IFUNC work. */
.text
.globl _start
.type _start,@function
_start:
    mov public_slot(%rip),%rax
    ret
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
