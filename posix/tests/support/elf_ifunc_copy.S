/* A fixed root requests COPY of data whose provider still needs IFUNC work. */
.text
.globl _start
.type _start,@function
_start:
#ifdef GNU_REFERENCE
    mov root_slot(%rip),%rax
    cmp public_slot(%rip),%rax
    jne 2f
    call *%rax
    cmp $73,%eax
    jne 2f
    xor %edi,%edi
    jmp 3f
2:  mov $1,%edi
3:  mov $60,%eax
    syscall
#else
    mov public_slot(%rip),%rax
    ret
#endif
.size _start,.-_start
.type root_pick,@gnu_indirect_function
root_pick:
    sub $8,%rsp
    call *public_slot(%rip)
    add $8,%rsp
    cmp $73,%eax
    jne 1f
    mov public_slot(%rip),%rax
    ret
1:  xor %eax,%eax
    ret
.size root_pick,.-root_pick
#ifdef CRT_CONTRACT
.globl __mochios_indirect_v1
.type __mochios_indirect_v1,@function
__mochios_indirect_v1:
    mov $1,%eax
    ret
.size __mochios_indirect_v1,.-__mochios_indirect_v1
#ifdef COPY_CONTRACT
.globl __mochios_indirect_v2
.type __mochios_indirect_v2,@function
__mochios_indirect_v2:
    mov $2,%eax
    ret
.size __mochios_indirect_v2,.-__mochios_indirect_v2
#endif
#endif
.data
.globl root_slot
.type root_slot,@object
root_slot: .quad root_pick
.size root_slot,8
.section .note.GNU-stack,"",@progbits
