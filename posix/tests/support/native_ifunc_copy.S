/* A real COPY followed by a root IRELATIVE which reads the copied pointer. */
.text
.globl native_copy_direct
.type native_copy_direct,@function
native_copy_direct:
    jmp *native_copied_pointer(%rip)
.size native_copy_direct,.-native_copy_direct
.type native_copy_pick,@gnu_indirect_function
native_copy_pick:
    sub $8,%rsp
    call native_copy_direct
    add $8,%rsp
    cmp $73,%eax
    jne 1f
    mov native_copied_pointer(%rip),%rax
    ret
1:  xor %eax,%eax
    ret
.size native_copy_pick,.-native_copy_pick
.globl native_copy_selected
.type native_copy_selected,@function
native_copy_selected:
    jmp *native_copy_slot(%rip)
.size native_copy_selected,.-native_copy_selected
.data
.type native_copy_slot,@object
native_copy_slot: .quad native_copy_pick
.size native_copy_slot,8
.section .note.GNU-stack,"",@progbits
