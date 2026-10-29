.section .text.interpreter_root_entry,"ax",@progbits
.balign 8
.global interpreter_root_entry
interpreter_root_entry:
    jmp _start
    .balign 8
    .quad interpreted_started
.section .interp,"a",@progbits
    .asciz "/system/libraries/interpreter-probe/ld.native.so"
.section .note.GNU-stack,"",@progbits
