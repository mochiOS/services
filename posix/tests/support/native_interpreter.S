/* Test-only interpreter, not a dynamic linker. It validates the initial handoff
 * and marks a documented fixture entry before entering the existing CRT. */
.text
.global _start
.hidden __ehdr_start
_start:
    mov %rsp, %r12
    mov (%rsp), %rcx
    cmp $256, %rcx
    ja .Lbad
    lea 16(%rsp,%rcx,8), %rsi
    mov $257, %ecx
.Lenv:
    dec %ecx
    jz .Lbad
    lodsq
    test %rax, %rax
    jnz .Lenv
    xor %r8d, %r8d
    xor %r9d, %r9d
    xor %r10d, %r10d
    xor %r11d, %r11d
    xor %ebx, %ebx
    mov $512, %ecx
.Laux:
    dec %ecx
    jz .Lbad
    lodsq
    mov %rax, %rdx
    lodsq
    test %rdx, %rdx
    jz .Lcheck
    cmp $9, %rdx
    cmove %rax, %r8
    cmp $7, %rdx
    cmove %rax, %r9
    cmp $3, %rdx
    cmove %rax, %r10
    cmp $5, %rdx
    cmove %rax, %r11
    cmp $4, %rdx
    cmove %rax, %rbx
    jmp .Laux
.Lcheck:
    lea __ehdr_start(%rip), %rax
    cmp %rax, %r9
    jne .Lbad
    cmp $56, %rbx
    jne .Lbad
    test %r8, %r8
    jz .Lbad
    test %r10, %r10
    jz .Lbad
    test %r11, %r11
    jz .Lbad
    cmp $65535, %r11
    jae .Lbad
    xor %ecx, %ecx
.Lheaders:
    cmpl $3, (%r10)
    jne .Lnext
    inc %ecx
.Lnext:
    add $56, %r10
    dec %r11
    jnz .Lheaders
    cmp $1, %ecx
    jne .Lbad
    /* The fixed root fixture puts its flag address at entry + 8. */
    mov 8(%r8), %rax
    movl $1, (%rax)
    mov %r12, %rsp
    xor %ebp, %ebp
    xor %edx, %edx
    jmp *%r8
.Lbad:
    ud2
.section .note.GNU-stack,"",@progbits
