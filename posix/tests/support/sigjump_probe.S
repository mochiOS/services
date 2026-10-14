.text
.global sigjump_probe
.type sigjump_probe,@function
sigjump_probe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 136
    mov [rsp + 120], rdi
    mov ebx, 0x1133
    mov ebp, 0x2244
    mov r12d, 0x3355
    mov r13d, 0x4466
    mov r14d, 0x5577
    mov r15d, 0x6688
    mov rdi, rsp
    mov esi, 37
    call sigsetjmp
    test eax, eax
    jne 1f
    mov ebx, 0xbad
    mov ebp, 0xbad
    mov r12d, 0xbad
    mov r13d, 0xbad
    mov r14d, 0xbad
    mov r15d, 0xbad
    mov rdi, rsp
    mov esi, 37
    mov rdx, [rsp + 120]
    mov ecx, 3
    call __mochios_sigjump_restore
1:
    cmp eax, 37
    jne 2f
    cmp rbx, 0x1133
    jne 2f
    cmp rbp, 0x2244
    jne 2f
    cmp r12, 0x3355
    jne 2f
    cmp r13, 0x4466
    jne 2f
    cmp r14, 0x5577
    jne 2f
    cmp r15, 0x6688
    jne 2f
    jmp 3f
2:
    mov eax, -1
3:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size sigjump_probe, .-sigjump_probe
.section .note.GNU-stack,"",@progbits
