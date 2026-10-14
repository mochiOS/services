.text
.globl mochios_test_signal_checkpoint
.type mochios_test_signal_checkpoint,@function
mochios_test_signal_checkpoint:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    fxsave64 [rsp]
    fninit
    fld1
    mov dword ptr [rsp + 512], 0x1f80
    ldmxcsr [rsp + 512]
    movdqu xmm0, [rip + .Lcheckpoint_xmm_seed]
    mov r8, 0x1000
    mov r9, 0x1001
    mov r10, 0x1002
    mov r11, 0x1003
    mov r12, 0x1004
    mov r13, 0x1005
    mov r14, 0x1006
    mov r15, 0x1007
    mov rbp, 0x100a
    mov rbx, 0x100b
    mov rdx, 0x100c
    mov rcx, 0x100e
    stc
    call mochios_posix_signal_checkpoint
.Lcheckpoint_probe_resume:
    // RSI is the preserved opaque pointer. Record the actual restored CPU
    // before using arithmetic or scratch registers which would overwrite it.
    mov [rsi + 656 + 0], r8
    mov [rsi + 656 + 8], r9
    mov [rsi + 656 + 16], r10
    mov [rsi + 656 + 24], r11
    mov [rsi + 656 + 32], r12
    mov [rsi + 656 + 40], r13
    mov [rsi + 656 + 48], r14
    mov [rsi + 656 + 56], r15
    mov [rsi + 656 + 64], rdi
    mov [rsi + 656 + 72], rsi
    mov [rsi + 656 + 80], rbp
    mov [rsi + 656 + 88], rbx
    mov [rsi + 656 + 96], rdx
    mov [rsi + 656 + 104], rax
    mov [rsi + 656 + 112], rcx
    mov [rsi + 656 + 120], rsp
    lea rax, [rip + .Lcheckpoint_probe_resume]
    mov [rsi + 656 + 128], rax
    pushfq
    pop qword ptr [rsi + 656 + 136]
    fxsave64 [rsi + 656 + 144]
    // Do not leak the probe's deliberately edited callee-saved state into
    // the Rust harness or another test running on this host thread.
    fxrstor64 [rsp]
    mov rax, [rsi + 656 + 104]
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.size mochios_test_signal_checkpoint, .-mochios_test_signal_checkpoint
.globl mochios_test_signal_checkpoint_alternate
.type mochios_test_signal_checkpoint_alternate,@function
mochios_test_signal_checkpoint_alternate:
    mov [rsi + 1328], rsp
    mov qword ptr [rsi + 1320], 1
    lea rsp, [rsp + 16]
    jmp .Lcheckpoint_probe_resume
.size mochios_test_signal_checkpoint_alternate, .-mochios_test_signal_checkpoint_alternate
.section .rodata
.balign 16
.Lcheckpoint_xmm_seed:
    .quad 0x1111111111111111, 0x1111111111111111
.section .note.GNU-stack,"",@progbits
