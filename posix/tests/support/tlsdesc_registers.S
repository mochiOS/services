/* Check the descriptor ABI while every non-RAX register is live. */
.text
.global run_tls_descriptor
.type run_tls_descriptor,@function
run_tls_descriptor:
  push rbx
  push rbp
  push r12
  push r13
  push r14
  push r15
  sub rsp, 24
  mov [rsp], rdi
  mov [rsp + 8], rsi
  mov rbx, 11
  mov rbp, 12
  mov rcx, 13
  mov rdx, 14
  mov rdi, 15
  mov rsi, 16
  mov r8, 17
  mov r9, 18
  mov r10, 19
  mov r11, 20
  mov r12, 21
  mov r13, 22
  mov r14, 23
  mov r15, 24
  .irp reg,xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15
    pcmpeqb \reg, \reg
  .endr
  mov rax, [rsp]
  call [rax]
  mov [rsp + 16], rax
  cmp rbx, 11
  jne 2f
  cmp rbp, 12
  jne 2f
  cmp rcx, 13
  jne 2f
  cmp rdx, 14
  jne 2f
  cmp rdi, 15
  jne 2f
  cmp rsi, 16
  jne 2f
  cmp r8, 17
  jne 2f
  cmp r9, 18
  jne 2f
  cmp r10, 19
  jne 2f
  cmp r11, 20
  jne 2f
  cmp r12, 21
  jne 2f
  cmp r13, 22
  jne 2f
  cmp r14, 23
  jne 2f
  cmp r15, 24
  jne 2f
  .irp reg,xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15
    pmovmskb eax, \reg
    cmp eax, 65535
    jne 2f
  .endr
  mov rdx, [rsp + 8]
  mov rax, [rsp + 16]
  mov [rdx], rax
  xor eax, eax
  jmp 3f
2:
  mov eax, 1
3:
  add rsp, 24
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rbx
  ret
.size run_tls_descriptor, .-run_tls_descriptor
