#![cfg(target_arch = "x86_64")]

use mnu_abi::ThreadCreateContext;
use mochios_posix_client::snapshot::capture_with;

core::arch::global_asm!(
    r#"
    .text
    .globl snapshot_mock_child
    .type snapshot_mock_child,@function
snapshot_mock_child:
    // Simulate restoring the recorded stack and instruction pointer while the
    // caller frame is still live. No Rust frame or destructor is skipped.
    mov rax, [rdi]
    mov rsp, [rdi + 8]
    jmp rax
    .size snapshot_mock_child, .-snapshot_mock_child

    .globl snapshot_seeded_call
    .type snapshot_seeded_call,@function
snapshot_seeded_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rbx, 0x1234567812345678
    mov rbp, 0x2234567822345678
    mov r12, 0x3234567832345678
    mov r13, 0x4234567842345678
    mov r14, 0x5234567852345678
    mov r15, 0x6234567862345678
    mov rcx, 0x7234567872345678
    mov r8, 0x8234567882345678
    mov r9, 0x9234567892345678
    mov r10, 0xa2345678a2345678
    mov r11, 0xb2345678b2345678
    call mochios_posix_capture_snapshot
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size snapshot_seeded_call, .-snapshot_seeded_call
    "#
);

unsafe extern "C" {
    fn snapshot_mock_child() -> u64;
    fn snapshot_seeded_call(
        context: *mut ThreadCreateContext,
        tls: u64,
        capture: unsafe extern "C" fn() -> u64,
    ) -> u64;
}

unsafe extern "C" fn parent_handle() -> u64 {
    41
}

unsafe extern "C" fn parent_error() -> u64 {
    (-12i64) as u64
}

#[test]
fn parent_preserves_backend_handle_and_child_return_value_is_in_context() {
    let mut context = ThreadCreateContext::default();
    assert_eq!(
        unsafe { capture_with(&mut context, 0x1234000, parent_handle) },
        41
    );
    assert_ne!(context.entry, 0);
    assert_ne!(context.stack_pointer, 0);
    assert_eq!(context.stack_pointer % 16, 8);
    assert_eq!(context.argument, core::ptr::addr_of!(context) as u64);
    assert_eq!(context.thread_local_base, 0x1234000);
    assert_eq!(context.flags, 0);
    assert_eq!(context.reserved, [0; 3]);
    assert_eq!(context.registers.rax, 0);
}

#[test]
fn parent_native_error_is_not_confused_with_child_zero() {
    let mut context = ThreadCreateContext::default();
    assert_eq!(
        unsafe { capture_with(&mut context, 0, parent_error) },
        (-12i64) as u64
    );
}

#[test]
fn recorded_child_continuation_really_returns_zero_to_call_site() {
    let mut context = ThreadCreateContext::default();
    assert_eq!(
        unsafe { capture_with(&mut context, 0, snapshot_mock_child) },
        0
    );
    assert_ne!(context.entry, 0);
}

#[test]
fn callee_saved_registers_are_captured_in_both_return_paths() {
    for backend in [parent_handle, snapshot_mock_child] {
        let mut context = ThreadCreateContext::default();
        let result = unsafe { snapshot_seeded_call(&mut context, 0x8888000, backend) };
        assert!(result == 0 || result == 41);
        assert_eq!(context.registers.rbx, 0x1234567812345678);
        assert_eq!(context.registers.rbp, 0x2234567822345678);
        assert_eq!(context.registers.r12, 0x3234567832345678);
        assert_eq!(context.registers.r13, 0x4234567842345678);
        assert_eq!(context.registers.r14, 0x5234567852345678);
        assert_eq!(context.registers.r15, 0x6234567862345678);
        assert_eq!(context.registers.rcx, 0x7234567872345678);
        assert_eq!(context.registers.r8, 0x8234567882345678);
        assert_eq!(context.registers.r9, 0x9234567892345678);
        assert_eq!(context.registers.r10, 0xa2345678a2345678);
        assert_eq!(context.registers.r11, 0xb2345678b2345678);
        assert_eq!(context.registers.rdx, backend as usize as u64);
        assert_eq!(context.registers.rsi, 0x8888000);
        assert_eq!(context.thread_local_base, 0x8888000);
    }
}

#[test]
fn assembly_offsets_match_the_actual_native_context_layout() {
    assert_eq!(core::mem::size_of::<ThreadCreateContext>(), 176);
    assert_eq!(core::mem::offset_of!(ThreadCreateContext, registers), 64);
    assert_eq!(
        core::mem::offset_of!(mnu_abi::ThreadInitialRegisters, rbx),
        8
    );
    assert_eq!(
        core::mem::offset_of!(mnu_abi::ThreadInitialRegisters, rbp),
        40
    );
    assert_eq!(
        core::mem::offset_of!(mnu_abi::ThreadInitialRegisters, r15),
        104
    );
}
