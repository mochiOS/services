use mochi_user_platform::syscall::ThreadCreateContext;

#[test]
fn native_thread_context_has_stable_zero_extended_layout() {
    let context = ThreadCreateContext::default();

    assert_eq!(core::mem::size_of::<ThreadCreateContext>(), 64);
    assert_eq!(core::mem::align_of::<ThreadCreateContext>(), 8);
    assert_eq!(context.entry, 0);
    assert_eq!(context.stack_pointer, 0);
    assert_eq!(context.argument, 0);
    assert_eq!(context.thread_local_base, 0);
    assert_eq!(context.flags, 0);
    assert_eq!(context.reserved, [0; 3]);
}

#[test]
fn native_thread_context_keeps_runtime_tls_opaque() {
    let context = ThreadCreateContext {
        entry: 0x1000,
        stack_pointer: 0x8000,
        argument: 0x55,
        thread_local_base: 0x4000,
        flags: 0,
        reserved: [0; 3],
    };

    assert_eq!(context.thread_local_base, 0x4000);
}

#[test]
fn initial_thread_argument_cannot_alias_iret_frame_scratch_registers() {
    let source = include_str!("../../../core/src/task/usermode.rs");
    let initial_entry = source.split("/// GDTR").next().unwrap();
    assert!(initial_entry.contains("in(\"rdi\") user_arg0"));
    assert!(!initial_entry.contains("arg0 = in(reg)"));
}
