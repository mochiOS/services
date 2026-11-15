use mnu_abi::ThreadCreateContext;

#[test]
fn native_thread_context_has_stable_zero_extended_layout() {
    let context = ThreadCreateContext::default();

    assert_eq!(core::mem::size_of::<ThreadCreateContext>(), 176);
    assert_eq!(core::mem::align_of::<ThreadCreateContext>(), 8);
    assert_eq!(context.entry, 0);
    assert_eq!(context.stack_pointer, 0);
    assert_eq!(context.argument, 0);
    assert_eq!(context.thread_local_base, 0);
    assert_eq!(context.flags, 0);
    assert_eq!(context.reserved, [0; 3]);
    assert_eq!(
        context.registers,
        mnu_abi::ThreadInitialRegisters::default()
    );
    assert_eq!(core::mem::offset_of!(ThreadCreateContext, registers), 64);
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
        registers: mnu_abi::ThreadInitialRegisters::default(),
    };

    assert_eq!(context.thread_local_base, 0x4000);
}

#[test]
fn initial_thread_argument_cannot_alias_iret_frame_scratch_registers() {
    let source = include_str!("../../../core/src/arch/x86_64/task_usermode.rs");
    let initial_entry = source.split("/// GDTR").next().unwrap();
    assert!(initial_entry.contains("in(\"rdi\") user_arg0"));
    assert!(!initial_entry.contains("arg0 = in(reg)"));
}

#[test]
fn explicit_initial_registers_are_independent_of_privileged_flags() {
    let source = include_str!("../../../core/src/syscall/task.rs");
    let create = source.split("pub fn thread_create(").nth(1).unwrap();
    assert!(create.contains("context.flags != 0"));
    assert!(create.contains("context.reserved != [0; 3]"));
    assert!(create.contains("crate::arch::thread::initial_context(&context)"));
    assert!(create.contains("        result,\n        context.thread_local_base,"));
    let conversion = include_str!("../../../core/src/arch/x86_64/thread.rs");
    assert!(conversion.contains("rflags: 0x202"));
    assert!(conversion.contains("rcx: registers.rcx"));
    assert!(conversion.contains("r11: registers.r11"));
    assert!(conversion.contains("registers.rax,"));
    let restore = include_str!("../../../core/src/arch/x86_64/task_usermode.rs");
    for register in ["rcx", "r11", "rax"] {
        assert!(restore.contains(&format!(
            "\"mov {register}, [{0} + {{{register}_offset}}]\"",
            "rax"
        )));
    }
}
