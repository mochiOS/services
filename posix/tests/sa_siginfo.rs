use mochios_posix_client::{signal, signal_context::*};

fn machine() -> MachineContext {
    let mut context = MachineContext {
        gregs: [0; NGREG],
        fpregs: [0; 512],
    };
    context.gregs[REG_RIP] = 0x4000;
    context.gregs[REG_RSP] = 0x8000;
    context.gregs[REG_EFL] = 0x202;
    context.fpregs[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes());
    context.fpregs[28..32].copy_from_slice(&0xffbf_u32.to_le_bytes());
    context
}

#[test]
fn edited_cpu_returns_are_checked_before_userspace_restore() {
    let original = machine();
    assert_eq!(original.checked_return(&original), Some(original));
    for (register, value) in [
        (REG_RIP, 0),
        (REG_RIP, 1 << 47),
        (REG_RSP, 0),
        (REG_RSP, 15),
        (REG_RSP, u64::MAX),
        (REG_EFL, 2),
        (REG_EFL, 0x200),
        (REG_EFL, 0x3202),
        (REG_EFL, u64::MAX),
    ] {
        let mut edited = original;
        edited.gregs[register] = value;
        assert!(edited.checked_return(&original).is_none());
    }
    let mut edited = original;
    edited.fpregs[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    edited.fpregs[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        edited.checked_return(&original).is_none(),
        "handler mask must not authorize MXCSR bits"
    );
    edited.fpregs[24..28].copy_from_slice(&0x3f80_u32.to_le_bytes());
    let selected = edited.checked_return(&original).unwrap();
    assert_eq!(&selected.fpregs[28..32], &0xffbf_u32.to_le_bytes());
    let mut no_mask = original;
    no_mask.fpregs[28..32].fill(0);
    let mut unsupported = no_mask;
    unsupported.fpregs[24..28].copy_from_slice(&0x1fc0_u32.to_le_bytes());
    assert!(unsupported.checked_return(&no_mask).is_none());
    assert_eq!(signal::SA_SIGINFO, 4);
}

#[test]
fn dispatch_requires_real_delivery_metadata_and_finishes_bookkeeping_before_restore() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let dispatch = source
        .split("fn dispatch_signal(")
        .nth(1)
        .unwrap()
        .split("fn apply_default_signal_action(")
        .next()
        .unwrap();
    assert!(dispatch.contains(".signal_delivery_origin(delivery)"));
    assert!(dispatch.contains("signal_stack::invoke(") && dispatch.contains("preparation"));
    let stack = include_str!("../../../user/crates/newlib-runtime/src/signal_stack.rs");
    let compact: String = stack.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(compact.contains("function(invocation.signal,info,"));
    assert!(stack.contains("(invocation.context as *mut UContext).cast()"));
    assert!(dispatch.contains("context.uc_sigmask = previous"));
    assert!(dispatch.contains("checked_return(&original)"));
    let scoped = include_str!("../../../user/crates/newlib-runtime/src/signal_delivery.rs");
    assert!(
        scoped
            .find("drain_pending_signals_with_context(&mut frame, false)")
            .unwrap()
            < scoped.find("machine.write(frame.uc_mcontext)").unwrap()
    );
    assert!(scoped.contains("ThreadUpcallInspect"));
    assert!(scoped.contains("ThreadUpcallReturnContext"));
    assert!(!scoped.contains("ThreadUpcallReturn,"));
    assert!(source.contains("dispatch_signal(delivery, None, context, native, &mut preparation)"));
    let fault = include_str!("../../../user/crates/newlib-runtime/src/fault_signal.rs");
    let compact: String = fault.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(
        compact.contains("dispatch_signal(fault.signal,Some(info),context,true,&mutpreparation)")
    );
    assert!(scoped.contains("if delivered.is_ok()"));
}
