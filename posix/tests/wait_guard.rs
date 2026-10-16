use mnu_abi::{HandleWaitGuard, SyscallNumber};

#[test]
fn wait_guard_layout_and_native_entry_are_explicit() {
    assert_eq!(std::mem::size_of::<HandleWaitGuard>(), 16);
    assert_eq!(std::mem::align_of::<HandleWaitGuard>(), 8);
    assert_eq!(std::mem::offset_of!(HandleWaitGuard, expected), 8);
    assert_eq!(SyscallNumber::HandleWaitMany as u64, 647);
    assert_eq!(SyscallNumber::HandleWaitManyGuarded as u64, 682);
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    assert!(dispatch.contains("handle::wait_many(arg0, arg1, arg2, 0)"));
    assert!(dispatch.contains("handle::wait_many(arg0, arg1, arg2, arg3)"));
}

#[test]
fn kernel_checks_only_readable_aligned_values_after_waiter_cleanup() {
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let wait = source
        .split("pub fn wait_many(")
        .nth(1)
        .unwrap()
        .split("pub fn process_resume(")
        .next()
        .unwrap();
    assert!(wait.contains("copy_from_user_native(guard_ptr, &mut bytes)"));
    assert!(!wait.contains("read_user_u64"));
    let check = wait.find("read_guard_value(guard.address)").unwrap();
    assert!(wait[..check].contains("remove_provider_waiters(current"));
    assert!(
        wait[check..].find("value != guard.expected").unwrap()
            < wait[check..].find("sleep_thread_unless_woken").unwrap()
    );
    assert!(!wait.contains("SIGNAL_TTIN"));
    assert!(!wait.contains("posix"));
    let address = include_str!("../../../core/src/syscall/address_wait.rs");
    let guard = address
        .split("fn read_guard_value(")
        .nth(1)
        .unwrap()
        .split("fn load_value(")
        .next()
        .unwrap();
    assert!(guard.contains("resolve_key(address, 8)"));
    assert!(guard.contains("load_value(key, 8)"));
}

#[test]
fn runtime_guards_notifications_while_preserving_nonrestart_signal_semantics() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let wait = source
        .split("fn wait_for_handle_since(")
        .nth(1)
        .unwrap()
        .split("fn stream_io<")
        .next()
        .unwrap();
    assert!(wait.contains("HandleWaitGuard"));
    assert!(wait.contains("expected: notification"));
    assert!(wait.contains("control.nonrestart_signal_generation.load(Ordering::Acquire)"));
    assert!(wait.contains("control.multiplex_generation as *const AtomicU64"));
    assert!(wait.contains("SyscallNumber::HandleWaitManyGuarded"));
    assert!(wait.contains("raw_syscall4"));
}
