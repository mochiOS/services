use mnu_abi::SyscallNumber;

#[test]
fn native_process_suspension_is_generic_and_outside_the_posix_protocol() {
    assert_eq!(SyscallNumber::ProcessSuspendCurrent as u64, 669);

    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let implementation = include_str!("../../../core/src/syscall/process.rs");
    assert!(dispatch.contains("SyscallNumber::ProcessSuspendCurrent"));
    assert!(implementation.contains("pub fn suspend_current_process()"));
    assert!(!implementation.contains("SIGTSTP"));
    assert!(!implementation.contains("SIGTTIN"));
    assert!(!implementation.contains("SIGTTOU"));

    let protocol = include_str!("../../../user/crates/posix-protocol/src/lib.rs");
    assert!(!protocol.contains("OP_PROCESS_SUSPEND"));
}

#[test]
fn suspension_preserves_wait_state_and_resume_does_not_wake_blocked_threads() {
    let thread = include_str!("../../../core/src/task/thread.rs");
    let handle = include_str!("../../../core/src/syscall/handle.rs");
    assert!(thread.contains("scheduling_suspended: bool"));
    assert!(thread.contains("thread.state() == ThreadState::Ready"));
    assert!(thread.contains("&& !thread.is_scheduling_suspended()"));
    assert!(thread.contains("THREAD_QUEUE.lock().resume_process(process_id)"));
    assert!(handle.contains("crate::task::resume_process_threads(process_id)"));
    assert!(!handle.contains("for thread in threads {\n        crate::task::wake_thread(thread);"));
    assert!(!thread.contains("ThreadState::Suspended"));
}
