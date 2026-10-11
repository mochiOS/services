use mnu_abi::SyscallNumber;

#[test]
fn native_process_suspension_is_generic_and_outside_the_posix_protocol() {
    assert_eq!(SyscallNumber::ProcessSuspendCurrent as u64, 669);
    assert_eq!(SyscallNumber::ProcessHandleSuspend as u64, 670);

    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let implementation = include_str!("../../../core/src/syscall/process.rs");
    assert!(dispatch.contains("SyscallNumber::ProcessSuspendCurrent"));
    assert!(dispatch.contains("SyscallNumber::ProcessHandleSuspend"));
    assert!(implementation.contains("pub fn suspend_current_process()"));
    assert!(!implementation.contains("SIGTSTP"));
    assert!(!implementation.contains("SIGTTIN"));
    assert!(!implementation.contains("SIGTTOU"));

    let protocol = include_str!("../../../user/crates/posix-protocol/src/lib.rs");
    assert!(!protocol.contains("OP_PROCESS_SUSPEND"));

    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("posix_protocol::SIGNAL_TSTP"));
    assert!(runtime.contains("posix_protocol::SIGNAL_TTIN"));
    assert!(runtime.contains("posix_protocol::SIGNAL_TTOU"));
    let report = runtime
        .find(".report_process_stopped(delivery)")
        .expect("default stop action must report authenticated process state");
    assert!(runtime.contains("PosixClientError::Remote(posix_protocol::STATUS_EAGAIN)"));
    assert!(!runtime[report..report + 256.min(runtime.len() - report)]
        .contains("ProcessSuspendCurrent"));
    assert!(runtime.contains(".report_process_signaled(delivery)"));
    assert!(runtime.contains(".complete_signal_delivery(delivery)"));

    let service = include_str!("../src/main.rs");
    assert!(service.contains("platform::process::suspend_handle(process)"));
    assert!(service.contains("platform::process::terminate_handle(process, exit_code)"));

    let native_process_control = include_str!("../../../core/src/syscall/handle.rs");
    assert!(!native_process_control.contains("WTERMSIG"));
    assert!(!native_process_control.contains("SIGCHLD"));
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

    let service = include_str!("../src/main.rs");
    assert!(service.contains("platform::process::resume_handle(handle)"));

    let native_handles = include_str!("../../../core/src/syscall/handle.rs");
    assert!(native_handles.contains("crate::capability::Capability::ProcessKill"));
    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("\"process.kill\""));
}

#[test]
fn child_exit_notification_waits_on_generic_process_handles() {
    let service = include_str!("../src/main.rs");
    assert!(service.contains("service.refresh_child_exit_notifications(&mut processes)"));
    assert!(service.contains("let lifecycle_handles = service.child_lifecycle_handles();"));
    assert!(service.contains("for handle in lifecycle_handles"));
    assert!(service.contains("interests: syscall::HANDLE_SIGNAL_TERMINATED"));

    let kernel = include_str!("../../../core/src/syscall/handle.rs");
    assert!(!kernel.contains("SIGNAL_CHLD"));
    assert!(!kernel.contains("SIGCHLD"));
}
