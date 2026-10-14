#[test]
fn pending_generic_upcalls_return_after_wait_registration_cleanup() {
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let wait = source
        .split("pub fn wait_many(")
        .nth(1)
        .unwrap()
        .split("pub fn process_resume(")
        .next()
        .unwrap();
    let check = wait.find("upcall::current_has_deliverable_upcall()").unwrap();
    for cleanup in [
        "remove_process_exit_waiters(current)",
        "remove_endpoint_waiters(current",
        "remove_stream_waiters(current",
        "remove_provider_waiters(current",
        "disarm_thread_deadline(current)",
    ] {
        assert!(wait.find(cleanup).unwrap() < check);
    }
    assert!(
        wait[check..]
            .find("copy_wait_items_to_user(items_ptr, &items)")
            .unwrap()
            < wait[check..]
                .find("sleep_thread_unless_woken(current)")
                .unwrap()
    );
    assert!(!wait.contains("SIGNAL_"));
    assert!(!wait.contains("EINTR"));
    assert!(!wait.contains("posix"));
}

#[test]
fn userspace_wait_converts_caught_handlers_but_retries_other_wakeups() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let wait = runtime
        .split("fn wait_for_handle(")
        .nth(1)
        .unwrap()
        .split("fn syscall_write(")
        .next()
        .unwrap();
    assert!(wait.contains("nonrestart_signal_generation.load"));
    assert!(wait.contains("return Err(EINTR)"));
    assert!(wait.contains("wait_cancellable("));
    assert!(wait.contains("Err(EAGAIN) => Ok(false)"));
}
