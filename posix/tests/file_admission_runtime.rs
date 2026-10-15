#[test]
fn runtime_waits_outside_global_state_and_keeps_file_lease_for_replay() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let resize = source
        .split("pub extern \"C\" fn _ftruncate(")
        .nth(1)
        .unwrap()
        .split("pub extern \"C\" fn ftruncate(")
        .next()
        .unwrap();
    assert!(resize.contains("file_mutation::ftruncate(fd, length as u64)"));
    let mutation = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    let helper = mutation
        .split("fn execute<'a,")
        .nth(1)
        .unwrap()
        .split("pub(super) fn ftruncate(")
        .next()
        .unwrap();
    assert!(helper.contains("client.execute_file_mutation(prepared"));
    assert!(helper.contains("drain_pending_signals()?"));
    assert!(!helper.contains("SyscallNumber::ThreadYield"));
    assert!(!helper.contains("state()"));
    assert!(helper.contains("generate_thread_signal(posix_protocol::SIGNAL_XFSZ)?"));
    let resize = mutation
        .split("pub(super) fn ftruncate(")
        .nth(1)
        .unwrap()
        .split("pub(super) fn truncate(")
        .next()
        .unwrap();
    assert!(resize.contains("source: with_fd_entry(fd)?"));
    assert!(resize.contains("scope.as_mut().activate()"));
    assert!(resize.contains("scope.as_mut().retire()"));
}
