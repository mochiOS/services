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
    assert!(resize.contains("let entry = with_fd_entry(fd)?"));
    assert!(resize.contains("file_mutation(|| client.ftruncate(file, length as u64))"));
    let helper = source
        .split("fn file_mutation<T>(")
        .nth(1)
        .unwrap()
        .split("pub extern \"C\" fn truncate(")
        .next()
        .unwrap();
    assert!(helper.contains("match retry(operation"));
    assert!(helper.contains("drain_pending_signals()?"));
    assert!(helper.contains("SyscallNumber::ThreadYield"));
    assert!(!helper.contains("state()"));
    assert!(helper.contains("generate_thread_signal(posix_protocol::SIGNAL_XFSZ)?"));
}
