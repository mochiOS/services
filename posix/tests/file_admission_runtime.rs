#[test]
fn openat_captures_directory_authority_and_tracks_it_before_reopening_callbacks() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let exported = runtime
        .split("pub extern \"C\" fn openat(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(exported.contains("file_mutation::open_at(dirfd, path, flags, mode)"));
    assert!(
        exported.find("pthread_testcancel()").unwrap()
            < exported.find("file_mutation::open_at(").unwrap()
    );
    let mutation = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    assert!(mutation.contains("_directory: Option<fd_lease::Lease>"));
    let slot = mutation.split("fn open_in_slot(").nth(1).unwrap();
    assert!(
        slot.find("let native = delivery(control)").unwrap()
            < slot.find("rename_posix_base(dirfd, path)").unwrap()
    );
    assert!(slot.find("prepare_open_at(base,").unwrap() < slot.find("drop(native)").unwrap());
    assert!(slot.find("_directory: directory").unwrap() < slot.find("activate()").unwrap());
    assert_eq!(slot.matches("c_bytes(path)").count(), 1);
    for error in ["return Err(ENOENT)", "return Err(ENAMETOOLONG)"] {
        assert!(slot.find(error).unwrap() < slot.find("prepare_open_at(base,").unwrap());
    }
}

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

#[test]
fn spawn_actions_use_the_live_child_table_and_the_same_queued_open_owner() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(!runtime.contains("fn open_posix_entry("));
    assert!(!runtime.contains("fn file_mutation<T>("));
    let actions = runtime
        .split("fn apply_spawn_file_actions(")
        .nth(1)
        .unwrap()
        .split("unsafe fn read_exec_vector")
        .next()
        .unwrap();
    assert!(!actions.contains("fds: &mut FdTable"));
    assert!(actions.contains("state().fds.close_for_spawn"));
    assert!(actions.contains("file_mutation::open_for_spawn("));
    let child = runtime
        .split("pub extern \"C\" fn _posix_spawn(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(
        child.find("state().fds = desired_fds").unwrap()
            < child.find("apply_spawn_file_actions(").unwrap()
    );
    assert!(child.contains("execve_with_launch_context("));
    let mutation = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    assert!(mutation.contains("open_in_slot(-2, path, flags, mode, Some(fd))"));
    let slot = mutation.split("fn open_in_slot(").nth(1).unwrap();
    assert!(
        slot.find("close_for_spawn(fd").unwrap()
            < slot.find("reserve_from(minimum, limit)").unwrap()
    );
    assert!(slot.contains("(fd, fd + 1)"));
}

#[test]
fn exec_snapshot_pins_are_registered_before_application_callbacks_can_run() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let operation = source
        .split("fn execve_with_launch_context(")
        .nth(1)
        .unwrap()
        .split("fn clone_registered_process(")
        .next()
        .unwrap();
    assert!(
        operation.find("Guard::enter(").unwrap()
            < operation.find("clone_current_fd_table()").unwrap()
    );
    assert!(operation.find("activate()").unwrap() < operation.find("drop(delivery)").unwrap());
    assert!(
        operation.find("replace_process_image(").unwrap() < operation.find("retire()").unwrap()
    );
}
