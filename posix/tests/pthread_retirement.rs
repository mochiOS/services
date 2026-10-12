const RUNTIME: &str = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");

#[test]
fn join_waits_for_native_retirement_before_reclaiming_user_mappings() {
    let join = RUNTIME
        .split("fn pthread_join(")
        .nth(1)
        .unwrap()
        .split("fn pthread_detach(")
        .next()
        .unwrap();
    assert!(join.contains("match native_thread_retired(control)"));
    assert!(join.contains(
        "Ok(true) => {\n                    join_cancel_point(control);\n                    break;"
    ));
    assert!(join.contains("SyscallNumber::ThreadYield"));
    assert!(
        join.find("native_thread_retired(control)").unwrap()
            < join.find("release_thread_control(control)").unwrap()
    );
    let check = RUNTIME
        .split("fn native_thread_retired(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(check.contains("ThreadHandleStatus"));
    assert!(check.contains("mnu_abi::THREAD_STATE_TERMINATED"));
    assert!(check.contains("Err(ESRCH) => Ok(true)"));
    assert!(check.contains("Err(error) => Err(error)"));
}

#[test]
fn detached_reclamation_requires_native_retirement_and_closes_owned_handle() {
    let source = RUNTIME
        .split("fn reap_detached_threads()")
        .nth(1)
        .unwrap()
        .split("fn current_thread_control()")
        .next()
        .unwrap();
    let claim = source.find("THREAD_REAP_CLAIMED").unwrap();
    let check = source
        .find("native_thread_retired(control) == Ok(true)")
        .unwrap();
    let release = source.find("release_thread_control(control)").unwrap();
    assert!(claim < check && check < release);
    assert!(source.contains("control.joinability.store(THREAD_DETACHED, Ordering::Release)"));
    assert!(check < source.find("control.state.store(THREAD_REAPING").unwrap());
    let detach = RUNTIME
        .split("fn pthread_detach(")
        .nth(1)
        .unwrap()
        .split("fn pthread_exit(")
        .next()
        .unwrap();
    assert!(detach.contains("reap_detached_threads()"));
    let lookup = RUNTIME
        .split("fn current_thread_control()")
        .nth(1)
        .unwrap()
        .split("fn register_current_thread()")
        .next()
        .unwrap();
    assert!(lookup.contains("state != THREAD_REAPING"));
    let release = RUNTIME
        .split("fn release_thread_control(")
        .nth(1)
        .unwrap()
        .split("fn allocate_thread_reent(")
        .next()
        .unwrap();
    assert!(release.contains("native_handle.swap(0, Ordering::AcqRel)"));
    assert!(release.contains("SyscallNumber::HandleClose"));
}
