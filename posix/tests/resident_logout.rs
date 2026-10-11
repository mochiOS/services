#[test]
fn resident_logout_uses_only_retained_process_owners_and_keeps_its_rpc_client() {
    let source = include_str!("../../service-manager/src/bootstrap.rs");
    let session = include_str!("../../service-manager/src/session.rs");
    for legacy in [
        "terminate_process_tree",
        "open_handle_for_process_id",
        "process::list",
        "parent_pid",
    ] {
        assert!(!source.contains(legacy));
        assert!(!session.contains(legacy));
    }
    let pending = source
        .split("struct PendingLogout {")
        .nth(1)
        .unwrap()
        .split("impl Runtime {")
        .next()
        .unwrap();
    assert!(pending.contains("session: ActiveSession"));
    assert!(pending.contains("plan: SessionTeardown"));
    assert!(pending.contains("client: mochios_posix_client::Client<"));
    let begin = source
        .split("platform::session_control::Action::LogOut => {")
        .nth(1)
        .unwrap();
    assert!(begin.contains("runtime.posix_endpoint"));
    assert!(begin.contains("SessionTeardown::begin("));
    assert!(begin.contains("&runtime.session_processes"));
    assert!(begin.contains("pending_logout = Some(PendingLogout"));
    assert!(!begin.contains("authenticate_session"));
    assert!(!begin.contains("active_session = None"));
    assert!(!begin.contains("request.action, session.id, 0"));
}

#[test]
fn resident_acknowledges_binder_last_and_only_complete_teardown_can_start_login() {
    let source = include_str!("../../service-manager/src/bootstrap.rs");
    let pending = source
        .split("(pending_logout.as_mut(), runtime.as_mut())")
        .nth(1)
        .unwrap()
        .split("let received =")
        .next()
        .unwrap();
    let compact: String = pending
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(compact.contains(
        "!logout.acknowledged&&logout.plan.pending_root()==Some(logout.session.binder_pid)"
    ));
    assert!(
        pending.find("reply_session_status(").unwrap() < pending.find("logout.plan.step(").unwrap()
    );
    assert!(pending.contains("terminate_owned_root(&logout.client, &mut runtime.session_processes"));
    let success = pending
        .split("Ok(true) => {")
        .nth(1)
        .unwrap()
        .split("Ok(false)")
        .next()
        .unwrap();
    assert!(success.contains("pending_logout = None"));
    assert!(success.contains("active_session.take()"));
    assert!(success.contains("runtime.login_next_session(previous)"));
    let failure = pending.split("Err(error) => {").nth(1).unwrap();
    for forbidden in [
        "active_session.take",
        "login_next_session",
        "pending_logout = None",
        "session_processes.remove",
    ] {
        assert!(!failure.contains(forbidden));
    }
    assert!(failure.contains("logout.last_error != Some(status)"));
    assert!(failure.contains("sleep_milliseconds(10)"));
}

#[test]
fn pending_logout_blocks_new_portal_launches_and_session_actions_without_losing_identity() {
    let source = include_str!("../../service-manager/src/bootstrap.rs");
    let resident = source.split("fn resident(").nth(1).unwrap();
    let compact: String = resident
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(compact
        .contains("letavailable_session=ifpending_logout.is_none(){active_session}else{None}"));
    assert!(resident.contains("sender_process != Some(session.binder_pid)"));
    assert!(resident.contains("request.session_id != session.id"));
    let busy = resident
        .split("if pending_logout.is_some() {")
        .nth(1)
        .unwrap()
        .split("let Some(runtime)")
        .next()
        .unwrap();
    assert!(busy.contains("mochi_user_syscall::EAGAIN"));
    assert!(busy.contains("continue;"));
}
