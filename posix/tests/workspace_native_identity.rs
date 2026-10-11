#[test]
fn file_panel_identity_uses_only_the_authenticated_native_endpoint_owner() {
    let source = include_str!("../../workspace/src/main.rs");
    let panel = source
        .split_once("    fn file_panel(&mut self,")
        .unwrap()
        .1
        .split_once("    fn file_panel_complete(")
        .unwrap()
        .0;
    assert!(panel.contains("platform::ipc::endpoint_execution_identity(sender)"));
    assert!(!panel.contains("thread_security_context"));
    assert!(!panel.contains("effective_uid"));
    assert!(!panel.contains("effective_gid"));
    assert!(panel.contains("if context.process_id == 0"));
    assert!(panel.contains("requester_process: context.process_id"));
    assert!(panel.contains("grant_endpoint: sender"));
}

#[test]
fn notification_package_authentication_is_not_replaced_with_a_bare_pid() {
    let source = include_str!("../../workspace/src/main.rs");
    let notification = source
        .split_once("    fn notification_post(")
        .unwrap()
        .1
        .split_once("    fn ")
        .unwrap()
        .0;
    assert!(notification.contains("thread_security_context(sender)"));
    assert!(notification.contains("package != Some(notification.bundle_id)"));
}
