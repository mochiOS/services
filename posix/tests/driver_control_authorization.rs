#[path = "../../drivers/src/control_authorization.rs"]
mod control_authorization;

#[test]
fn control_requires_authority_on_the_kernel_authenticated_sender() {
    assert!(control_authorization::manager_request(
        11,
        |endpoint| endpoint == 11
    ));
    assert!(!control_authorization::manager_request(11, |_| false));
}

#[test]
fn missing_authority_and_zero_sender_are_rejected() {
    assert!(!control_authorization::manager_request(0, |_| panic!(
        "zero sender"
    )));
    assert!(!control_authorization::manager_request(11, |_| false));
}

#[test]
fn both_idle_and_running_control_paths_validate_received_sender_identity() {
    let worker = include_str!("../../drivers/src/control_worker.rs");
    assert_eq!(
        worker.matches("is_manager_request(message >> 32)").count(),
        2
    );
    assert!(
        worker.contains("platform::capability::check_thread(endpoint, \"capabilities.manage\")")
    );
    assert!(!worker.contains("endpoint_owner_process"));
}
