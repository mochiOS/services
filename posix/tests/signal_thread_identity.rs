use mnu_abi::{HANDLE_RIGHT_SIGNAL, HANDLE_RIGHT_WAIT, ThreadSecurityContext, ThreadStatus};
use posix_service::signal_thread_registration_matches;

#[test]
fn signal_registration_uses_authenticated_thread_identity_not_endpoint_number() {
    let sender = ThreadSecurityContext {
        process_id: 19,
        thread_id: 42,
        ..Default::default()
    };
    let thread = ThreadStatus {
        process_id: 19,
        thread_id: 42,
        ..Default::default()
    };
    let rights = HANDLE_RIGHT_SIGNAL | HANDLE_RIGHT_WAIT;
    assert!(signal_thread_registration_matches(&sender, &thread, rights));
    // The message's opaque endpoint can have a completely different number.
    let endpoint_as_thread = ThreadStatus {
        thread_id: 0x4000_0005,
        ..thread
    };
    assert!(!signal_thread_registration_matches(
        &sender,
        &endpoint_as_thread,
        rights
    ));
    let other_thread = ThreadStatus {
        thread_id: 43,
        ..thread
    };
    assert!(!signal_thread_registration_matches(
        &sender,
        &other_thread,
        rights
    ));
    let other_process = ThreadStatus {
        process_id: 20,
        ..thread
    };
    assert!(!signal_thread_registration_matches(
        &sender,
        &other_process,
        rights
    ));
    assert!(!signal_thread_registration_matches(
        &sender,
        &thread,
        HANDLE_RIGHT_WAIT
    ));
    assert!(!signal_thread_registration_matches(
        &sender,
        &thread,
        rights | mnu_abi::HANDLE_RIGHT_TRANSFER
    ));
}
