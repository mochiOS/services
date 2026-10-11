use mnu_abi::{ExecutionIdentity, HANDLE_RIGHT_SIGNAL, HANDLE_RIGHT_WAIT, ThreadStatus};
use posix_service::signal_thread_registration_matches;

#[test]
fn signal_registration_uses_authenticated_thread_identity_not_endpoint_number() {
    let sender = ExecutionIdentity {
        process_id: 19,
        thread_id: 42,
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

#[test]
fn matching_zero_identities_do_not_authenticate_a_signal_thread() {
    let rights = HANDLE_RIGHT_SIGNAL | HANDLE_RIGHT_WAIT;
    for sender in [
        ExecutionIdentity::default(),
        ExecutionIdentity {
            process_id: 0,
            thread_id: 42,
        },
        ExecutionIdentity {
            process_id: 19,
            thread_id: 0,
        },
    ] {
        let thread = ThreadStatus {
            process_id: sender.process_id,
            thread_id: sender.thread_id,
            ..Default::default()
        };
        assert!(!signal_thread_registration_matches(&sender, &thread, rights));
    }
}

#[test]
fn signal_validation_does_not_depend_on_native_credentials_or_package_policy() {
    let library = include_str!("../src/lib.rs");
    assert!(!library.contains("ThreadSecurityContext"));
    let runtime = include_str!("../src/main.rs");
    assert!(runtime.contains("context.process_id == peer.process_id"));
    assert!(runtime.contains("map(|context| platform::syscall::ExecutionIdentity"));
    assert!(!runtime.contains("context.effective_uid"));
    assert!(!runtime.contains("context.effective_gid"));
}
