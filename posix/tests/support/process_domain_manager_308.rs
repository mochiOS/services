//! A measured manager is not itself a member of the user's launch domain.
use mochi_user_platform as p;
pub fn run(
    domain: &crate::consent_session::LaunchDomain,
    root: &crate::native_process::NativeProcess,
) {
    use mochios_posix_client::{Client, ObjectHandleAttachment, SyscallEndpointTransport};
    let endpoint = p::handle::inherited(mochios_posix_protocol::CONTROL_HANDLE_KEY).unwrap();
    let client = Client::new(SyscallEndpointTransport::new(endpoint));
    let mut attachment = root.termination_attachment();
    attachment.rights = p::handle::HANDLE_RIGHT_WAIT;
    assert!(
        client
            .process_domain_contains(domain.attachment(), attachment)
            .unwrap()
    );
    let self_endpoint = p::ipc::create().unwrap();
    let process = p::execution_peer::ProcessReference(
        p::process::open_handle_for_endpoint(
            self_endpoint,
            p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_TRANSFER,
        )
        .unwrap(),
    );
    let own = ObjectHandleAttachment {
        handle: process.0,
        rights: p::handle::HANDLE_RIGHT_WAIT,
    };
    assert!(
        !client
            .process_domain_contains(domain.attachment(), own)
            .unwrap()
    );
    assert!(
        client
            .process_domain_contains(
                ObjectHandleAttachment {
                    handle: process.0,
                    rights: p::handle::HANDLE_RIGHT_TRANSFER
                },
                own
            )
            .is_err(),
        "a Process cannot impersonate a domain object"
    );
    let broker = p::process::find_by_name("capability.service").unwrap();
    let mut reply = [0; 8];
    p::ipc::call(broker, b"DM08", &mut reply).unwrap();
    assert_eq!(u64::from_le_bytes(reply), 13);
    p::ipc::call(broker, b"DM08fake-session", &mut reply).unwrap();
    assert_eq!(u64::from_le_bytes(reply), 22);
    println!(
        "process-domain-308: PASS actual session root admitted; manager outside user domain denied; wrong object and caller-supplied session refused"
    );
}
