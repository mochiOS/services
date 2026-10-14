use mochios_posix_client::{
    Client, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

fn peer(process_id: u64) -> PeerIdentity {
    PeerIdentity {
        process_id,
        effective_uid: 0,
        effective_gid: 0,
    }
}
fn process(process_id: u64) -> AuthenticatedProcess<u32> {
    AuthenticatedProcess {
        handle: process_id as u32,
        process_id,
    }
}

#[test]
fn only_the_selected_bootstrap_process_can_initialize_existing_tasks() {
    let mut service = PosixService::new();
    assert_eq!(
        service.initialize_process(peer(70), process(80), 0, 0, &[]),
        Err(protocol::STATUS_EPERM)
    );
    service
        .initialize_bootstrap_process(process(70), 0, 0, &[])
        .unwrap();
    service
        .initialize_process(peer(70), process(90), 0, 0, &[])
        .unwrap();
    // A different UID-zero process, even with a genuine ProcessHandle, is not
    // the authority that was explicitly inherited at bootstrap.
    assert_eq!(
        service.initialize_process(peer(90), process(80), 0, 0, &[]),
        Err(protocol::STATUS_EPERM)
    );
    assert!(service.process_handle(80).is_none());
    service
        .initialize_process(peer(70), process(80), 501, 20, &[42])
        .unwrap();
    let before = *service.session(80).unwrap();
    assert_eq!(
        (before.real_uid, before.effective_uid, before.saved_uid),
        (501, 501, 501)
    );
    assert_eq!(before.effective_gid, 20);
    assert_eq!(service.parent_id(80), None);
    assert_eq!(service.process_handle(80), Some(80));
    service.handle(
        peer(80),
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(*service.session(80).unwrap(), before);
    assert_eq!(
        service.initialize_process(peer(70), process(80), 0, 0, &[]),
        Err(posix_service::STATUS_EINVAL)
    );
    assert_eq!(*service.session(80).unwrap(), before);
    let groups = service.handle(
        peer(80),
        protocol::Header {
            opcode: protocol::OP_GROUPS_GET,
            ..Default::default()
        },
        &[],
    );
    let mut decoded = [0; 1];
    assert_eq!(
        protocol::decode_group_list(&groups.payload, &mut decoded),
        Ok(1)
    );
    assert_eq!(decoded, [42]);
}

#[test]
fn dropped_bootstrap_privilege_and_invalid_credentials_cannot_create_state() {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(process(70), 0, 0, &[])
        .unwrap();
    for (uid, gid, groups) in [
        (u32::MAX, 0, vec![]),
        (0, u32::MAX, vec![]),
        (0, 0, vec![0; protocol::MAX_SUPPLEMENTARY_GROUPS + 1]),
    ] {
        assert_eq!(
            service.initialize_process(peer(70), process(80), uid, gid, &groups),
            Err(posix_service::STATUS_EINVAL)
        );
        assert!(service.process_handle(80).is_none());
    }
    let mut uid = [0; 4];
    protocol::encode_credential_id(501, &mut uid).unwrap();
    assert_eq!(
        service
            .handle(
                peer(70),
                protocol::Header {
                    opcode: protocol::OP_SET_UID,
                    ..Default::default()
                },
                &uid
            )
            .header
            .status,
        0
    );
    assert_eq!(
        service.initialize_process(peer(70), process(80), 0, 0, &[]),
        Err(protocol::STATUS_EPERM)
    );
    assert!(service.process_handle(80).is_none());
}

struct InitializationTransport;
impl Transport for InitializationTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("initialization must attach a process object")
    }
}
impl ObjectTransport for InitializationTransport {
    type Handle = u32;

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_PROCESS_INITIALIZE);
        assert_eq!(header.flags, 0);
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 7,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL
            })
        );
        let mut groups = [0; 2];
        assert_eq!(
            protocol::decode_spawn_credentials(payload, &mut groups),
            Ok((501, 20, 2))
        );
        assert_eq!(groups, [42, 43]);
        assert_eq!(payload.len(), 20); // Credentials only: no process ID.
        handles.clear();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                ..Default::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_initialization_transfers_only_an_explicit_attenuated_process_handle() {
    Client::new(InitializationTransport)
        .initialize_process(
            ObjectHandleAttachment {
                handle: 7,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
            },
            501,
            20,
            &[42, 43],
        )
        .unwrap();
    let source = include_str!("../../service-manager/src/spawn_support.rs");
    let initializer = source
        .split("fn install_posix_endpoint_at(")
        .nth(1)
        .unwrap()
        .split("pub(crate) fn install_early_posix_endpoints(")
        .next()
        .unwrap();
    assert!(
        initializer.find("client.initialize_process(").unwrap()
            < initializer.find("call_object_handles(destination").unwrap()
    );
    assert!(initializer.contains("open_handle_for_endpoint("));
    assert!(initializer.contains("close(process)"));
    assert!(!initializer.contains("thread_security_context"));
    assert!(!initializer.contains("open_handle_for_process_id"));
}
