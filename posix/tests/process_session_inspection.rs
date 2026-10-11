use mochios_posix_client::{
    Client, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

fn register(service: &mut PosixService, pid: u64, uid: u32) -> PeerIdentity {
    let peer = PeerIdentity {
        process_id: pid,
        effective_uid: uid,
        effective_gid: 24,
    };
    service
        .bind_process(
            peer,
            AuthenticatedProcess {
                handle: pid as u32,
                process_id: pid,
            },
        )
        .unwrap();
    let response = service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(response.header.status, 0);
    peer
}

#[test]
fn inspection_uses_stored_posix_identity_not_native_uid() {
    let mut service = PosixService::new();
    let root = register(&mut service, 1, 0);
    let alice = register(&mut service, 2, 505);
    register(&mut service, 3, 506);
    register(&mut service, 4, 505);
    let process = |pid| AuthenticatedProcess {
        handle: pid as u32,
        process_id: pid,
    };
    let info = service.inspect_process_session(root, process(2)).unwrap();
    assert_eq!(
        protocol::decode_session_info(&info).unwrap().effective_uid,
        505
    );
    assert!(service.inspect_process_session(alice, process(2)).is_ok());
    assert!(service.inspect_process_session(alice, process(4)).is_ok());
    let forged_native_root = PeerIdentity {
        effective_uid: 0,
        ..alice
    };
    assert_eq!(
        service.inspect_process_session(forged_native_root, process(3)),
        Err(protocol::STATUS_EPERM)
    );
    assert_eq!(
        service.inspect_process_session(root, process(999)),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.inspect_process_session(
            PeerIdentity {
                process_id: 999,
                ..root
            },
            process(2)
        ),
        Err(protocol::STATUS_ESRCH)
    );
    let invalid = service.handle(
        root,
        protocol::Header {
            opcode: protocol::OP_PROCESS_SESSION_INFO,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(invalid.header.status, posix_service::STATUS_EINVAL);
}

struct Inspection;
impl Transport for Inspection {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("must attach the process object")
    }
}
impl ObjectTransport for Inspection {
    type Handle = u32;
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_PROCESS_SESSION_INFO);
        assert_eq!(header.flags, 0);
        assert!(payload.is_empty());
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 52,
                rights: mnu_abi::HANDLE_RIGHT_WAIT
            })
        );
        handles.clear();
        let mut payload = [0; protocol::SESSION_INFO_LEN];
        protocol::encode_session_info(
            protocol::SessionInfo {
                real_uid: 505,
                effective_uid: 505,
                real_gid: 24,
                effective_gid: 24,
                umask: 0o22,
            },
            &mut payload,
        )
        .unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            &payload,
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_attaches_wait_only_object_without_serializing_pid() {
    let info = Client::new(Inspection)
        .process_session_info(ObjectHandleAttachment {
            handle: 52,
            rights: mnu_abi::HANDLE_RIGHT_WAIT,
        })
        .unwrap();
    assert_eq!((info.effective_uid, info.effective_gid), (505, 24));
}

#[test]
fn native_inspection_authenticates_handle_and_never_retains_query_reference() {
    let source = include_str!("../src/main.rs");
    let start = source.find("fn inspect_sender_process(").unwrap();
    let end = start + source[start..].find("fn adopt_sender_child(").unwrap();
    let inspection = &source[start..end];
    assert!(inspection.contains("process.rights != platform::handle::HANDLE_RIGHT_WAIT"));
    assert!(inspection.contains("platform::process::handle_status(process.handle)"));
    assert!(inspection.contains("process_id: status.process_id"));
    let start = source
        .find("if header.opcode == protocol::OP_PROCESS_SESSION_INFO")
        .unwrap();
    let end = start + source[start..].find("if matches!(").unwrap();
    let dispatch = &source[start..end];
    assert!(dispatch.contains("payload.is_empty()"));
    assert!(dispatch.contains("attachments.len() == 1"));
    assert!(!dispatch.contains("retained_handle ="));
}
