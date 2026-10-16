use super::*;

#[test]
fn service_uses_stored_credentials_and_attached_directory_authority() {
    let peer = PeerIdentity {
        process_id: 801,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = service_for(peer);
    let mut filesystem = RecordingFilesystem::default();
    let mut payload = [0; 128];
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            flags: 0,
            path: "link/../file",
        },
        &mut payload,
    )
    .unwrap();
    let directory = AttachedObject {
        handle: 901,
        rights: 0x81,
    };
    let reply = service.handle_objects(
        PeerIdentity {
            effective_uid: 0,
            effective_gid: 0,
            ..peer
        },
        protocol::Header {
            opcode: protocol::OP_CANONICAL_PATH_AT,
            request_id: 71,
            ..Default::default()
        },
        &payload[..length],
        &[directory],
        &mut filesystem,
    );
    assert_eq!(reply.response.header.status, 0);
    assert_eq!(reply.response.payload, b"/resolved/target");
    assert!(reply.handles.is_empty());
    let prepared = filesystem.stat_request.as_ref().unwrap();
    assert_eq!((prepared.effective_uid, prepared.effective_gid), (501, 20));
    assert_eq!(prepared.path, "link/../file");
    assert_eq!(filesystem.directory, Some(directory));
    assert!(filesystem.root.is_some());
}

#[test]
fn service_rejects_flags_missing_authority_and_extra_attachments() {
    let peer = PeerIdentity {
        process_id: 802,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = service_for(peer);
    let mut filesystem = RecordingFilesystem::default();
    for (base, flags, handles) in [
        (
            protocol::OpenBase::ProcessCwd,
            protocol::STAT_NOFOLLOW,
            vec![],
        ),
        (protocol::OpenBase::AttachedDirectory, 0, vec![]),
        (
            protocol::OpenBase::ProcessRoot,
            0,
            vec![AttachedObject {
                handle: 901,
                rights: 0x81,
            }],
        ),
    ] {
        let mut payload = [0; 128];
        let length = protocol::encode_stat_at(
            protocol::StatAtRequest {
                base,
                flags,
                path: "/file",
            },
            &mut payload,
        )
        .unwrap();
        let reply = service.handle_objects(
            peer,
            protocol::Header {
                opcode: protocol::OP_CANONICAL_PATH_AT,
                ..Default::default()
            },
            &payload[..length],
            &handles,
            &mut filesystem,
        );
        assert_eq!(reply.response.header.status, STATUS_EINVAL);
        assert!(filesystem.stat_request.is_none());
    }
}

struct CanonicalTransport;
impl Transport for CanonicalTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("object transport required")
    }
}
impl ObjectTransport for CanonicalTransport {
    type Handle = u32;
    fn close_received_handle(&self, _: u32) {
        panic!("no reply objects")
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_CANONICAL_PATH_AT);
        let request = protocol::decode_stat_at(payload).unwrap();
        assert_eq!(request.base, protocol::OpenBase::AttachedDirectory);
        assert_eq!(request.flags, 0);
        assert_eq!(request.path, "relative");
        assert_eq!(handles.len(), 1);
        assert_eq!(handles.get(0).unwrap().handle, 19);
        handles.clear();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: 6,
                ..Default::default()
            },
            b"/final",
            response,
        )
        .map_err(|_| ())
    }
}
#[test]
fn client_encodes_path_and_explicit_handle_not_fd_or_pointer() {
    let mut output = [0; 64];
    let length = Client::new(CanonicalTransport)
        .canonical_path_at(
            mochios_posix_client::StatAtBase::Directory(ObjectHandleAttachment {
                handle: 19,
                rights: 0x81,
            }),
            "relative",
            &mut output,
        )
        .unwrap();
    assert_eq!(&output[..length], b"/final");
}
