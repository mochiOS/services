use super::*;
use mochios_filesystem_protocol::object_limits::Limits;

#[test]
fn limits_request_uses_stored_identity_not_peer_claims() {
    let peer = PeerIdentity {
        process_id: 991,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = service_for(peer);
    let mut filesystem = RecordingFilesystem::default();
    let mut payload = [0; 128];
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            flags: 0,
            path: b"not-readable",
        },
        &mut payload,
    )
    .unwrap();
    let result = service.handle_objects(
        PeerIdentity {
            effective_uid: 0,
            effective_gid: 0,
            ..peer
        },
        protocol::Header {
            opcode: protocol::OP_PATH_LIMITS_AT,
            request_id: 72,
            ..Default::default()
        },
        &payload[..length],
        &[],
        &mut filesystem,
    );
    assert_eq!(result.response.header.status, 0);
    assert_eq!(
        Limits::decode(&result.response.payload)
            .unwrap()
            .name_bytes_max,
        255
    );
    assert!(result.handles.is_empty());
    let request = filesystem.stat_request.unwrap();
    assert_eq!((request.effective_uid, request.effective_gid), (501, 20));
    assert_eq!(request.path, b"not-readable");
}

struct LimitsTransport {
    bytes: usize,
}
impl Transport for LimitsTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("explicit object transport required")
    }
}
impl ObjectTransport for LimitsTransport {
    type Handle = u32;
    fn close_received_handle(&self, _: u32) {
        panic!("no reply object expected")
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_PATH_LIMITS_AT);
        let request = protocol::decode_stat_at(payload).unwrap();
        assert_eq!(request.base, protocol::OpenBase::AttachedDirectory);
        assert_eq!(request.flags, 0);
        assert_eq!(request.path, b"target-\xff");
        assert_eq!(handles.len(), 1);
        assert_eq!(handles.get(0).unwrap().handle, 19);
        handles.clear();
        let bytes = Limits {
            name_bytes_max: 255,
            path_bytes_max: 4096,
            link_count_max: 65535,
            filesystem_block_bytes: 1024,
        }
        .encode();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: self.bytes as u32,
                ..Default::default()
            },
            &bytes[..self.bytes],
            output,
        )
        .map_err(|_| ())
    }
}
#[test]
fn client_transfers_directory_authority_and_decodes_only_complete_limits() {
    for length in [0, 15, 16] {
        let result = Client::new(LimitsTransport { bytes: length }).path_limits_at(
            mochios_posix_client::StatAtBase::Directory(ObjectHandleAttachment {
                handle: 19,
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
            }),
            b"target-\xff",
        );
        if length == 16 {
            assert_eq!(result.unwrap().filesystem_block_bytes, 1024);
        } else {
            assert!(matches!(result, Err(ClientError::MismatchedResponse)));
        }
    }
}
