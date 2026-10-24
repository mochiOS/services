use super::*;
pub(super) fn status() -> filesystem_protocol::volume_status::Status {
    filesystem_protocol::volume_status::Status {
        block_bytes: 4096,
        flags: 0,
        blocks: 1 << 36,
        free_blocks: 1 << 35,
        inodes: 2048,
        free_inodes: 2000,
        filesystem_id: 7,
        name_bytes_max: 255,
    }
}
#[test]
fn volume_paths_use_saved_session_credentials_and_canonical_stat_policy() {
    let peer = PeerIdentity {
        process_id: 992,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = service_for(peer);
    let mut filesystem = RecordingFilesystem::default();
    let mut bytes = [0; 128];
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            flags: 0,
            path: b"file\xff",
        },
        &mut bytes,
    )
    .unwrap();
    let reply = service.handle_objects(
        PeerIdentity {
            effective_uid: 0,
            effective_gid: 0,
            ..peer
        },
        protocol::Header {
            opcode: protocol::OP_VOLUME_STATUS_AT,
            request_id: 72,
            ..Default::default()
        },
        &bytes[..length],
        &[],
        &mut filesystem,
    );
    assert_eq!(reply.response.header.status, 0);
    assert_eq!(
        filesystem_protocol::volume_status::Status::decode(&reply.response.payload),
        Some(status())
    );
    let request = filesystem.stat_request.take().unwrap();
    assert_eq!((request.effective_uid, request.effective_gid), (501, 20));
    assert_eq!(request.path, b"file\xff");
    assert!(reply.handles.is_empty());
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            flags: protocol::STAT_NOFOLLOW,
            path: b"x",
        },
        &mut bytes,
    )
    .unwrap();
    let reply = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_VOLUME_STATUS_AT,
            ..Default::default()
        },
        &bytes[..length],
        &[],
        &mut filesystem,
    );
    assert_eq!(reply.response.header.status, -22);
    assert!(filesystem.stat_request.is_none());
}
#[test]
fn volume_handle_is_explicit_and_requires_transfer() {
    let peer = PeerIdentity {
        process_id: 992,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = service_for(peer);
    let mut filesystem = RecordingFilesystem::default();
    for rights in [0, mnu_abi::HANDLE_RIGHT_TRANSFER] {
        let reply = service.handle_objects(
            peer,
            protocol::Header {
                opcode: protocol::OP_VOLUME_STATUS_HANDLE,
                ..Default::default()
            },
            &[],
            &[AttachedObject { handle: 51, rights }],
            &mut filesystem,
        );
        assert_eq!(
            reply.response.header.status,
            if rights == 0 { -13 } else { 0 }
        );
    }
    assert_eq!(
        filesystem.stat_file,
        Some(AttachedObject {
            handle: 51,
            rights: mnu_abi::HANDLE_RIGHT_TRANSFER
        })
    );
}
