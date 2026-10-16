use super::*;

macro_rules! roundtrip {
    ($encode:ident, $decode:ident, $request:expr) => {{
        let request = $request;
        let mut payload = [0; protocol::MAX_CONTROL_PAYLOAD_LEN];
        let length = protocol::$encode(request, &mut payload).unwrap();
        assert_eq!(protocol::$decode(&payload[..length]).unwrap(), request);
        // Unicode validity is irrelevant, but framing and embedded NUL rules
        // remain mandatory for all byte pathname/target fields.
        payload[length - 1] = 0;
        assert!(protocol::$decode(&payload[..length]).is_err());
    }};
}

#[test]
fn all_path_codecs_roundtrip_non_utf8_without_normalization() {
    let path = b"../name-\xff\xc0\x80".as_slice();
    let other = b"/target-\xfe".as_slice();
    let base = protocol::OpenBase::AttachedDirectory;
    roundtrip!(
        encode_open_at,
        decode_open_at,
        protocol::OpenAtRequest {
            base,
            options: protocol::OPEN_READ,
            mode: 0,
            path,
        }
    );
    roundtrip!(
        encode_stat_at,
        decode_stat_at,
        protocol::StatAtRequest {
            base,
            flags: 0,
            path
        }
    );
    roundtrip!(
        encode_access_at,
        decode_access_at,
        protocol::AccessAtRequest {
            base,
            flags: 0,
            modes: 0,
            path,
        }
    );
    roundtrip!(
        encode_rename_at,
        decode_rename_at,
        protocol::RenameAtRequest {
            old_base: base,
            new_base: base,
            old_path: path,
            new_path: other,
        }
    );
    roundtrip!(
        encode_link_at,
        decode_link_at,
        protocol::LinkAtRequest {
            old_base: base,
            new_base: base,
            flags: 0,
            old_path: path,
            new_path: other,
        }
    );
    roundtrip!(
        encode_truncate_at,
        decode_truncate_at,
        protocol::TruncateAtRequest {
            base,
            length: 5,
            path
        }
    );
    roundtrip!(
        encode_symlink_at,
        decode_symlink_at,
        protocol::SymlinkAtRequest {
            base,
            target: path,
            link_path: other
        }
    );
    roundtrip!(
        encode_chown_at,
        decode_chown_at,
        protocol::ChownAtRequest {
            base,
            flags: 0,
            uid: 501,
            gid: 20,
            path
        }
    );
}

#[test]
fn authenticated_preparation_preserves_every_byte_and_authority() {
    let peer = PeerIdentity {
        process_id: 803,
        effective_uid: 501,
        effective_gid: 20,
    };
    let service = service_for(peer);
    let forged = PeerIdentity {
        effective_uid: 0,
        effective_gid: 0,
        ..peer
    };
    let mut payload = [0; 128];
    let path = b"directory-\xff/file-\xfe";
    let length = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            options: protocol::OPEN_READ,
            mode: 0,
            path,
        },
        &mut payload,
    )
    .unwrap();
    let prepared = service
        .prepare_open_at(forged, &payload[..length], 1)
        .unwrap();
    assert_eq!(prepared.path, path);
    assert_eq!((prepared.effective_uid, prepared.effective_gid), (501, 20));
    assert_eq!(
        service.prepare_open_at(forged, &payload[..length], 0),
        Err(STATUS_EINVAL)
    );
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            flags: 0,
            path,
        },
        &mut payload,
    )
    .unwrap();
    let prepared = service
        .prepare_stat_at(forged, &payload[..length], 1)
        .unwrap();
    assert_eq!(prepared.path, path);
    assert_eq!((prepared.effective_uid, prepared.effective_gid), (501, 20));
}

#[test]
fn path_encoder_still_enforces_nul_empty_and_length_limits() {
    let too_long = vec![0xff; protocol::MAX_PATH_LEN + 1];
    let mut output = [0; protocol::MAX_CONTROL_PAYLOAD_LEN];
    for path in [b"".as_slice(), b"non\0utf8-\xff", &too_long] {
        assert!(
            protocol::encode_open_at(
                protocol::OpenAtRequest {
                    base: protocol::OpenBase::ProcessRoot,
                    options: protocol::OPEN_READ,
                    mode: 0,
                    path,
                },
                &mut output
            )
            .is_err()
        );
    }
    let maximum = vec![0xff; protocol::MAX_PATH_LEN];
    roundtrip!(
        encode_open_at,
        decode_open_at,
        protocol::OpenAtRequest {
            base: protocol::OpenBase::ProcessRoot,
            options: protocol::OPEN_READ,
            mode: 0,
            path: &maximum,
        }
    );
}
