use super::*;
use posix_service::mutation_admission::TICKET_RIGHTS;

#[test]
fn two_hop_native_probe_tracks_posix_wire_constants() {
    let source = include_str!("../native_posix_admission.c");
    for (name, opcode) in [
        ("P_OPEN", protocol::OP_OPEN_AT),
        ("P_FTRUNCATE", protocol::OP_FTRUNCATE),
        ("P_UNLINK", protocol::OP_UNLINK_AT),
        ("P_TRUNCATE", protocol::OP_TRUNCATE_AT),
    ] {
        assert!(source.contains(&format!("{name} = {opcode}")));
    }
    assert_eq!(protocol::CONTROL_HANDLE_KEY, 0x4c52544358534f50);
    assert_eq!(protocol::HEADER_LEN, 32);
    assert_eq!(protocol::OPEN_AT_HEADER_LEN, 16);
    assert_eq!(protocol::TRUNCATE_AT_HEADER_LEN, 16);
    assert_eq!(protocol::STAT_AT_HEADER_LEN, 12);
    assert_eq!(protocol::MUTATION_ADMISSION, 1 << 31);
    assert_eq!(protocol::MUTATION_ADMISSION_ATTACHED, 1 << 30);
}

fn payload(opcode: u16) -> Vec<u8> {
    let mut bytes = vec![0; 256];
    let len = match opcode {
        protocol::OP_OPEN_AT => protocol::encode_open_at(
            protocol::OpenAtRequest {
                base: protocol::OpenBase::AttachedDirectory,
                options: protocol::OPEN_WRITE | protocol::OPEN_TRUNCATE,
                mode: 0,
                path: "file",
            },
            &mut bytes,
        )
        .unwrap(),
        protocol::OP_TRUNCATE_AT => protocol::encode_truncate_at(
            protocol::TruncateAtRequest {
                base: protocol::OpenBase::AttachedDirectory,
                length: 5000,
                path: "file",
            },
            &mut bytes,
        )
        .unwrap(),
        _ => {
            bytes[..8].copy_from_slice(&5000u64.to_le_bytes());
            8
        }
    };
    bytes.truncate(len);
    bytes
}

fn file() -> AttachedObject<u32> {
    AttachedObject {
        handle: 55,
        rights: mnu_abi::HANDLE_RIGHT_READ
            | mnu_abi::HANDLE_RIGHT_WRITE
            | mnu_abi::HANDLE_RIGHT_TRANSFER,
    }
}

#[test]
fn queued_mutations_forward_one_owned_ticket_and_resume_without_fd_numbers() {
    for opcode in [
        protocol::OP_OPEN_AT,
        protocol::OP_FTRUNCATE,
        protocol::OP_TRUNCATE_AT,
    ] {
        let peer = PeerIdentity {
            process_id: 111,
            effective_uid: 505,
            effective_gid: 24,
        };
        let mut service = service_for(peer);
        let token = OpenedObject {
            handle: 900,
            rights: TICKET_RIGHTS,
        };
        let mut fs = RecordingFilesystem {
            admission_response: Some(Ok(token)),
            ..Default::default()
        };
        let body = payload(opcode);
        let header = protocol::Header {
            opcode,
            request_id: 123,
            flags: protocol::MUTATION_ADMISSION,
            ..Default::default()
        };
        let first = service.handle_objects(peer, header, &body, &[file()], &mut fs);
        assert_eq!(
            first.response.header.status,
            protocol::STATUS_MEMORY_ADMISSION_BUSY
        );
        assert_eq!(first.response.header.request_id, 123);
        assert!(first.response.payload.is_empty());
        assert_eq!(first.handles, [token]);
        assert_eq!(fs.admission_calls, [(opcode, None)]);
        assert!(fs.truncated.is_none() && fs.request.is_none() && fs.truncate_request.is_none());
        // A pending mutation does not change the process environment or stop
        // unrelated requests while the client waits outside the service.
        assert_eq!(
            service
                .handle(
                    peer,
                    protocol::Header {
                        opcode: protocol::OP_SESSION_INFO,
                        ..Default::default()
                    },
                    &[]
                )
                .header
                .status,
            0
        );
        fs.admission_response = None;
        let ticket = AttachedObject {
            handle: 901,
            rights: TICKET_RIGHTS,
        };
        let resumed = service.handle_objects(
            peer,
            protocol::Header {
                flags: header.flags | protocol::MUTATION_ADMISSION_ATTACHED,
                ..header
            },
            &body,
            &[file(), ticket],
            &mut fs,
        );
        assert_eq!(resumed.response.header.status, 0);
        assert_eq!(
            resumed.handles.len(),
            usize::from(opcode == protocol::OP_OPEN_AT)
        );
        assert_eq!(fs.admission_calls.last(), Some(&(opcode, Some(ticket))));
        match opcode {
            protocol::OP_OPEN_AT => {
                let prepared = fs.request.unwrap();
                assert_eq!((prepared.effective_uid, prepared.effective_gid), (505, 24));
                assert_eq!(fs.directory, Some(file()));
            }
            protocol::OP_FTRUNCATE => {
                assert_eq!(fs.truncated, Some((file(), 5000)));
                assert_eq!(fs.truncate_ceiling, Some(protocol::RLIM_INFINITY));
            }
            _ => {
                let prepared = fs.truncate_request.unwrap();
                assert_eq!((prepared.effective_uid, prepared.effective_gid), (505, 24));
                assert_eq!(fs.directory, Some(file()));
            }
        }
    }
}

#[test]
fn attenuated_file_or_malformed_ticket_cannot_reach_the_backend() {
    let peer = PeerIdentity {
        process_id: 111,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(peer);
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_WAIT,
        TICKET_RIGHTS | mnu_abi::HANDLE_RIGHT_CONTROL,
    ] {
        let mut fs = RecordingFilesystem::default();
        let token = AttachedObject {
            handle: 900,
            rights,
        };
        let result = service.handle_objects(
            peer,
            protocol::Header {
                opcode: protocol::OP_FTRUNCATE,
                flags: protocol::MUTATION_ADMISSION | protocol::MUTATION_ADMISSION_ATTACHED,
                ..Default::default()
            },
            &payload(protocol::OP_FTRUNCATE),
            &[file(), token],
            &mut fs,
        );
        assert_eq!(result.response.header.status, -13);
        assert!(result.handles.is_empty() && fs.admission_calls.is_empty());
    }
    let mut fs = RecordingFilesystem::default();
    let mut read_only = file();
    read_only.rights &= !mnu_abi::HANDLE_RIGHT_WRITE;
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FTRUNCATE,
            flags: protocol::MUTATION_ADMISSION,
            ..Default::default()
        },
        &payload(protocol::OP_FTRUNCATE),
        &[read_only],
        &mut fs,
    );
    assert_eq!(result.response.header.status, -13);
    assert!(result.handles.is_empty() && fs.admission_calls.is_empty());
}

#[test]
fn ordinary_failures_are_not_replayed_and_malformed_wait_references_are_released() {
    let peer = PeerIdentity {
        process_id: 111,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(peer);
    for status in [
        -11,
        -5,
        protocol::STATUS_FILE_SIZE_LIMIT,
        protocol::STATUS_MEMORY_ADMISSION_BUSY,
    ] {
        let mut fs = RecordingFilesystem {
            admission_response: Some(Err(status)),
            ..Default::default()
        };
        let result = service.handle_objects(
            peer,
            protocol::Header {
                opcode: protocol::OP_FTRUNCATE,
                flags: protocol::MUTATION_ADMISSION,
                ..Default::default()
            },
            &payload(protocol::OP_FTRUNCATE),
            &[file()],
            &mut fs,
        );
        assert_eq!(
            result.response.header.status,
            if status == protocol::STATUS_MEMORY_ADMISSION_BUSY {
                -5
            } else {
                status
            }
        );
        assert!(result.handles.is_empty());
        assert_eq!(fs.admission_calls.len(), 1);
    }
    let bad = OpenedObject {
        handle: 900,
        rights: TICKET_RIGHTS | mnu_abi::HANDLE_RIGHT_READ,
    };
    let mut fs = RecordingFilesystem {
        admission_response: Some(Ok(bad)),
        ..Default::default()
    };
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FTRUNCATE,
            flags: protocol::MUTATION_ADMISSION,
            ..Default::default()
        },
        &payload(protocol::OP_FTRUNCATE),
        &[file()],
        &mut fs,
    );
    assert_eq!(result.response.header.status, -5);
    assert!(result.handles.is_empty());
    assert_eq!(
        fs.released,
        [AttachedObject {
            handle: bad.handle,
            rights: bad.rights
        }]
    );
}

#[test]
fn only_the_three_mutations_accept_the_envelope_and_unknown_flags_fail_closed() {
    use posix_service::mutation_admission::Request;
    let ticket = AttachedObject {
        handle: 900,
        rights: TICKET_RIGHTS,
    };
    for (opcode, flags, status, expected) in [
        (
            protocol::OP_FTRUNCATE,
            protocol::MUTATION_ADMISSION_ATTACHED,
            0,
            -22,
        ),
        (
            protocol::OP_FTRUNCATE,
            protocol::MUTATION_ADMISSION | protocol::MUTATION_ADMISSION_ATTACHED,
            0,
            -22,
        ),
        (protocol::OP_FSYNC, protocol::MUTATION_ADMISSION, 0, -22),
        (
            protocol::OP_FTRUNCATE,
            protocol::MUTATION_ADMISSION | 1,
            0,
            -22,
        ),
        (
            protocol::OP_FTRUNCATE,
            protocol::MUTATION_ADMISSION,
            -5,
            -22,
        ),
    ] {
        assert_eq!(
            Request::<u32>::decode(
                protocol::Header {
                    opcode,
                    flags,
                    status,
                    ..Default::default()
                },
                &[]
            )
            .err(),
            Some(expected)
        );
    }
    let attached = [file(), ticket];
    let parsed = Request::decode(
        protocol::Header {
            opcode: protocol::OP_FTRUNCATE,
            flags: protocol::MUTATION_ADMISSION | protocol::MUTATION_ADMISSION_ATTACHED,
            ..Default::default()
        },
        &attached,
    )
    .unwrap();
    assert_eq!(parsed.sources, &[file()]);
    assert_eq!(parsed.admission, Some(Some(ticket)));
    assert_eq!(attached, [file(), ticket]);
}
