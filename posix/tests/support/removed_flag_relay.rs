use super::*;

// Currently unassigned wire values, exercised without exporting or reserving
// obsolete operation constants in the public protocol.
const UNASSIGNED: [u16; 3] = [16, 17, 90];

#[test]
fn request_recognition_agrees_with_all_exported_operations_and_excludes_responses() {
    let source = include_str!("../../../../user/crates/posix-protocol/src/lib.rs");
    let assigned: std::collections::BTreeSet<u16> = source
        .lines()
        .chain(include_str!("../../../../user/crates/posix-protocol/src/read_scope.rs").lines())
        .filter_map(|line| {
            let line = line.strip_prefix("pub const OP_")?;
            let (name, value) = line.split_once(": u16 = ")?;
            if name == "STATUS" {
                return None;
            }
            Some(value.trim_end_matches(';').parse::<u16>().unwrap())
        })
        .collect();
    for opcode in 0..=u16::MAX {
        assert_eq!(
            protocol::is_request_opcode(opcode),
            assigned.contains(&opcode),
            "{opcode}"
        );
    }
    assert!(!protocol::is_request_opcode(protocol::OP_STATUS));
}

#[test]
fn old_flag_messages_are_unknown_and_never_forward_to_a_filesystem() {
    let peer = PeerIdentity {
        process_id: 118,
        effective_uid: 506,
        effective_gid: 25,
    };
    let mut service = service_for(peer);
    let file = AttachedObject {
        handle: 60,
        rights: mnu_abi::HANDLE_RIGHT_ALL,
    };
    let mut filesystem = RecordingFilesystem {
        file_hook: Some(Box::new(|_| panic!("no flag relay backend exists"))),
        root_hook: Some(Box::new(|| panic!("no pathname lookup is allowed"))),
        ..Default::default()
    };
    for opcode in UNASSIGNED {
        assert!(!posix_service::file_request::supports(opcode));
        assert_eq!(protocol::file_mutation_rights(opcode), None);
        for payload in [
            vec![],
            protocol::OPEN_APPEND.to_le_bytes().to_vec(),
            vec![0; 8],
        ] {
            let header = protocol::Header {
                opcode,
                request_id: 72,
                payload_len: payload.len() as u32,
                ..Default::default()
            };
            assert_eq!(
                service.handle(peer, header, &payload).header.status,
                protocol::STATUS_ENOSYS
            );
            for handles in [&[][..], &[file][..]] {
                let reply =
                    service.handle_objects(peer, header, &payload, handles, &mut filesystem);
                assert_eq!(reply.response.header.status, protocol::STATUS_ENOSYS);
                assert_eq!(reply.response.header.request_id, 72);
                assert!(reply.response.payload.is_empty());
                assert!(reply.handles.is_empty());
            }
        }
    }
    assert_eq!(filesystem.roots_opened, 0);
    assert!(filesystem.released.is_empty());
    assert!(filesystem.synced.is_none());
    assert!(filesystem.truncated.is_none());
}

#[test]
fn unsupported_file_request_cannot_enter_any_mutation_backend() {
    let peer = PeerIdentity {
        process_id: 119,
        effective_uid: 501,
        effective_gid: 20,
    };
    let state = std::sync::Mutex::new(service_for(peer));
    let mut filesystem = RecordingFilesystem {
        file_hook: Some(Box::new(|_| panic!("unassigned opcode reached a backend"))),
        ..Default::default()
    };
    for opcode in UNASSIGNED {
        let header = protocol::Header {
            opcode,
            request_id: 73,
            ..Default::default()
        };
        let reply =
            posix_service::file_request::execute(&state, peer, header, &[], &[], &mut filesystem);
        assert_eq!(reply.response.header.status, protocol::STATUS_ENOSYS);
        assert!(reply.response.payload.is_empty() && reply.handles.is_empty());
    }
    assert!(filesystem.released.is_empty());
}
