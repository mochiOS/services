use super::*;
use mochios_posix_client::StatAtBase;
use protocol::file_time::{self as time, Change, Update};

const CONTROL: u64 = mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER;

fn explicit() -> Update {
    Update {
        access: Change::Set {
            seconds: -1,
            nanoseconds: 123_456_789,
        },
        modification: Change::Set {
            seconds: 2_147_483_648,
            nanoseconds: 987_654_321,
        },
    }
}

struct Loopback {
    service: RefCell<PosixService>,
    filesystem: RefCell<RecordingFilesystem>,
    peer: PeerIdentity,
    calls: std::cell::Cell<usize>,
    extra_reply: std::cell::Cell<Option<u32>>,
    closed: RefCell<Vec<u32>>,
}

impl Transport for Loopback {
    type Error = ();
    fn call(&self, bytes: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(bytes).unwrap();
        let reply = self.service.borrow_mut().handle(self.peer, header, payload);
        protocol::encode(reply.header, &reply.payload, output).map_err(|_| ())
    }
}
impl ObjectTransport for Loopback {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        bytes: &[u8],
        output: &mut [u8],
        objects: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        self.calls.set(self.calls.get() + 1);
        let (header, payload) = protocol::decode(bytes).unwrap();
        let handles: Vec<_> = objects
            .iter()
            .map(|object| AttachedObject {
                handle: object.handle,
                rights: object.rights,
            })
            .collect();
        let reply = self.service.borrow_mut().handle_objects(
            self.peer,
            header,
            payload,
            &handles,
            &mut *self.filesystem.borrow_mut(),
        );
        objects.clear();
        for object in reply.handles {
            objects
                .push(ObjectHandleAttachment {
                    handle: object.handle,
                    rights: object.rights,
                })
                .unwrap();
        }
        if let Some(handle) = self.extra_reply.take() {
            objects
                .push(ObjectHandleAttachment {
                    handle,
                    rights: CONTROL,
                })
                .unwrap();
        }
        protocol::encode(reply.response.header, &reply.response.payload, output).map_err(|_| ())
    }
}

fn client() -> Client<Loopback> {
    // Peer UID/GID deliberately stay zero after POSIX credentials change.
    let peer = PeerIdentity {
        process_id: 850,
        effective_uid: 0,
        effective_gid: 0,
    };
    let client = Client::new(Loopback {
        service: RefCell::new(service_for(peer)),
        filesystem: RefCell::new(RecordingFilesystem::default()),
        peer,
        calls: std::cell::Cell::new(0),
        extra_reply: std::cell::Cell::new(None),
        closed: RefCell::new(Vec::new()),
    });
    client.register_session().unwrap();
    client.set_groups(&[77, 88]).unwrap();
    client.set_real_effective_gid(20, 42).unwrap();
    client.set_real_effective_uid(501, 502).unwrap();
    client
}

#[test]
fn file_time_wire_preserves_signed_seconds_and_rejects_noncanonical_or_malformed_data() {
    for access in [
        Change::Now,
        Change::Omit,
        Change::Set {
            seconds: i64::MIN,
            nanoseconds: 0,
        },
        Change::Set {
            seconds: i64::MAX,
            nanoseconds: 999_999_999,
        },
    ] {
        for modification in [Change::Now, Change::Omit, explicit().modification] {
            let value = Update {
                access,
                modification,
            };
            let mut bytes = [0; time::UPDATE_LEN];
            assert_eq!(time::encode(value, &mut bytes), Ok(time::UPDATE_LEN));
            assert_eq!(time::decode(&bytes), Ok(value));
            for length in 0..time::UPDATE_LEN {
                assert!(time::decode(&bytes[..length]).is_err());
                assert!(time::encode(value, &mut bytes[..length]).is_err());
            }
            assert!(time::decode(&[bytes.as_slice(), b"x"].concat()).is_err());
            let provider = posix_service::filesystem_times::translate(value);
            let mut encoded_provider = [0; filesystem_protocol::TIME_UPDATE_LEN];
            filesystem_protocol::encode_time_update(provider, &mut encoded_provider).unwrap();
            assert_eq!(encoded_provider, bytes);
            assert_eq!(
                filesystem_protocol::decode_time_update(&encoded_provider)
                    .unwrap()
                    .0,
                provider
            );
        }
    }
    let mut bytes = [0; time::UPDATE_LEN];
    time::encode(Update::now(), &mut bytes).unwrap();
    for start in [0, 16] {
        for tag in [3u32, u32::MAX] {
            let mut invalid = bytes;
            invalid[start..start + 4].copy_from_slice(&tag.to_le_bytes());
            assert!(time::decode(&invalid).is_err());
        }
        for offset in start + 4..start + 16 {
            let mut invalid = bytes;
            invalid[offset] = 1;
            assert!(time::decode(&invalid).is_err());
        }
    }
    assert!(
        time::encode(
            Update {
                access: Change::Set {
                    seconds: 0,
                    nanoseconds: 1_000_000_000
                },
                modification: Change::Now
            },
            &mut bytes
        )
        .is_err()
    );
}

#[test]
fn path_frame_validates_bounds_flags_reserved_bytes_and_raw_names() {
    let request = time::AtRequest {
        target: protocol::StatAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            flags: protocol::STAT_NOFOLLOW,
            path: b"space and raw\xff",
        },
        times: explicit(),
    };
    let mut output = [0; 128];
    let length = time::encode_at(request, &mut output).unwrap();
    assert_eq!(time::decode_at(&output[..length]), Ok(request));
    for size in 0..length {
        assert!(time::decode_at(&output[..size]).is_err());
    }
    for offset in [
        time::UPDATE_LEN,
        time::UPDATE_LEN + 1,
        time::UPDATE_LEN + 2,
        time::UPDATE_LEN + 3,
        time::UPDATE_LEN + 7,
    ] {
        let mut bad = output;
        bad[offset] = 0xff;
        assert!(time::decode_at(&bad[..length]).is_err());
    }
    let mut bad = output;
    bad[length - 1] = 0;
    assert!(time::decode_at(&bad[..length]).is_err());
    assert!(time::decode_at(&output[..length + 1]).is_err());
    assert!(
        time::encode_at(
            time::AtRequest {
                target: protocol::StatAtRequest {
                    path: b"",
                    ..request.target
                },
                ..request
            },
            &mut output
        )
        .is_err()
    );
}

#[test]
fn path_and_handle_client_routes_use_stored_credentials_and_explicit_authority() {
    let client = client();
    let directory = ObjectHandleAttachment {
        handle: 901,
        rights: 0x81,
    };
    for (base, expected) in [
        (StatAtBase::ProcessRoot, None),
        (StatAtBase::ProcessCwd, Some(101)),
        (StatAtBase::Directory(directory), Some(901)),
    ] {
        client
            .utimens_at(
                base,
                b"link/../raw\xff",
                explicit(),
                protocol::STAT_NOFOLLOW,
            )
            .unwrap();
        let filesystem = client.transport().filesystem.borrow();
        let request = filesystem.time_request.as_ref().unwrap();
        assert_eq!(request.target.path, b"link/../raw\xff");
        assert_eq!(request.target.flags, protocol::STAT_NOFOLLOW);
        assert_eq!(
            (request.target.effective_uid, request.target.effective_gid),
            (502, 42)
        );
        assert_eq!(request.target.supplementary_groups, [77, 88]);
        assert_eq!(request.times, explicit());
        assert_eq!(filesystem.root.unwrap().handle, 100);
        assert_eq!(
            filesystem.directory.map(|directory| directory.handle),
            expected
        );
        assert!(
            filesystem.stat_request.is_none(),
            "must not stat then update"
        );
    }
    let file = ObjectHandleAttachment {
        handle: 902,
        rights: CONTROL | mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE,
    };
    client.futimens(file, explicit()).unwrap();
    let filesystem = client.transport().filesystem.borrow();
    let (received, times, uid, gid, groups) = filesystem.time_file.as_ref().unwrap();
    assert_eq!((received.handle, received.rights), (902, CONTROL));
    assert_eq!(*times, explicit());
    assert_eq!((*uid, *gid), (502, 42));
    assert_eq!(groups, &[77, 88]);
    assert!(filesystem.stat_file.is_none());
}

#[test]
fn invalid_client_requests_do_not_call_transport_or_amplify_handle_rights() {
    let client = client();
    let invalid = Update {
        access: Change::Set {
            seconds: 0,
            nanoseconds: u32::MAX,
        },
        modification: Change::Omit,
    };
    let file = ObjectHandleAttachment {
        handle: 902,
        rights: CONTROL,
    };
    assert!(client.futimens(file, invalid).is_err());
    assert!(
        client
            .utimens_at(StatAtBase::ProcessCwd, b"target", invalid, 0)
            .is_err()
    );
    assert!(
        client
            .utimens_at(StatAtBase::ProcessCwd, b"bad\0path", Update::now(), 0)
            .is_err()
    );
    assert!(
        client
            .utimens_at(StatAtBase::ProcessCwd, b"target", Update::now(), 1 << 30)
            .is_err()
    );
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_CONTROL,
        mnu_abi::HANDLE_RIGHT_TRANSFER,
        mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_TRANSFER,
    ] {
        assert_eq!(
            client.futimens(
                ObjectHandleAttachment {
                    handle: 902,
                    rights
                },
                Update::now()
            ),
            Err(ClientError::Remote(-13))
        );
    }
    assert_eq!(client.transport().calls.get(), 0);
}

#[test]
fn service_rejects_missing_sessions_authority_and_extra_or_invalid_payloads() {
    let peer = PeerIdentity {
        process_id: 851,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(peer);
    let mut filesystem = RecordingFilesystem::default();
    let file = AttachedObject {
        handle: 902,
        rights: CONTROL,
    };
    let mut payload = [0; time::UPDATE_LEN];
    time::encode(Update::now(), &mut payload).unwrap();
    for (objects, flags, bytes, expected) in [
        (vec![], 0, payload.to_vec(), -22),
        (vec![file, file], 0, payload.to_vec(), -22),
        (
            vec![AttachedObject {
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
                ..file
            }],
            0,
            payload.to_vec(),
            -13,
        ),
        (vec![file], 1, payload.to_vec(), -22),
        (vec![file], 0, payload[..31].to_vec(), -22),
        (vec![file], 0, [payload.as_slice(), b"extra"].concat(), -22),
    ] {
        let result = service.handle_objects(
            peer,
            protocol::Header {
                opcode: protocol::OP_FUTIMENS,
                flags,
                ..Default::default()
            },
            &bytes,
            &objects,
            &mut filesystem,
        );
        assert_eq!(result.response.header.status, expected);
        assert!(filesystem.time_file.is_none());
    }
    let mut missing = PosixService::new();
    let result = missing.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FUTIMENS,
            ..Default::default()
        },
        &payload,
        &[file],
        &mut filesystem,
    );
    assert_eq!(result.response.header.status, protocol::STATUS_ESRCH);
    for (base, objects) in [
        (protocol::OpenBase::AttachedDirectory, vec![]),
        (protocol::OpenBase::ProcessRoot, vec![file]),
        (protocol::OpenBase::ProcessCwd, vec![file, file]),
    ] {
        let mut payload = [0; 128];
        let length = time::encode_at(
            time::AtRequest {
                target: protocol::StatAtRequest {
                    base,
                    path: b"target",
                    flags: 0,
                },
                times: explicit(),
            },
            &mut payload,
        )
        .unwrap();
        let result = service.handle_objects(
            peer,
            protocol::Header {
                opcode: protocol::OP_UTIMENS_AT,
                ..Default::default()
            },
            &payload[..length],
            &objects,
            &mut filesystem,
        );
        assert_eq!(result.response.header.status, -22);
        assert!(filesystem.time_request.is_none());
    }
}

#[test]
fn remote_failures_are_preserved_and_unexpected_reply_handles_are_closed_once() {
    let client = client();
    let file = ObjectHandleAttachment {
        handle: 902,
        rights: CONTROL,
    };
    for status in [-1, -5, -13, -30, -75] {
        client.transport().filesystem.borrow_mut().time_error = Some(status);
        assert_eq!(
            client.futimens(file, explicit()),
            Err(ClientError::Remote(status))
        );
        assert_eq!(
            client.utimens_at(StatAtBase::ProcessRoot, b"/target", explicit(), 0),
            Err(ClientError::Remote(status))
        );
    }
    client.transport().filesystem.borrow_mut().time_error = None;
    for path in [false, true] {
        client.transport().extra_reply.set(Some(999));
        let result = if path {
            client.utimens_at(StatAtBase::ProcessRoot, b"/target", explicit(), 0)
        } else {
            client.futimens(file, explicit())
        };
        assert!(result.is_err());
    }
    assert_eq!(*client.transport().closed.borrow(), [999, 999]);
}
