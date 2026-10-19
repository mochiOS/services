//! Isolated POSIX-role provider probe, launched with the real delegated
//! filesystem control endpoint. This does not pretend to implement posix.service
//! or publish READY. It exits after testing the filesystem IPC boundary.

#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("filesystem-times: SKIP (requires isolated mochiOS POSIX-role fixture)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform::{self as platform, handle, ipc};
    use mochios_filesystem_protocol::{
        self as wire, FileTimeUpdate as Update, TimestampUpdate as Field,
    };

    fn objects(file: Option<(u32, u64)>) -> ipc::IpcObjectHandles {
        let mut objects = ipc::IpcObjectHandles::default();
        if let Some((handle, rights)) = file {
            objects.count = 1;
            objects.handles[0] = ipc::IpcObjectHandle {
                handle,
                reserved: 0,
                rights,
            };
        }
        objects
    }
    fn rpc(
        endpoint: u32,
        mut header: wire::Header,
        payload: &[u8],
        objects: &mut ipc::IpcObjectHandles,
    ) -> (wire::Header, Vec<u8>) {
        let mut request = [0; 1024];
        header.length = u32::try_from(payload.len()).unwrap();
        let length = wire::encode(header, payload, &mut request).unwrap();
        let mut response = [0; 1024];
        let result = posix_service::filesystem_transport::call_native(objects, |objects| {
            ipc::call_object_handles(endpoint, &request[..length], &mut response, objects)
        })
        .unwrap();
        let (reply, payload) =
            posix_service::filesystem_transport::reply_frame(&response, result, header.request_id)
                .unwrap();
        assert_eq!(objects.delivery_flags, 0);
        if header.opcode != wire::OP_OPEN_AT {
            assert_eq!(objects.count, 0);
        }
        (reply, payload.to_vec())
    }
    fn credential_payload(uid: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = [0; 512];
        let length = wire::encode_credentials_payload(uid, 0, &[], body, &mut bytes).unwrap();
        bytes[..length].to_vec()
    }
    fn times_payload(uid: u32, times: Update, path: &[u8]) -> Vec<u8> {
        let mut body = vec![0; wire::TIME_UPDATE_LEN];
        wire::encode_time_update(times, &mut body).unwrap();
        body.extend_from_slice(path);
        credential_payload(uid, &body)
    }
    fn header(opcode: u16) -> wire::Header {
        wire::Header {
            opcode,
            request_id: 77,
            ..Default::default()
        }
    }
    fn stat(endpoint: u32, file: u32, rights: u64) -> wire::NodeStatus {
        let (reply, payload) = rpc(
            endpoint,
            header(wire::OP_STAT_HANDLE),
            &[],
            &mut objects(Some((file, rights))),
        );
        assert_eq!(reply.status, 0);
        wire::decode_node_status(&payload).unwrap()
    }

    platform::io::stdout(b"filesystem-times: starting real provider IPC\n").unwrap();
    let endpoint = handle::inherited(wire::CONTROL_HANDLE_KEY).unwrap();
    assert_ne!(endpoint, 0);
    // The POSIX-role probe itself has no realtime clock capability. NOW must
    // be supplied by filesystem.service, not by a client's self-reported time.
    assert_eq!(
        platform::time::utc_seconds().unwrap_err().native_error(),
        Some(platform::syscall::NativeError::AccessDenied)
    );
    let path = b"/tmp/native-filesystem-times";
    let mut created = objects(None);
    let (reply, _) = rpc(
        endpoint,
        wire::Header {
            flags: wire::OPEN_AT_READ
                | wire::OPEN_AT_WRITE
                | wire::OPEN_AT_CREATE
                | wire::OPEN_AT_EXCLUSIVE,
            mode: 0o600,
            ..header(wire::OP_OPEN_AT)
        },
        &credential_payload(0, path),
        &mut created,
    );
    assert_eq!(reply.status, 0);
    assert_eq!(created.count, 1);
    let file = created.handles[0].handle;
    let rights = created.handles[0].rights;
    let open_id = reply.open_id;
    let (reply, _) = rpc(
        endpoint,
        wire::Header {
            node_id: 1001,
            ..header(wire::OP_CHOWN_HANDLE)
        },
        &credential_payload(0, &[]),
        &mut objects(Some((file, rights))),
    );
    assert_eq!(reply.status, 0);
    let explicit = Update {
        access: Field::Set {
            seconds: -1,
            nanoseconds: 123_456_789,
        },
        modification: Field::Set {
            seconds: 2_147_483_648,
            nanoseconds: 987_654_321,
        },
    };
    let (reply, _) = rpc(
        endpoint,
        header(wire::OP_SET_TIMES_AT),
        &times_payload(1001, explicit, path),
        &mut objects(None),
    );
    assert_eq!(reply.status, 0);
    let before = stat(endpoint, file, rights);
    assert_eq!(
        (before.access_time_seconds, before.access_time_nanoseconds),
        (-1, 123_456_789)
    );
    assert_eq!(
        (
            before.modification_time_seconds,
            before.modification_time_nanoseconds
        ),
        (2_147_483_648, 987_654_321)
    );
    for (uid, update, expected) in [
        (2002, explicit, -1),
        (
            2002,
            Update {
                access: Field::Now,
                modification: Field::Now,
            },
            -13,
        ),
        (
            2002,
            Update {
                access: Field::Omit,
                modification: Field::Omit,
            },
            0,
        ),
    ] {
        let (reply, _) = rpc(
            endpoint,
            header(wire::OP_SET_TIMES_HANDLE),
            &times_payload(uid, update, &[]),
            &mut objects(Some((file, rights))),
        );
        assert_eq!(reply.status, expected);
        assert_eq!(stat(endpoint, file, rights), before);
    }
    // A claimed uid-zero credential does not replace explicit Handle authority.
    let limited_rights = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER;
    let limited = handle::duplicate(file, limited_rights).unwrap();
    let (reply, _) = rpc(
        endpoint,
        wire::Header {
            open_id,
            ..header(wire::OP_SET_TIMES_HANDLE)
        },
        &times_payload(0, explicit, &[]),
        &mut objects(Some((limited, limited_rights))),
    );
    assert_eq!(reply.status, -13);
    assert_eq!(stat(endpoint, file, rights), before);
    handle::close(limited).unwrap();
    // Malformed trailing data on the Handle form must not become a pathname.
    let (reply, _) = rpc(
        endpoint,
        header(wire::OP_SET_TIMES_HANDLE),
        &times_payload(1001, explicit, b"unexpected"),
        &mut objects(Some((file, rights))),
    );
    assert_eq!(reply.status, -22);
    assert_eq!(stat(endpoint, file, rights), before);
    let (reply, _) = rpc(
        endpoint,
        header(wire::OP_UNLINK_AT),
        &credential_payload(0, path),
        &mut objects(None),
    );
    assert_eq!(reply.status, 0);
    let (reply, _) = rpc(
        endpoint,
        header(wire::OP_SET_TIMES_HANDLE),
        &times_payload(
            1001,
            Update {
                access: Field::Now,
                modification: Field::Now,
            },
            &[],
        ),
        &mut objects(Some((file, rights))),
    );
    assert_eq!(reply.status, 0);
    let after = stat(endpoint, file, rights);
    assert_eq!(
        (after.access_time_seconds, after.access_time_nanoseconds),
        (
            after.modification_time_seconds,
            after.modification_time_nanoseconds
        )
    );
    assert_eq!(
        (after.access_time_seconds, after.access_time_nanoseconds),
        (after.change_time_seconds, after.change_time_nanoseconds)
    );
    assert_ne!(
        after.modification_time_seconds,
        before.modification_time_seconds
    );
    handle::close(file).unwrap();
    platform::io::stdout(b"filesystem-times: PASS explicit signed dates, provider NOW, OMIT, permissions, attenuated authority, malformed payload and unlinked Handle\n").unwrap();
}
