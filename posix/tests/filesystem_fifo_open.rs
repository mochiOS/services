use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
use mochios_filesystem_protocol as fs;
use mochios_posix_protocol as posix;
use posix_service::{
    MutationError, OpenCompletion, OpenedObject, PreparedOpen, fifo::Access, filesystem_open,
};
fn prepared(options: u32) -> PreparedOpen {
    PreparedOpen {
        base: posix::OpenBase::ProcessRoot,
        options,
        mode: 0,
        path: b"/fifo".to_vec(),
        effective_uid: 501,
        effective_gid: 20,
        supplementary_groups: vec![],
    }
}
fn reply(fifo: bool) -> (fs::Header, Vec<u8>, IpcObjectHandles) {
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle: 7,
        reserved: 0,
        rights: if fifo {
            posix_service::fifo_inode::METADATA_RIGHTS
        } else {
            mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER
        },
    };
    let mut header = fs::Header {
        opcode: fs::OP_STATUS,
        request_id: 31,
        open_id: 4,
        node_id: (1 << 32) | 9,
        ..Default::default()
    };
    let mut payload = Vec::new();
    if fifo {
        header.flags = fs::OPEN_REPLY_FIFO;
        payload.resize(fs::NODE_STATUS_LEN, 0);
        fs::encode_node_status(
            fs::NodeStatus {
                node_id: header.node_id,
                device: 1,
                kind: fs::NODE_TYPE_FIFO,
                mode: 0o600,
                ..Default::default()
            },
            &mut payload,
        )
        .unwrap();
        header.length = payload.len() as u32;
    }
    (header, payload, objects)
}
#[test]
fn ordinary_and_admission_wait_results_keep_their_original_ownership_contract() {
    let (header, payload, mut objects) = reply(false);
    let expected = objects.handles[0];
    let result = filesystem_open::finish(
        header,
        31,
        &payload,
        &mut objects,
        &prepared(posix::OPEN_READ),
        |_, _, _, _, _| panic!("ordinary file"),
    )
    .unwrap_or_else(|_| panic!("open failed"));
    assert!(matches!(
        result,
        OpenCompletion::Ready(OpenedObject { handle: 7, .. })
    ));
    assert_eq!(objects.count, 0);
    assert_ne!(expected.rights, 0);
    let mut header = header;
    header.status = -fs::ERROR_MEMORY_ADMISSION_BUSY;
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle: 9,
        reserved: 0,
        rights: posix_service::mutation_admission::TICKET_RIGHTS,
    };
    let result = filesystem_open::finish(
        header,
        31,
        &[],
        &mut objects,
        &prepared(posix::OPEN_READ),
        |_, _, _, _, _| panic!("storage ticket"),
    );
    assert!(matches!(
        result,
        Err(MutationError::Wait(OpenedObject { handle: 9, .. }))
    ));
    assert_eq!(objects.count, 0);
}
#[test]
fn retained_fifo_transfers_exact_metadata_and_authenticated_open_direction() {
    for (options, access, nonblocking) in [
        (posix::OPEN_READ, Access::Read, false),
        (
            posix::OPEN_WRITE | posix::OPEN_NONBLOCK,
            Access::Write,
            true,
        ),
    ] {
        let (header, payload, mut objects) = reply(true);
        let result = filesystem_open::finish(
            header,
            31,
            &payload,
            &mut objects,
            &prepared(options),
            |reply, body, metadata, direction, mode| {
                assert_eq!(reply, header);
                assert_eq!(body, payload);
                assert_eq!(metadata.count, 1);
                assert_eq!(metadata.handles[0].handle, 7);
                assert_eq!((direction, mode), (access, nonblocking));
                Ok(OpenCompletion::Ready(OpenedObject {
                    handle: 90,
                    rights: posix::fifo::data_rights(options).unwrap(),
                }))
            },
        )
        .unwrap_or_else(|_| panic!("admission failed"));
        assert_eq!(objects.count, 0);
        assert!(matches!(
            result,
            OpenCompletion::Ready(OpenedObject { handle: 90, .. })
        ));
    }
    let (header, payload, mut objects) = reply(true);
    assert!(matches!(
        filesystem_open::finish(
            header,
            31,
            &payload,
            &mut objects,
            &prepared(posix::OPEN_READ),
            |_, _, owned, _, _| {
                assert_eq!(owned.count, 1);
                Err(-12)
            }
        ),
        Err(MutationError::Failed(-12))
    ));
    assert_eq!(objects.count, 0, "consumed on callback failure too");
}
#[test]
fn malformed_fifo_reply_and_ambiguous_direction_leave_owned_refs_for_cleanup() {
    for case in 0..8 {
        let (mut header, mut payload, mut objects) = reply(true);
        let mut options = posix::OPEN_READ;
        match case {
            0 => header.request_id += 1,
            1 => header.flags |= 2,
            2 => {
                payload.pop();
            }
            3 => objects.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
            4 => objects.handles[0].rights |= mnu_abi::HANDLE_RIGHT_READ,
            5 => options |= posix::OPEN_WRITE,
            6 => header.node_id += 1,
            7 => header.status = -13,
            _ => unreachable!(),
        }
        assert!(
            filesystem_open::finish(
                header,
                31,
                &payload,
                &mut objects,
                &prepared(options),
                |_, _, _, _, _| panic!("no data authority from malformed reply")
            )
            .is_err()
        );
        assert_eq!(objects.count, 1);
        assert_eq!(objects.handles[0].handle, 7);
    }
}
