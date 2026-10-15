use filesystem_service::admission_ipc::{Request, TICKET_RIGHTS, reply_attachment, requested};
use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
use mochios_filesystem_protocol as wire;

#[test]
fn freestanding_probe_tracks_authoritative_native_and_filesystem_abis() {
    let source = include_str!("native_filesystem_admission.c");
    use mnu_abi::SyscallNumber as Number;
    for (name, number) in [
        ("PROCESS_EXIT", Number::ProcessExit),
        ("HANDLE_CLOSE", Number::HandleClose),
        ("LAUNCH_HANDLE_GET", Number::LaunchHandleGet),
        ("ENDPOINT_CREATE", Number::IpcCreateHandle),
        ("IPC_CALL", Number::IpcCallObjectHandles),
        ("HANDLE_SEEK", Number::HandleSeek),
        ("HANDLE_WAIT_MANY", Number::HandleWaitMany),
        ("DEBUG_WRITE", Number::DebugWrite),
        ("HANDLE_RIGHTS_GET", Number::HandleRightsGet),
        (
            "MEMORY_ADMISSION_CREATE",
            Number::ProviderMemoryAdmissionCreate,
        ),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
    for (name, opcode) in [
        ("OPEN_AT", wire::OP_OPEN_AT),
        ("TRUNCATE_HANDLE", wire::OP_TRUNCATE_HANDLE),
        ("TRUNCATE_AT", wire::OP_TRUNCATE_AT),
        ("UNLINK_AT", wire::OP_UNLINK_AT),
    ] {
        assert!(source.contains(&format!("{name} = {opcode}")));
    }
    assert_eq!(wire::MUTATION_ADMISSION, 1 << 31);
    assert_eq!(wire::MUTATION_ADMISSION_ATTACHED, 1 << 30);
    assert_eq!(wire::ERROR_MEMORY_ADMISSION_BUSY, 0x10002);
    assert_eq!(wire::CONTROL_HANDLE_KEY, 0x4c5254433153464d);
}

fn message(opcode: u16, sources: usize, ticket: bool) -> (wire::Header, IpcObjectHandles) {
    let header = wire::Header {
        opcode,
        flags: wire::MUTATION_ADMISSION
            | if ticket {
                wire::MUTATION_ADMISSION_ATTACHED
            } else {
                0
            }
            | wire::TRUNCATE_GROWTH_BOUNDED,
        request_id: 123,
        open_id: 8192,
        node_id: 5000,
        ..Default::default()
    };
    let mut handles = IpcObjectHandles::default();
    handles.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    for index in 0..sources {
        handles.handles[index] = IpcObjectHandle {
            handle: 10 + index as u32,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        };
    }
    handles.count = sources as u32;
    if ticket {
        handles.handles[sources] = IpcObjectHandle {
            handle: 42,
            reserved: 0,
            rights: TICKET_RIGHTS,
        };
        handles.count += 1;
    }
    (header, handles)
}

#[test]
fn envelope_removes_only_transport_flags_and_trailing_borrowed_ticket() {
    for opcode in [
        wire::OP_OPEN_AT,
        wire::OP_TRUNCATE_HANDLE,
        wire::OP_TRUNCATE_AT,
    ] {
        for sources in 0..=3 {
            for ticket in [false, true] {
                let (header, received) = message(opcode, sources, ticket);
                let original = received;
                assert!(requested(header));
                let request = Request::decode(header, &received).unwrap();
                assert_eq!(request.header.flags, wire::TRUNCATE_GROWTH_BOUNDED);
                assert_eq!(request.header.opcode, opcode);
                assert_eq!(request.header.request_id, 123);
                assert_eq!(request.header.open_id, 8192);
                assert_eq!(request.header.node_id, 5000);
                assert_eq!(request.ticket, ticket.then_some(42));
                assert_eq!(request.sources.count, sources as u32);
                assert_eq!(request.sources.delivery_flags, received.delivery_flags);
                assert_eq!(
                    request.sources.handles[..sources],
                    received.handles[..sources]
                );
                if ticket {
                    assert_eq!(request.sources.handles[sources], IpcObjectHandle::default());
                }
                assert_eq!(
                    received, original,
                    "original cleanup still owns all references"
                );
            }
        }
    }
}

#[test]
fn delivery_proof_is_required_even_for_the_control_endpoint_protocol() {
    for delivery in [0, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, u32::MAX] {
        let (header, mut received) = message(wire::OP_TRUNCATE_HANDLE, 1, true);
        received.delivery_flags = delivery;
        assert_eq!(Request::decode(header, &received).err(), Some(13));
    }
}

#[test]
fn unrelated_operations_and_missing_opt_in_are_rejected() {
    for opcode in [
        wire::OP_READ,
        wire::OP_SYNC,
        wire::OP_STAT_AT,
        wire::OP_CREATE_SOCKET_AT,
    ] {
        let (header, received) = message(opcode, 0, true);
        assert_eq!(Request::decode(header, &received).err(), Some(22));
    }
    let (mut header, received) = message(wire::OP_OPEN_AT, 0, true);
    header.flags &= !wire::MUTATION_ADMISSION;
    assert!(requested(header));
    assert_eq!(Request::decode(header, &received).err(), Some(22));
    header.flags = 0;
    assert!(!requested(header));
    assert_eq!(Request::decode(header, &received).err(), Some(22));
}

#[test]
fn ticket_requires_exact_wait_transfer_rights_without_surplus_authority() {
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_WAIT,
        mnu_abi::HANDLE_RIGHT_TRANSFER,
        TICKET_RIGHTS | mnu_abi::HANDLE_RIGHT_READ,
        TICKET_RIGHTS | mnu_abi::HANDLE_RIGHT_WRITE,
        TICKET_RIGHTS | mnu_abi::HANDLE_RIGHT_CONTROL,
        TICKET_RIGHTS | mnu_abi::HANDLE_RIGHT_DUPLICATE,
        mnu_abi::HANDLE_RIGHT_ALL,
    ] {
        let (header, mut received) = message(wire::OP_TRUNCATE_HANDLE, 1, true);
        received.handles[1].rights = rights;
        assert_eq!(Request::decode(header, &received).err(), Some(13));
    }
}

#[test]
fn malformed_counts_null_reserved_and_aliases_are_rejected() {
    let (header, mut received) = message(wire::OP_TRUNCATE_HANDLE, 1, true);
    received.count = 0;
    assert_eq!(Request::decode(header, &received).err(), Some(22));
    received.count = received.handles.len() as u32 + 1;
    assert_eq!(Request::decode(header, &received).err(), Some(22));
    received.count = 2;
    received.handles[1].reserved = 1;
    assert_eq!(Request::decode(header, &received).err(), Some(13));
    received.handles[1].reserved = 0;
    received.handles[1].handle = 0;
    assert_eq!(Request::decode(header, &received).err(), Some(13));
    received.handles[1].handle = received.handles[0].handle;
    assert_eq!(Request::decode(header, &received).err(), Some(22));
}

#[test]
fn reply_carries_one_attenuated_reference_and_no_delivery_proof() {
    let reply = reply_attachment(42);
    assert_eq!(reply.count, 1);
    assert_eq!(reply.delivery_flags, 0);
    assert_eq!(
        reply.handles[0],
        IpcObjectHandle {
            handle: 42,
            reserved: 0,
            rights: TICKET_RIGHTS
        }
    );
    assert!(
        reply.handles[1..]
            .iter()
            .all(|object| *object == IpcObjectHandle::default())
    );
}
