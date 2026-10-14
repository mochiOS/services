use mochios_posix_protocol::{
    InheritedFdMetadata, ProtocolError,
    socket::{Create, Domain, Kind},
    socket_transfer as wire,
};
use posix_service::{
    AuthenticatedProcess, PeerIdentity, PosixService,
    socket::{MAX_DESCRIPTION_ID, Streams},
    socket_rights::Lease,
    socket_transfer::{Transfers, job_id, object_id},
};
use std::cell::RefCell;
thread_local! { static CLOSED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) }; }
fn close(handle: u32) {
    CLOSED.with(|closed| closed.borrow_mut().push(handle));
}
fn closed() -> Vec<u32> {
    CLOSED.with(|closed| closed.borrow().clone())
}
fn metadata() -> InheritedFdMetadata {
    InheritedFdMetadata {
        kind: 10,
        open_flags: 2,
        descriptor_flags: 0,
    }
}
fn lease(handle: u32) -> Lease {
    Lease::adopt(
        handle,
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        metadata(),
        close,
    )
    .ok()
    .unwrap()
}
fn fixture() -> (Streams, u64) {
    CLOSED.with(|closed| closed.borrow_mut().clear());
    let mut service = PosixService::<u32>::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 1,
                process_id: 1,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    let mut streams = Streams::new();
    let id = service
        .create_socket(
            PeerIdentity {
                process_id: 1,
                effective_uid: 501,
                effective_gid: 20,
            },
            Create {
                domain: Domain::Unix,
                kind: Kind::Datagram,
                protocol: 0,
                options: 0,
            },
            &mut streams,
        )
        .unwrap();
    (streams, id)
}
#[test]
fn codec_is_versioned_and_contains_only_lengths_indices_and_validated_metadata() {
    let begin = wire::begin(65536, 253).unwrap();
    assert_eq!(
        wire::decode(&begin),
        Ok(wire::Request::Begin {
            length: 65536,
            descriptors: 253
        })
    );
    assert!(wire::begin(0, 254).is_err());
    assert!(wire::begin(wire::MAX_PAYLOAD_LEN + 1, 0).is_err());
    let mut bytes = [0; wire::MAX_REQUEST_LEN];
    let length = wire::append(250, &[metadata(); 3], &mut bytes).unwrap();
    assert_eq!(
        wire::decode(&bytes[..length]),
        Ok(wire::Request::Append {
            offset: 250,
            count: 3,
            metadata: [Some(metadata()); 3]
        })
    );
    for bad in [0, 4, 6, 14] {
        let mut invalid = begin;
        invalid[bad] ^= 0xff;
        assert!(wire::decode(&invalid).is_err());
    }
    let mut unknown = begin;
    unknown[6..8].copy_from_slice(&99u16.to_le_bytes());
    assert_eq!(wire::decode(&unknown), Err(wire::Error::UnknownOperation));
    let mut invalid = bytes;
    invalid[12] = 1;
    assert_eq!(
        wire::decode(&invalid[..length]),
        Err(wire::Error::Protocol(ProtocolError::InvalidLength))
    );
    for info in [
        InheritedFdMetadata {
            descriptor_flags: 1,
            ..metadata()
        },
        InheritedFdMetadata {
            kind: 0,
            ..metadata()
        },
        InheritedFdMetadata {
            open_flags: 3,
            ..metadata()
        },
    ] {
        assert!(wire::append(0, &[info], &mut bytes).is_err());
    }
    assert!(wire::append(251, &[metadata(); 3], &mut bytes).is_err());
    for size in 0..length {
        assert!(wire::decode(&bytes[..size]).is_err());
    }
}
#[test]
fn transfer_ids_are_disjoint_from_sockets_routes_and_wait_jobs() {
    assert_eq!(job_id(object_id(1).unwrap()), Ok(1));
    assert_eq!(
        job_id(object_id(MAX_DESCRIPTION_ID).unwrap()),
        Ok(MAX_DESCRIPTION_ID)
    );
    assert_eq!(object_id(MAX_DESCRIPTION_ID + 1), Err(-9));
    for object in [
        0,
        1,
        1 << 59,
        (1 << 60) | 1,
        (1 << 61) | 1,
        (1 << 62) | 1,
        (1 << 59) | (1 << 60) | 1,
    ] {
        assert_eq!(job_id(object), Err(-9));
    }
    let tagged = object_id(1).unwrap();
    assert_eq!(posix_service::socket_route::job_id(tagged), Err(-9));
    assert_eq!(posix_service::socket_receive_wait::job_id(tagged), Err(-9));
}
#[test]
fn release_owns_source_and_every_batch_while_errors_preserve_previous_stage() {
    let (streams, socket) = fixture();
    let mut jobs = Transfers::new(253);
    let id = jobs.start(&streams, socket, 1000, 8, 253, close).unwrap();
    assert_eq!(jobs.progress(id), Ok((socket, 8, 0)));
    for offset in (0..252).step_by(3) {
        assert_eq!(
            jobs.append(
                id,
                offset,
                (offset..offset + 3).map(|i| lease(i as u32 + 1)).collect()
            ),
            Ok(offset + 3)
        );
    }
    assert_eq!(jobs.append(id, 0, vec![lease(999)]), Err(-22));
    assert_eq!(closed(), [999]);
    assert_eq!(jobs.append(id, 252, vec![lease(253)]), Ok(253));
    assert_eq!(jobs.reserved_references(), 253);
    assert!(jobs.start(&streams, socket, 1001, 8, 1, close).is_err());
    assert!(!closed().contains(&1001)); // failed start never adopted source
    jobs.release(id).unwrap();
    assert_eq!(jobs.reserved_references(), 0);
    let expected: Vec<u32> = [999, 1000].into_iter().chain(1..=253).collect();
    assert_eq!(closed(), expected);
    assert_eq!(jobs.release(id), Err(-9));
    assert_eq!(jobs.append(id, 0, vec![lease(1002)]), Err(-9));
    assert_eq!(closed().last(), Some(&1002));
    for _ in 0..1100 {
        let id = jobs.start(&streams, socket, 1003, 0, 253, close).unwrap();
        jobs.release(id).unwrap();
    }
    assert_eq!(jobs.reserved_references(), 0);
}
#[test]
fn dropping_worker_cleans_partial_transactions_and_failed_starts_do_not_take_source() {
    let (streams, socket) = fixture();
    let mut jobs = Transfers::new(6);
    assert_eq!(jobs.start(&streams, socket, 99, 65537, 0, close), Err(-90));
    assert_eq!(jobs.start(&streams, u64::MAX, 99, 0, 0, close), Err(-9));
    assert!(closed().is_empty());
    let first = jobs.start(&streams, socket, 100, 10, 3, close).unwrap();
    let second = jobs.start(&streams, socket, 200, 10, 3, close).unwrap();
    jobs.append(first, 0, vec![lease(1)]).unwrap();
    jobs.append(second, 0, vec![lease(2), lease(3)]).unwrap();
    drop(jobs);
    assert_eq!(closed(), [100, 1, 200, 2, 3]);
}
