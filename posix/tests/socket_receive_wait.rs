use mochios_posix_protocol::socket::{Create, Domain, Kind};
use posix_service::{
    AuthenticatedProcess, PeerIdentity, PosixService,
    socket::{MAX_ENDPOINTS, Shutdown, Streams},
    socket_receive_wait::{ReceiveWaits, job_id, object_id},
};

fn pair() -> (Streams, [u64; 2]) {
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
    let ids = service
        .create_socket_pair(
            PeerIdentity {
                process_id: 1,
                effective_uid: 501,
                effective_gid: 20,
            },
            Create {
                domain: Domain::Unix,
                kind: Kind::Stream,
                protocol: 0,
                options: 0,
            },
            &mut streams,
        )
        .unwrap();
    (streams, ids)
}

#[test]
fn partial_prefix_does_not_wake_until_additional_data_and_notifications_latch() {
    let (mut streams, [a, b]) = pair();
    let mut waits = ReceiveWaits::new();
    streams.write(a, b"ab").unwrap();
    let job = waits.start(&streams, b, 3, 42).unwrap();
    assert_eq!(waits.ready(job), Ok(false));
    for _ in 0..3 {
        waits.pump(&streams, |_| panic!("existing prefix cannot wake"));
    }
    streams.write(a, b"c").unwrap();
    let mut signaled = Vec::new();
    waits.pump(&streams, |id| signaled.push(id));
    assert_eq!(signaled, [job]);
    assert_eq!(waits.ready(job), Ok(true));
    streams.read(b, &mut [0; 8]).unwrap();
    waits.pump(&streams, |id| assert_eq!(id, job));
    let mut closed = Vec::new();
    assert_eq!(waits.release(job, |handle| closed.push(handle)), Ok(()));
    assert_eq!(closed, [42]);
    assert_eq!(waits.release(job, |_| panic!("double close")), Err(-9));
}

#[test]
fn data_arriving_before_registration_and_terminal_conditions_cannot_be_missed() {
    for terminal in 0..4 {
        let (mut streams, [a, b]) = pair();
        let mut waits = ReceiveWaits::new();
        streams.write(a, b"ab").unwrap();
        match terminal {
            0 => {
                streams.write(a, b"c").unwrap();
            }
            1 => streams.shutdown(a, Shutdown::Write).unwrap(),
            2 => streams.shutdown(b, Shutdown::Read).unwrap(),
            3 => {
                streams.write(b, b"discarded").unwrap();
                streams.release(a).unwrap();
            }
            _ => unreachable!(),
        }
        let job = waits.start(&streams, b, 3, 42).unwrap();
        assert_eq!(waits.ready(job), Ok(true));
        let mut signaled = Vec::new();
        waits.pump(&streams, |id| signaled.push(id));
        assert_eq!(signaled, [job]);
    }
}

#[test]
fn terminal_changes_after_registration_wake_independent_waiters_without_consuming() {
    let (mut streams, [a, b]) = pair();
    let mut waits = ReceiveWaits::new();
    let first = waits.start(&streams, b, 1, 41).unwrap();
    let second = waits.start(&streams, b, u64::MAX, 42).unwrap();
    streams.write(a, b"x").unwrap();
    waits.pump(&streams, |id| assert_eq!(id, first));
    assert_eq!(waits.ready(second), Ok(false));
    streams.shutdown(a, Shutdown::Write).unwrap();
    let mut signaled = Vec::new();
    waits.pump(&streams, |id| signaled.push(id));
    assert_eq!(signaled, [first, second]);
    assert_eq!(streams.read(b, &mut [0; 1]), Ok(1));
}

#[test]
fn cancellation_releases_only_the_lease_without_changing_socket_state() {
    let (mut streams, [a, b]) = pair();
    let mut waits = ReceiveWaits::new();
    streams.write(a, b"data").unwrap();
    for _ in 0..MAX_ENDPOINTS * 2 {
        let id = waits.start(&streams, b, 5, 42).unwrap();
        waits.release(id, |handle| assert_eq!(handle, 42)).unwrap();
    }
    let mut bytes = [0; 4];
    assert_eq!(streams.read(b, &mut bytes), Ok(4));
    assert_eq!(&bytes, b"data");
    assert_eq!(streams.options(b), Ok(0));
    assert_eq!(streams.read(b, &mut bytes), Err(-11));
}

#[test]
fn quota_and_invalid_registration_do_not_publish_or_reuse_identities() {
    let (streams, [_, b]) = pair();
    let mut waits = ReceiveWaits::new();
    assert_eq!(waits.start(&streams, b, 0, 99), Err(-22));
    assert_eq!(waits.start(&streams, u64::MAX, 1, 99), Err(-9));
    let ids: Vec<_> = (0..MAX_ENDPOINTS)
        .map(|_| waits.start(&streams, b, 1, 42).unwrap())
        .collect();
    assert_eq!(waits.start(&streams, b, 1, 99), Err(-23));
    waits.release(ids[0], |_| ()).unwrap();
    let next = waits.start(&streams, b, 1, 42).unwrap();
    assert!(!ids.contains(&next));
    for id in ids.into_iter().skip(1).chain([next]) {
        waits.release(id, |_| ()).unwrap();
    }
}

#[test]
fn job_namespaces_do_not_alias_streams_connections_or_forged_release_requests() {
    use mnu_abi::provider;
    use posix_service::{socket::MAX_DESCRIPTION_ID, socket_connect};
    for id in [1, MAX_DESCRIPTION_ID] {
        let object = object_id(id).unwrap();
        assert!(object > MAX_DESCRIPTION_ID);
        assert_eq!(job_id(object), Ok(id));
        assert_eq!(socket_connect::job_id(object), Err(-9));
        assert_eq!(job_id(socket_connect::object_id(id).unwrap()), Err(-9));
    }
    for object in [0, 1 << 61, u64::MAX, 1 << 63] {
        assert_eq!(job_id(object), Err(-9));
    }
    assert_eq!(object_id(MAX_DESCRIPTION_ID + 1), Err(-9));
    let (streams, [_, b]) = pair();
    let mut waits = ReceiveWaits::new();
    let job = waits.start(&streams, b, 1, 42).unwrap();
    let mut frame = [0; provider::REQUEST_HEADER_LEN];
    provider::RequestHeader {
        opcode: provider::OP_RELEASE,
        object_id: object_id(job).unwrap(),
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut frame)
    .unwrap();
    for flags in [0, mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE] {
        assert_eq!(
            waits.handle_provider_request(&frame, flags, 0, |_| panic!("forged release")),
            Err(-13)
        );
    }
    assert_eq!(
        waits.handle_provider_request(&frame, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 1, |_| panic!(
            "invalid attachment"
        )),
        Err(-22)
    );
    assert_eq!(waits.ready(job), Ok(false));
    assert_eq!(
        waits.handle_provider_request(
            &frame,
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            0,
            |source| assert_eq!(source, 42)
        ),
        Ok(None)
    );
}
