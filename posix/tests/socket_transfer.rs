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
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::{Cell, RefCell},
};
thread_local! { static CLOSED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) }; }
thread_local! { static FAIL_AFTER: Cell<isize> = const { Cell::new(-1) }; }
struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let fail = FAIL_AFTER
            .try_with(|remaining| {
                let count = remaining.get();
                if count < 0 {
                    false
                } else {
                    remaining.set(count - 1);
                    count == 0
                }
            })
            .unwrap_or(false);
        if fail {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
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
    for offset in [0, 4095, u64::MAX] {
        let commit = wire::commit(offset);
        assert_eq!(wire::decode(&commit), Ok(wire::Request::Commit { offset }));
        assert!(wire::decode(&commit[..15]).is_err());
        let mut oversized = commit.to_vec();
        oversized.push(0);
        assert!(wire::decode(&oversized).is_err());
    }
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
fn receive_and_delivery_codecs_bind_limits_offsets_counts_and_reserved_fields() {
    use mochios_posix_protocol::socket::Address;
    let request = wire::receive(17, 3, 2).unwrap();
    assert_eq!(
        wire::decode(&request),
        Ok(wire::Request::Receive {
            offset: 17,
            length: 3,
            maximum_rights: 2
        })
    );
    assert!(wire::receive(u64::MAX, 1, 0).is_err());
    assert!(wire::receive(0, 65537, 0).is_err());
    assert!(wire::receive(0, 0, 254).is_err());
    let mut invalid = request;
    invalid[22] = 1;
    assert!(wire::decode(&invalid).is_err());
    let reply = wire::ReceiveReply {
        copied: 3,
        length: 8,
        total_rights: 253,
        available_rights: 2,
        source: Address::UnixPath(b"/peer"),
    };
    let mut bytes = [0; wire::MAX_RECEIVE_REPLY_LEN];
    let count = reply.encode(3, 2, &mut bytes).unwrap();
    assert_eq!(wire::ReceiveReply::decode(3, 2, &bytes[..count]), Ok(reply));
    assert!(wire::ReceiveReply::decode(2, 2, &bytes[..count]).is_err());
    assert!(wire::ReceiveReply::decode(3, 1, &bytes[..count]).is_err());
    assert!(wire::ReceiveReply::decode(65537, 2, &bytes[..count]).is_err());
    bytes[22] = 1;
    assert!(wire::ReceiveReply::decode(3, 2, &bytes[..count]).is_err());
    for maximum in [0, 5, u16::MAX] {
        assert!(wire::deliver(0, maximum).is_err());
    }
    assert!(wire::deliver(254, 4).is_err());
    let request = wire::deliver(252, 4).unwrap();
    assert_eq!(
        wire::decode(&request),
        Ok(wire::Request::Deliver {
            offset: 252,
            maximum: 4
        })
    );
    let mut bytes = [0; wire::MAX_DELIVERY_REPLY_LEN];
    let count = wire::delivery_reply(249, &[metadata(); 4], &mut bytes).unwrap();
    assert_eq!(
        wire::decode_delivery(249, 4, &bytes[..count]),
        Ok(([Some(metadata()); 4], 4))
    );
    assert!(wire::decode_delivery(248, 4, &bytes[..count]).is_err());
    assert!(wire::decode_delivery(249, 3, &bytes[..count]).is_err());
    for length in 0..count {
        assert!(wire::decode_delivery(249, 4, &bytes[..length]).is_err());
    }
    bytes[16 + 4] = 1; // Sender CLOEXEC must not be inherited as descriptor policy.
    assert!(wire::decode_delivery(249, 4, &bytes[..count]).is_err());
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

struct Buffer {
    bytes: Vec<u8>,
    reads: usize,
    fail: bool,
    write_fail: bool,
}
impl Buffer {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            reads: 0,
            fail: false,
            write_fail: false,
        }
    }
}
impl posix_service::socket_record_io::RecordBuffer for Buffer {
    fn extent(&self) -> Result<u64, i32> {
        Ok(self.bytes.len() as u64)
    }
    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), i32> {
        self.reads += 1;
        if self.fail {
            return Err(-5);
        }
        output.copy_from_slice(&self.bytes[offset as usize..offset as usize + output.len()]);
        Ok(())
    }
    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), i32> {
        if self.write_fail {
            return Err(-5);
        }
        self.bytes[offset as usize..offset as usize + input.len()].copy_from_slice(input);
        Ok(())
    }
}

fn queued_rights(
    streams: &mut Streams,
    source: u64,
    handles: &[u32],
    payload: &[u8],
) -> posix_service::socket_rights::Budget {
    use posix_service::socket_rights::Budget;
    let budget = Budget::new(handles.len());
    queue_using_budget(streams, source, handles, payload, &budget);
    budget
}

fn queue_using_budget(
    streams: &mut Streams,
    source: u64,
    handles: &[u32],
    payload: &[u8],
    budget: &posix_service::socket_rights::Budget,
) {
    use posix_service::socket_rights::Pending;
    let mut pending = Pending::new(handles.len(), budget).unwrap();
    for (index, chunk) in handles.chunks(3).enumerate() {
        pending
            .append(
                index * 3,
                chunk.iter().map(|handle| lease(*handle)).collect(),
            )
            .unwrap();
    }
    streams
        .commit_record_with_rights(source, payload, pending.finish().ok().unwrap())
        .ok()
        .unwrap();
}

#[test]
fn repeated_peek_receipts_keep_bounded_prefixes_alive_after_other_reader_consumes() {
    use posix_service::socket_rights::Budget;
    let (mut streams, [a, b]) = pair();
    let budget = Budget::new(8);
    queue_using_budget(&mut streams, a, &[1, 2, 3], b"abcdef", &budget);
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"--------");
    let mut receipts = Vec::new();
    for source in [200, 201] {
        let mut published = None;
        let result = jobs
            .peek(
                &mut streams,
                b,
                source,
                2,
                2,
                2,
                close,
                |id, info| {
                    published = Some((info, id));
                    Ok(())
                },
                &mut buffer,
            )
            .unwrap();
        assert_eq!(published, Some(result));
        assert_eq!(
            (
                result.0.record.copied,
                result.0.record.length,
                result.0.total_rights,
                result.0.available_rights
            ),
            (2, 6, 3, 2)
        );
        assert_eq!(&buffer.bytes, b"--ab----");
        receipts.push(result.1.unwrap());
        assert!(streams.readiness(b).unwrap().readable);
        assert!(closed().is_empty());
    }
    assert_ne!(receipts[0], receipts[1]);
    assert_eq!(budget.used(), 7);
    let (_, consumed) = jobs
        .receive(
            &mut streams,
            b,
            202,
            0,
            8,
            0,
            close,
            |_, _| Ok(()),
            &mut buffer,
        )
        .unwrap();
    assert!(consumed.is_none());
    assert_eq!(closed(), [3]);
    assert_eq!(budget.used(), 4);
    assert!(!streams.readiness(b).unwrap().readable);
    for (index, receipt) in receipts.into_iter().enumerate() {
        assert_eq!(
            jobs.deliver(receipt, 0, 4, |leases| {
                assert_eq!(leases.iter().map(Lease::handle).collect::<Vec<_>>(), [1, 2]);
                assert!(leases.iter().all(|lease| lease.rights()
                    == mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER));
                Ok(())
            }),
            Ok(2)
        );
        assert_eq!(budget.used(), 2 * (1 - index));
        jobs.release(receipt).unwrap();
    }
    assert_eq!(closed(), [3, 200, 1, 2, 201]);
}

#[test]
fn zero_control_and_zero_payload_peeks_preserve_empty_datagram_rights() {
    let (mut streams, [a, b]) = pair();
    let budget = posix_service::socket_rights::Budget::new(2);
    queue_using_budget(&mut streams, a, &[1], b"", &budget);
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"");
    let (info, receipt) = jobs
        .peek(
            &mut streams,
            b,
            200,
            0,
            0,
            0,
            close,
            |id, info| {
                assert!(id.is_none());
                assert_eq!((info.total_rights, info.available_rights), (1, 0));
                Ok(())
            },
            &mut buffer,
        )
        .unwrap();
    assert_eq!((info.record.copied, info.record.length), (0, 0));
    assert!(receipt.is_none() && closed().is_empty());
    assert_eq!(budget.used(), 1);
    let (_, receipt) = jobs
        .peek(
            &mut streams,
            b,
            201,
            0,
            0,
            1,
            close,
            |_, _| Ok(()),
            &mut buffer,
        )
        .unwrap();
    let receipt = receipt.unwrap();
    assert_eq!(budget.used(), 2);
    jobs.release(receipt).unwrap();
    assert_eq!(closed(), [201]);
    assert_eq!(budget.used(), 1);
    assert!(streams.readiness(b).unwrap().readable);
    jobs.receive(
        &mut streams,
        b,
        202,
        0,
        0,
        0,
        close,
        |_, _| Ok(()),
        &mut buffer,
    )
    .unwrap();
    assert_eq!(closed(), [201, 1]);
    assert_eq!(budget.used(), 0);
}

#[test]
fn failed_peek_publication_releases_pins_without_adopting_source_or_reusing_id() {
    let (mut streams, [a, b]) = pair();
    let budget = posix_service::socket_rights::Budget::new(4);
    queue_using_budget(&mut streams, a, &[1, 2], b"abc", &budget);
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"---");
    buffer.write_fail = true;
    assert_eq!(
        jobs.peek(
            &mut streams,
            b,
            200,
            0,
            3,
            2,
            close,
            |_, _| panic!("copy failed"),
            &mut buffer
        ),
        Err(-5)
    );
    buffer.write_fail = false;
    let mut failed_id = None;
    assert_eq!(
        jobs.peek(
            &mut streams,
            b,
            200,
            0,
            3,
            2,
            close,
            |id, _| {
                failed_id = id;
                assert_eq!(budget.used(), 4);
                Err(-5)
            },
            &mut buffer
        ),
        Err(-5)
    );
    assert_eq!(budget.used(), 2);
    assert!(closed().is_empty());
    let (_, receipt) = jobs
        .peek(
            &mut streams,
            b,
            201,
            0,
            3,
            2,
            close,
            |_, _| Ok(()),
            &mut buffer,
        )
        .unwrap();
    let receipt = receipt.unwrap();
    assert_ne!(Some(receipt), failed_id);
    assert_eq!(jobs.release(failed_id.unwrap()), Err(-9));
    assert_eq!(jobs.deliver(receipt, 0, 2, |_| Err(-5)), Err(-5));
    assert_eq!(budget.used(), 4);
    jobs.release(receipt).unwrap();
    assert_eq!(budget.used(), 2);
    assert_eq!(closed(), [201]);
    assert!(streams.readiness(b).unwrap().readable);
}

#[test]
fn peek_quota_and_allocation_failures_leave_original_record_and_rights_usable() {
    let mut failures = 0;
    for allocation in 0..4 {
        let (mut streams, [a, b]) = pair();
        let budget = posix_service::socket_rights::Budget::new(4);
        queue_using_budget(&mut streams, a, &[1, 2], b"abc", &budget);
        let mut jobs = Transfers::new(0);
        let mut buffer = Buffer::new(b"---");
        FAIL_AFTER.with(|remaining| remaining.set(allocation));
        let result = jobs.peek(
            &mut streams,
            b,
            200,
            0,
            3,
            2,
            close,
            |_, _| Ok(()),
            &mut buffer,
        );
        FAIL_AFTER.with(|remaining| remaining.set(-1));
        match result {
            Err(error) => {
                assert_eq!(error, -12);
                failures += 1;
                assert_eq!(budget.used(), 2);
                assert!(closed().is_empty());
            }
            Ok((_, receipt)) => jobs.release(receipt.unwrap()).unwrap(),
        }
        assert!(streams.readiness(b).unwrap().readable);
        jobs.receive(
            &mut streams,
            b,
            201,
            0,
            3,
            0,
            close,
            |_, info| {
                assert_eq!(info.total_rights, 2);
                Ok(())
            },
            &mut buffer,
        )
        .unwrap();
        assert_eq!(buffer.bytes, b"abc");
        assert_eq!(budget.used(), 0);
    }
    assert_eq!(failures, 3);
    let (mut streams, [a, b]) = pair();
    let budget = queued_rights(&mut streams, a, &[1], b"a");
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"-");
    assert_eq!(
        jobs.peek(
            &mut streams,
            b,
            200,
            0,
            1,
            1,
            close,
            |_, _| panic!("quota exhausted"),
            &mut buffer
        ),
        Err(-105)
    );
    assert_eq!(budget.used(), 1);
    assert!(closed().is_empty());
    assert!(streams.readiness(b).unwrap().readable);
}

#[test]
fn receipt_moves_data_and_rights_together_truncates_control_and_delivers_once() {
    let (mut streams, [a, b]) = pair();
    let budget = queued_rights(&mut streams, a, &[1, 2, 3, 4, 5, 6], b"abcdef");
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"--------");
    let mut published = None;
    let (info, id) = jobs
        .receive(
            &mut streams,
            b,
            200,
            2,
            2,
            4,
            close,
            |id, info| {
                assert!(closed().is_empty());
                assert_eq!(budget.used(), 6);
                published = Some((info, id));
                Ok(())
            },
            &mut buffer,
        )
        .unwrap();
    assert_eq!(published, Some((info, id)));
    assert_eq!(
        (
            info.record.copied,
            info.record.length,
            info.total_rights,
            info.available_rights
        ),
        (2, 6, 6, 4)
    );
    assert_eq!(&buffer.bytes, b"--ab----");
    assert!(!streams.readiness(b).unwrap().readable);
    assert_eq!(closed(), [5, 6]);
    assert_eq!(budget.used(), 4);
    let id = id.unwrap();
    assert_eq!(jobs.commit(&mut streams, id, 0, &mut buffer), Err(-95));
    assert_eq!(jobs.append(id, 0, vec![]), Err(-95));
    assert_eq!(
        jobs.deliver(id, 0, 4, |leases| {
            assert_eq!(
                leases
                    .iter()
                    .map(|lease| lease.handle())
                    .collect::<Vec<_>>(),
                [1, 2, 3, 4]
            );
            assert!(leases.iter().all(|lease| lease.rights()
                == mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER));
            Ok(())
        }),
        Ok(4)
    );
    assert_eq!(budget.used(), 0);
    assert_eq!(closed(), [5, 6, 1, 2, 3, 4]);
    assert_eq!(
        jobs.deliver(id, 0, 1, |_| panic!("replayed delivery")),
        Err(-22)
    );
    assert_eq!(jobs.deliver(id, 4, 1, |_| panic!("past end")), Err(-61));
    jobs.release(id).unwrap();
    assert_eq!(closed(), [5, 6, 1, 2, 3, 4, 200]);
}

#[test]
fn failed_receive_copy_and_publication_preserve_queue_and_do_not_adopt_source() {
    let (mut streams, [a, b]) = pair();
    let budget = queued_rights(&mut streams, a, &[1, 2], b"xyz");
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"---");
    buffer.write_fail = true;
    assert_eq!(
        jobs.receive(
            &mut streams,
            b,
            200,
            0,
            3,
            2,
            close,
            |_, _| panic!("copy failed"),
            &mut buffer
        ),
        Err(-5)
    );
    assert_eq!(buffer.bytes, b"---");
    buffer.write_fail = false;
    let mut failed_id = None;
    assert_eq!(
        jobs.receive(
            &mut streams,
            b,
            200,
            0,
            3,
            2,
            close,
            |id, _| {
                failed_id = id;
                Err(-5)
            },
            &mut buffer
        ),
        Err(-5)
    );
    assert!(closed().is_empty());
    assert_eq!(budget.used(), 2);
    assert!(streams.readiness(b).unwrap().readable);
    let (_, good_id) = jobs
        .receive(
            &mut streams,
            b,
            200,
            0,
            3,
            2,
            close,
            |_, _| Ok(()),
            &mut buffer,
        )
        .unwrap();
    let good_id = good_id.unwrap();
    assert_ne!(failed_id.unwrap(), good_id);
    assert_eq!(jobs.release(failed_id.unwrap()), Err(-9));
    assert!(closed().is_empty());
    jobs.release(good_id).unwrap();
    assert_eq!(closed(), [200, 1, 2]);
    assert_eq!(budget.used(), 0);
}

#[test]
fn failed_batch_reply_keeps_cursor_and_references_while_abort_closes_the_remainder() {
    let (mut streams, [a, b]) = pair();
    let budget = queued_rights(&mut streams, a, &[1, 2, 3], b"x");
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"-");
    let (_, id) = jobs
        .receive(
            &mut streams,
            b,
            200,
            0,
            1,
            3,
            close,
            |_, _| Ok(()),
            &mut buffer,
        )
        .unwrap();
    let id = id.unwrap();
    assert_eq!(jobs.deliver(id, 0, 0, |_| panic!()), Err(-22));
    assert_eq!(jobs.deliver(id, 0, 5, |_| panic!()), Err(-22));
    assert_eq!(jobs.deliver(id, 0, 2, |_| Err(-5)), Err(-5));
    assert!(closed().is_empty());
    assert_eq!(budget.used(), 3);
    assert_eq!(jobs.deliver(id, 0, 2, |_| Ok(())), Ok(2));
    assert_eq!(closed(), [1, 2]);
    assert_eq!(budget.used(), 1);
    jobs.release(id).unwrap();
    assert_eq!(closed(), [1, 2, 200, 3]);
    assert_eq!(budget.used(), 0);
}

#[test]
fn no_control_capacity_needs_no_receipt_and_closes_all_discarded_references() {
    let (mut streams, [a, b]) = pair();
    let budget = queued_rights(&mut streams, a, &[1, 2], b"x");
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"-");
    let (info, id) = jobs
        .receive(
            &mut streams,
            b,
            200,
            0,
            1,
            0,
            close,
            |id, info| {
                assert_eq!(id, None);
                assert_eq!((info.total_rights, info.available_rights), (2, 0));
                Ok(())
            },
            &mut buffer,
        )
        .unwrap();
    assert_eq!(id, None);
    assert_eq!((info.total_rights, info.available_rights), (2, 0));
    assert_eq!(buffer.bytes, b"x");
    assert_eq!(closed(), [1, 2]); // source is still the adapter's cleanup duty
    assert_eq!(budget.used(), 0);
}

#[test]
fn receiving_an_empty_record_with_rights_still_publishes_a_receipt() {
    let (mut streams, [a, b]) = pair();
    let budget = queued_rights(&mut streams, a, &[1], b"");
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"");
    let (info, id) = jobs
        .receive(
            &mut streams,
            b,
            200,
            0,
            0,
            1,
            close,
            |_, _| Ok(()),
            &mut buffer,
        )
        .unwrap();
    assert_eq!(
        (
            info.record.length,
            info.record.copied,
            info.available_rights
        ),
        (0, 0, 1)
    );
    assert!(!streams.readiness(b).unwrap().readable);
    jobs.release(id.unwrap()).unwrap();
    assert_eq!(closed(), [200, 1]);
    assert_eq!(budget.used(), 0);
}

#[test]
fn all_253_received_references_are_delivered_in_independent_native_sized_batches() {
    let (mut streams, [a, b]) = pair();
    let handles: Vec<_> = (1..=253).collect();
    let budget = queued_rights(&mut streams, a, &handles, b"x");
    let mut jobs = Transfers::new(0);
    let mut buffer = Buffer::new(b"-");
    let (_, id) = jobs
        .receive(
            &mut streams,
            b,
            1000,
            0,
            1,
            253,
            close,
            |_, _| Ok(()),
            &mut buffer,
        )
        .unwrap();
    let id = id.unwrap();
    let mut delivered = 0;
    while delivered < handles.len() {
        let count = jobs
            .deliver(id, delivered, 4, |leases| {
                assert_eq!(leases.len(), (253 - delivered).min(4));
                for (lease, expected) in leases.iter().zip(&handles[delivered..]) {
                    assert_eq!(lease.handle(), *expected);
                }
                Ok(())
            })
            .unwrap();
        delivered += count;
        assert_eq!(budget.used(), 253 - delivered);
    }
    assert_eq!(closed(), handles);
    jobs.release(id).unwrap();
    assert_eq!(closed().last(), Some(&1000));
    assert_eq!(closed().len(), 254);
}

#[test]
fn receive_allocation_failures_cannot_consume_a_record_or_its_rights() {
    for allocation in 0..2 {
        let (mut streams, [a, b]) = pair();
        let budget = queued_rights(&mut streams, a, &[1, 2], b"abc");
        let mut jobs = Transfers::new(0);
        let mut buffer = Buffer::new(b"---");
        FAIL_AFTER.with(|fail| fail.set(allocation));
        let result = jobs.receive(
            &mut streams,
            b,
            200,
            0,
            3,
            2,
            close,
            |_, _| panic!("allocation failed"),
            &mut buffer,
        );
        FAIL_AFTER.with(|fail| fail.set(-1));
        assert_eq!(result, Err(-12));
        assert!(closed().is_empty());
        assert_eq!(budget.used(), 2);
        assert!(streams.readiness(b).unwrap().readable);
        let (_, id) = jobs
            .receive(
                &mut streams,
                b,
                200,
                0,
                3,
                2,
                close,
                |_, _| Ok(()),
                &mut buffer,
            )
            .unwrap();
        jobs.release(id.unwrap()).unwrap();
        assert_eq!(closed(), [200, 1, 2]);
        assert_eq!(budget.used(), 0);
    }
}
fn pair() -> (Streams, [u64; 2]) {
    let (mut streams, _) = fixture();
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
    let ids = service
        .create_socket_pair(
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
    (streams, ids)
}
fn record(
    operation: mochios_posix_protocol::socket_record::Operation,
    length: u32,
    peek: bool,
) -> mochios_posix_protocol::socket_record::Request {
    mochios_posix_protocol::socket_record::Request {
        operation,
        length,
        offset: 0,
        peek,
    }
}

#[test]
fn data_and_leases_commit_once_and_survive_transaction_release_until_receive() {
    use mochios_posix_protocol::socket_record::{MAX_REPLY_LEN, Operation};
    let (mut streams, [a, b]) = pair();
    let mut jobs = Transfers::new(2);
    let id = jobs.start(&streams, a, 100, 3, 2, close).unwrap();
    jobs.append(id, 0, vec![lease(1), lease(2)]).unwrap();
    let mut buffer = Buffer::new(b"abcdefgh");
    assert_eq!(
        jobs.commit(&mut streams, id, 2, &mut buffer),
        Ok((3, [a, b]))
    );
    assert!(closed().is_empty());
    assert_eq!(jobs.progress(id), Err(-114));
    assert_eq!(jobs.commit(&mut streams, id, 2, &mut buffer), Err(-114));
    assert_eq!(buffer.reads, 1);
    assert_eq!(jobs.append(id, 2, vec![lease(3)]), Err(-114));
    jobs.release(id).unwrap();
    assert_eq!(closed(), [3, 100]);
    assert_eq!(jobs.reserved_references(), 2);
    let mut reply = [0; MAX_REPLY_LEN];
    streams
        .transfer_record(
            b,
            record(Operation::Receive, 2, true),
            &mut buffer,
            &mut reply,
        )
        .unwrap();
    assert_eq!(&buffer.bytes[..2], b"cd");
    assert_eq!(closed(), [3, 100]);
    streams
        .transfer_record(
            b,
            record(Operation::Receive, 1, false),
            &mut buffer,
            &mut reply,
        )
        .unwrap();
    assert_eq!(closed(), [3, 100, 1, 2]);
    assert_eq!(jobs.reserved_references(), 0);
    assert_eq!(
        streams.transfer_record(
            b,
            record(Operation::Receive, 1, false),
            &mut buffer,
            &mut reply
        ),
        Err(-11)
    );
}

#[test]
fn incomplete_batches_bad_extent_and_failed_copy_never_publish_data_or_rights() {
    use mochios_posix_protocol::socket_record::{MAX_REPLY_LEN, Operation};
    let (mut streams, [a, b]) = pair();
    let mut jobs = Transfers::new(2);
    let id = jobs.start(&streams, a, 100, 3, 2, close).unwrap();
    jobs.append(id, 0, vec![lease(1)]).unwrap();
    let mut buffer = Buffer::new(b"abc");
    assert_eq!(jobs.commit(&mut streams, id, 0, &mut buffer), Err(-22));
    assert_eq!(buffer.reads, 0);
    jobs.append(id, 1, vec![lease(2)]).unwrap();
    assert_eq!(jobs.commit(&mut streams, id, 1, &mut buffer), Err(-22));
    assert_eq!(
        jobs.commit(&mut streams, id, u64::MAX, &mut buffer),
        Err(-22)
    );
    assert_eq!(buffer.reads, 0);
    buffer.fail = true;
    assert_eq!(jobs.commit(&mut streams, id, 0, &mut buffer), Err(-5));
    assert_eq!(jobs.progress(id), Ok((a, 3, 2)));
    assert!(closed().is_empty());
    let mut reply = [0; MAX_REPLY_LEN];
    assert_eq!(
        streams.transfer_record(
            b,
            record(Operation::Receive, 3, false),
            &mut buffer,
            &mut reply
        ),
        Err(-11)
    );
    buffer.fail = false;
    assert_eq!(
        jobs.commit(&mut streams, id, 0, &mut buffer),
        Ok((3, [a, b]))
    );
    streams
        .transfer_record(
            b,
            record(Operation::Receive, 3, false),
            &mut buffer,
            &mut reply,
        )
        .unwrap();
    assert_eq!(buffer.bytes, b"abc");
    assert_eq!(closed(), [1, 2]);
    jobs.release(id).unwrap();
}

#[test]
fn pressure_and_peer_errors_keep_the_complete_bundle_available_for_retry_or_abort() {
    use mochios_posix_protocol::socket_record::{MAX_REPLY_LEN, Operation};
    let (mut streams, [a, b]) = pair();
    let mut jobs = Transfers::new(1);
    let id = jobs.start(&streams, a, 100, 1, 1, close).unwrap();
    jobs.append(id, 0, vec![lease(1)]).unwrap();
    let mut full = Buffer::new(&[0; 65536]);
    let mut reply = [0; MAX_REPLY_LEN];
    streams
        .transfer_record(
            a,
            record(Operation::Send, 65536, false),
            &mut full,
            &mut reply,
        )
        .unwrap();
    let mut buffer = Buffer::new(b"x");
    assert_eq!(jobs.commit(&mut streams, id, 0, &mut buffer), Err(-11));
    assert_eq!(buffer.reads, 0);
    streams
        .transfer_record(
            b,
            record(Operation::Receive, 0, false),
            &mut full,
            &mut reply,
        )
        .unwrap();
    streams.disconnect_datagram(a).unwrap();
    assert_eq!(jobs.commit(&mut streams, id, 0, &mut buffer), Err(-89));
    assert_eq!(jobs.progress(id), Ok((a, 1, 1)));
    assert!(closed().is_empty());
    streams
        .connect_datagram_named(a, b, None, b"/peer")
        .unwrap();
    assert_eq!(
        jobs.commit(&mut streams, id, 0, &mut buffer),
        Ok((1, [a, b]))
    );
    jobs.release(id).unwrap();
    streams
        .shutdown(b, posix_service::socket::Shutdown::Read)
        .unwrap();
    assert_eq!(jobs.reserved_references(), 0);
    assert_eq!(closed(), [100, 1]);
}

#[test]
fn every_commit_allocation_failure_restores_complete_ownership_and_allows_one_retry() {
    for allocation in 0..3 {
        let (mut streams, [a, b]) = pair();
        let mut jobs = Transfers::new(1);
        let id = jobs.start(&streams, a, 100, 3, 1, close).unwrap();
        jobs.append(id, 0, vec![lease(1)]).unwrap();
        let mut buffer = Buffer::new(b"abc");
        FAIL_AFTER.with(|fail| fail.set(allocation));
        let result = jobs.commit(&mut streams, id, 0, &mut buffer);
        FAIL_AFTER.with(|fail| fail.set(-1));
        assert_eq!(result, Err(-12));
        assert_eq!(jobs.progress(id), Ok((a, 3, 1)));
        assert!(!streams.readiness(b).unwrap().readable);
        assert!(closed().is_empty());
        assert_eq!(jobs.reserved_references(), 1);
        assert_eq!(
            jobs.commit(&mut streams, id, 0, &mut buffer),
            Ok((3, [a, b]))
        );
        assert_eq!(jobs.commit(&mut streams, id, 0, &mut buffer), Err(-114));
        jobs.release(id).unwrap();
        streams
            .shutdown(b, posix_service::socket::Shutdown::Read)
            .unwrap();
        assert_eq!(closed(), [100, 1]);
        assert_eq!(jobs.reserved_references(), 0);
    }
}

#[test]
fn empty_datagram_commits_rights_as_a_readable_record_not_eof() {
    use mochios_posix_protocol::socket_record::{MAX_REPLY_LEN, Operation};
    let (mut streams, [a, b]) = pair();
    let mut jobs = Transfers::new(1);
    let id = jobs.start(&streams, a, 100, 0, 1, close).unwrap();
    jobs.append(id, 0, vec![lease(1)]).unwrap();
    let mut buffer = Buffer::new(&[]);
    assert_eq!(
        jobs.commit(&mut streams, id, 0, &mut buffer),
        Ok((0, [a, b]))
    );
    jobs.release(id).unwrap();
    assert!(streams.readiness(b).unwrap().readable);
    let mut reply = [0; MAX_REPLY_LEN];
    streams
        .transfer_record(
            b,
            record(Operation::Receive, 0, false),
            &mut buffer,
            &mut reply,
        )
        .unwrap();
    assert_eq!(closed(), [100, 1]);
    assert_eq!(jobs.reserved_references(), 0);
    assert!(!streams.readiness(b).unwrap().readable);
    assert_eq!(
        streams.transfer_record(
            b,
            record(Operation::Receive, 0, false),
            &mut buffer,
            &mut reply
        ),
        Err(-11)
    );
}

#[test]
fn terminal_peer_error_can_abort_a_ready_bundle_without_leaking_or_publishing() {
    let (mut streams, [a, b]) = pair();
    let mut jobs = Transfers::new(1);
    let id = jobs.start(&streams, a, 100, 1, 1, close).unwrap();
    jobs.append(id, 0, vec![lease(1)]).unwrap();
    streams
        .shutdown(b, posix_service::socket::Shutdown::Read)
        .unwrap();
    let mut buffer = Buffer::new(b"x");
    assert_eq!(jobs.commit(&mut streams, id, 0, &mut buffer), Err(-111));
    assert_eq!(jobs.progress(id), Ok((a, 1, 1)));
    assert_eq!(jobs.reserved_references(), 1);
    assert!(closed().is_empty());
    jobs.release(id).unwrap();
    assert_eq!(closed(), [100, 1]);
    assert_eq!(jobs.reserved_references(), 0);
}

fn cycle() -> (Streams, [u64; 2], posix_service::socket_rights::Budget) {
    use posix_service::socket_rights::{Budget, Pending};
    let (mut streams, [a, b]) = pair();
    let budget = Budget::new(2);
    for (sender, handle) in [(a, 1), (b, 2)] {
        let mut pending = Pending::new(1, &budget).unwrap();
        pending.append(0, vec![lease(handle)]).unwrap();
        streams
            .commit_record_with_rights(sender, b"x", pending.finish().ok().unwrap())
            .ok()
            .unwrap();
    }
    (streams, [a, b], budget)
}

#[test]
fn queue_cycle_collection_keeps_external_roots_then_releases_unreachable_leases() {
    let (mut streams, [a, b], budget) = cycle();
    // Metadata says RAM, but collection must use the native object's identity,
    // not a client-supplied FD-kind hint when deciding socket graph edges.
    let identity = |handle| Ok(Some(if handle == 1 { a } else { b }));
    assert_eq!(
        streams.collect_record_cycles(identity, |id| Ok(if id == a { 2 } else { 1 })),
        Ok(vec![])
    );
    assert!(closed().is_empty());
    assert!(streams.readiness(a).unwrap().readable && streams.readiness(b).unwrap().readable);
    assert_eq!(
        streams.collect_record_cycles(identity, |_| Ok(1)),
        Ok(vec![a, b])
    );
    assert_eq!(closed(), [2, 1]);
    assert_eq!(budget.used(), 0);
    assert!(!streams.readiness(a).unwrap().readable && !streams.readiness(b).unwrap().readable);
    assert_eq!(
        streams.collect_record_cycles(identity, |_| panic!("empty graph queried")),
        Ok(vec![])
    );
}

#[test]
fn a_peek_pin_roots_a_mutual_queue_cycle_without_inventing_a_second_native_reference() {
    use posix_service::socket_rights::{Budget, Pending};
    let (mut streams, [a, b]) = pair();
    let budget = Budget::new(3);
    for (sender, handle) in [(a, 1), (b, 2)] {
        let mut pending = Pending::new(1, &budget).unwrap();
        pending.append(0, vec![lease(handle)]).unwrap();
        streams
            .commit_record_with_rights(sender, b"x", pending.finish().ok().unwrap())
            .ok()
            .unwrap();
    }
    let snapshot = streams.snapshot_queued_rights(b, 1, 1).unwrap().unwrap();
    let identity = |handle| Ok(Some(if handle == 1 { a } else { b }));
    assert_eq!(
        streams.collect_record_cycles(identity, |_| Ok(1)),
        Ok(vec![])
    );
    assert_eq!(budget.used(), 3);
    assert!(closed().is_empty());
    assert!(streams.readiness(a).unwrap().readable && streams.readiness(b).unwrap().readable);
    drop(snapshot);
    assert_eq!(budget.used(), 2);
    assert_eq!(
        streams.collect_record_cycles(identity, |_| Ok(1)),
        Ok(vec![a, b])
    );
    assert_eq!(closed(), [2, 1]);
    assert_eq!(budget.used(), 0);
}

#[test]
fn failed_or_inconsistent_observations_do_not_discard_any_queue() {
    let (mut streams, [a, b], budget) = cycle();
    let identity = |handle| Ok(Some(if handle == 1 { a } else { b }));
    assert_eq!(
        streams.collect_record_cycles(|_| Err(-13), |_| Ok(1)),
        Err(-13)
    );
    assert_eq!(
        streams.collect_record_cycles(identity, |id| if id == b { Err(-5) } else { Ok(1) }),
        Err(-5)
    );
    assert_eq!(streams.collect_record_cycles(identity, |_| Ok(0)), Err(-11));
    assert_eq!(
        streams.collect_record_cycles(|_| Ok(Some(u64::MAX)), |_| Ok(1)),
        Err(-22)
    );
    assert!(closed().is_empty());
    assert_eq!(budget.used(), 2);
    assert!(streams.readiness(a).unwrap().readable && streams.readiness(b).unwrap().readable);
}

#[test]
fn every_cycle_collection_allocation_failure_leaves_the_graph_and_queues_intact() {
    for allocation in 0..6 {
        let (mut streams, [a, b], budget) = cycle();
        let identity = |handle| Ok(Some(if handle == 1 { a } else { b }));
        FAIL_AFTER.with(|fail| fail.set(allocation));
        let result = streams.collect_record_cycles(identity, |_| Ok(1));
        FAIL_AFTER.with(|fail| fail.set(-1));
        assert_eq!(result, Err(-12), "allocation {allocation}");
        assert!(closed().is_empty());
        assert_eq!(budget.used(), 2);
        assert!(streams.readiness(a).unwrap().readable && streams.readiness(b).unwrap().readable);
        assert_eq!(
            streams.collect_record_cycles(identity, |_| Ok(1)),
            Ok(vec![a, b])
        );
        assert_eq!(closed(), [2, 1]);
        assert_eq!(budget.used(), 0);
    }
}
