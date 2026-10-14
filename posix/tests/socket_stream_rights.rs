use mochios_posix_protocol::{
    InheritedFdMetadata,
    socket::{Create, Domain, Kind},
};
use posix_service::{
    AuthenticatedProcess, PeerIdentity, PosixService,
    socket::{Shutdown, Streams},
    socket_rights::{Budget, Bundle, Lease, Pending},
    socket_stream::{MAX_MARKERS, StreamQueue},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::{Cell, RefCell},
};

thread_local! {
    static CLOSED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    static FAIL: Cell<isize> = const { Cell::new(-1) };
}
struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let fail = FAIL
            .try_with(|remaining| {
                let value = remaining.get();
                if value < 0 {
                    false
                } else {
                    remaining.set(value - 1);
                    value == 0
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
fn bundle(handles: &[u32]) -> Bundle {
    let budget = Budget::new(handles.len());
    bundle_using(handles, &budget)
}
fn bundle_using(handles: &[u32], budget: &Budget) -> Bundle {
    let mut pending = Pending::new(handles.len(), budget).unwrap();
    for (batch, handles) in handles.chunks(3).enumerate() {
        let leases = handles
            .iter()
            .map(|&handle| {
                Lease::adopt(
                    handle,
                    mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
                    InheritedFdMetadata {
                        kind: 5,
                        open_flags: 0,
                        descriptor_flags: 0,
                    },
                    close,
                )
                .ok()
                .unwrap()
            })
            .collect();
        pending.append(batch * 3, leases).unwrap();
    }
    pending.finish().ok().unwrap()
}
fn queue() -> StreamQueue {
    CLOSED.with(|closed| closed.borrow_mut().clear());
    let mut queue = StreamQueue::new();
    queue.write(b"aa").unwrap();
    queue
        .write_with_rights(b"bcd", bundle(&[501]))
        .ok()
        .unwrap();
    queue.write(b"ee").unwrap();
    queue
}
fn pair() -> (Streams, [u64; 2]) {
    CLOSED.with(|closed| closed.borrow_mut().clear());
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 1u32,
                process_id: 1,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    let peer = PeerIdentity {
        process_id: 1,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut streams = Streams::new();
    let pair = service
        .create_socket_pair(
            peer,
            Create {
                domain: Domain::Unix,
                kind: Kind::Stream,
                protocol: 0,
                options: 0,
            },
            &mut streams,
        )
        .unwrap();
    (streams, pair)
}

#[test]
fn plain_prefix_and_first_ancillary_segment_form_one_consuming_window() {
    let mut queue = queue();
    assert_eq!(queue.read_length(16), 5);
    assert_eq!(queue.read_rights(2).map(Bundle::len), None);
    assert_eq!(queue.read_rights(3).map(Bundle::len), Some(1));
    let mut output = [0xa5; 16];
    let (count, rights) = queue.read_owned(&mut output);
    assert_eq!(count, 5);
    assert_eq!(&output[..5], b"aabcd");
    assert_eq!(output[5], 0xa5);
    let rights = rights.unwrap();
    assert_eq!(rights.leases()[0].handle(), 501);
    assert_eq!(
        rights.leases()[0].rights(),
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER
    );
    assert!(closed().is_empty());
    assert_eq!(queue.read(&mut output), 2);
    assert_eq!(&output[..2], b"ee");
    drop(rights);
    assert_eq!(closed(), [501]);
    assert!(queue.is_empty());
}

#[test]
fn partial_reads_move_rights_on_first_data_byte_not_on_later_tail() {
    let mut queue = queue();
    assert_eq!(queue.read_owned(&mut []).0, 0);
    for _ in 0..2 {
        let (count, rights) = queue.read_owned(&mut [0; 1]);
        assert_eq!(count, 1);
        assert!(rights.is_none());
    }
    let (_, rights) = queue.read_owned(&mut [0; 1]);
    drop(rights.unwrap());
    assert_eq!(closed(), [501]);
    let mut output = [0; 16];
    let (count, rights) = queue.read_owned(&mut output);
    assert_eq!(count, 4);
    assert_eq!(&output[..count], b"cdee");
    assert!(rights.is_none());
    assert_eq!(closed(), [501]);
}

#[test]
fn ordinary_read_discards_once_and_peeking_never_consumes_references() {
    let mut queue = queue();
    for offset in [0, 1, 2, 3, usize::MAX] {
        let mut output = [0; 16];
        assert_eq!(
            queue.peek(offset, &mut output),
            5usize.saturating_sub(offset)
        );
        assert_eq!(queue.len(), 7);
        assert_eq!(queue.ancillary_leases().count(), 1);
        assert!(closed().is_empty());
    }
    assert_eq!(queue.read(&mut [0; 16]), 5);
    assert_eq!(closed(), [501]);
    queue.clear();
    assert_eq!(closed(), [501]);
}

#[test]
fn every_write_allocation_failure_preserves_bytes_and_returns_the_complete_bundle() {
    let mut failures = 0;
    for fail in 0..4 {
        CLOSED.with(|closed| closed.borrow_mut().clear());
        let mut queue = StreamQueue::new();
        queue.write(b"aa").unwrap();
        let rights = bundle(&[501, 502]);
        FAIL.with(|remaining| remaining.set(fail));
        let result = queue.write_with_rights(&[1; 32], rights);
        FAIL.with(|remaining| remaining.set(-1));
        match result {
            Err((error, rights)) => {
                assert_eq!(error, -12);
                assert_eq!(queue.len(), 2);
                assert_eq!(queue.ancillary_leases().count(), 0);
                assert_eq!(rights.len(), 2);
                assert!(closed().is_empty());
                drop(rights);
                assert_eq!(closed(), [501, 502]);
                failures += 1;
            }
            Ok(count) => {
                assert_eq!(count, 32);
                break;
            }
        }
    }
    assert_eq!(failures, 2);
}

#[test]
fn marker_and_byte_limits_bound_storage_and_error_ownership() {
    CLOSED.with(|closed| closed.borrow_mut().clear());
    let mut queue = StreamQueue::new();
    for index in 0..MAX_MARKERS {
        queue
            .write_with_rights(b"x", bundle(&[1000 + index as u32]))
            .ok()
            .unwrap();
    }
    let (error, rights) = queue
        .write_with_rights(b"y", bundle(&[2000]))
        .err()
        .unwrap();
    assert_eq!(error, -11);
    assert_eq!(queue.len(), MAX_MARKERS);
    assert_eq!(queue.read(&mut [0; 1]), 1);
    assert_eq!(closed(), [1000]);
    queue.write_with_rights(b"y", rights).ok().unwrap();
    queue.clear();
    assert_eq!(closed().len(), MAX_MARKERS + 1);
    queue.write(&[0; 65536]).unwrap();
    let (_, rights) = queue
        .write_with_rights(b"z", bundle(&[3000]))
        .err()
        .unwrap();
    assert_eq!(queue.len(), 65536);
    drop(rights);
    assert_eq!(closed().last(), Some(&3000));
}

#[test]
fn marker_offsets_remain_relative_to_the_current_head_across_queue_wraparound() {
    CLOSED.with(|closed| closed.borrow_mut().clear());
    let mut queue = StreamQueue::new();
    queue.write(b"p").unwrap();
    for index in 0..1024 {
        queue
            .write_with_rights(b"ab", bundle(&[1000 + index]))
            .ok()
            .unwrap();
        queue.write(b"q").unwrap();
        let mut output = [0; 3];
        let (count, rights) = queue.read_owned(&mut output);
        assert_eq!(count, 3);
        assert_eq!(output, if index == 0 { *b"pab" } else { *b"qab" });
        drop(rights.unwrap());
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.ancillary_leases().count(), 0);
    }
    assert_eq!(closed(), (1000..2024).collect::<Vec<_>>());
    assert_eq!(queue.read(&mut [0; 8]), 1);
}

#[test]
fn empty_data_and_empty_bundles_do_not_create_hidden_stream_markers() {
    CLOSED.with(|closed| closed.borrow_mut().clear());
    let mut queue = StreamQueue::new();
    assert_eq!(queue.write_with_rights(b"", bundle(&[501])).ok(), Some(0));
    assert!(queue.is_empty());
    assert_eq!(queue.ancillary_leases().count(), 0);
    assert_eq!(closed(), [501]);
    assert_eq!(queue.write_with_rights(b"abc", bundle(&[])).ok(), Some(3));
    assert_eq!(queue.ancillary_leases().count(), 0);
    assert_eq!(queue.read(&mut [0; 8]), 3);
}

#[test]
fn stream_short_writes_transfer_once_and_queue_survives_sender_close_until_eof() {
    let (mut streams, [a, b]) = pair();
    streams.set_receive_capacity(b, 256).unwrap();
    assert_eq!(streams.write(a, &[0; 255]), Ok(255));
    assert_eq!(
        streams
            .commit_stream_with_rights(a, b"abc", bundle(&[501]))
            .ok(),
        Some((1, [a, b]))
    );
    assert!(streams.has_ancillary_records());
    streams.release(a).unwrap();
    let mut bytes = [0; 512];
    let (count, rights) = streams.read_stream_with_rights(b, &mut bytes).unwrap();
    assert_eq!(count, 256);
    assert_eq!(bytes[255], b'a');
    assert_eq!(rights.as_ref().map(Bundle::len), Some(1));
    assert!(!streams.has_ancillary_records());
    drop(rights);
    assert_eq!(closed(), [501]);
    assert_eq!(streams.read(b, &mut bytes), Ok(0));
}

#[test]
fn shutdown_and_final_close_release_all_queued_stream_rights() {
    let (mut streams, [a, b]) = pair();
    streams
        .commit_stream_with_rights(a, b"a", bundle(&[501]))
        .ok()
        .unwrap();
    streams.shutdown(b, Shutdown::Read).unwrap();
    assert_eq!(closed(), [501]);
    let (error, rights) = streams
        .commit_stream_with_rights(a, b"b", bundle(&[502]))
        .err()
        .unwrap();
    assert_eq!(error, -32);
    assert_eq!(rights.len(), 1);
    drop(rights);
    assert_eq!(closed(), [501, 502]);
    let (mut streams, [a, b]) = pair();
    streams
        .commit_stream_with_rights(a, b"a", bundle(&[503]))
        .ok()
        .unwrap();
    streams.release(b).unwrap();
    assert_eq!(closed(), [503]);
}

#[test]
fn stream_socket_reference_cycles_share_the_existing_conservative_collector() {
    let (mut streams, [a, b]) = pair();
    streams
        .commit_stream_with_rights(a, b"a", bundle(&[501, 502]))
        .ok()
        .unwrap();
    assert!(streams.has_ancillary_records());
    assert!(
        streams
            .collect_record_cycles(|_| Ok(Some(b)), |_| Ok(3))
            .unwrap()
            .is_empty()
    );
    assert!(closed().is_empty());
    assert_eq!(
        streams.collect_record_cycles(|_| Ok(Some(b)), |_| Ok(2)),
        Ok(vec![b])
    );
    assert_eq!(closed(), [501, 502]);
    assert!(!streams.has_ancillary_records());
    assert!(!streams.readiness(b).unwrap().readable);
}

struct Buffer {
    bytes: Vec<u8>,
    read: usize,
    fail: bool,
}

#[test]
fn stream_peek_receipts_stop_at_ancillary_barrier_and_outlive_consuming_read() {
    let (mut streams, [a, b]) = pair();
    let budget = Budget::new(6);
    streams.write(a, b"aa").unwrap();
    streams
        .commit_stream_with_rights(a, b"bcd", bundle_using(&[501, 502], &budget))
        .ok()
        .unwrap();
    streams.write(a, b"ee").unwrap();
    let mut transfers = posix_service::socket_transfer::Transfers::new(0);
    let mut buffer = Buffer {
        bytes: vec![0; 16],
        read: 0,
        fail: false,
    };
    let mut receipts = Vec::new();
    for source in [900, 901] {
        let mut published = None;
        let result = transfers
            .peek(
                &mut streams,
                b,
                source,
                2,
                8,
                1,
                close,
                |id, info| {
                    published = Some((info, id));
                    Ok(())
                },
                &mut buffer,
            )
            .unwrap();
        assert_eq!(Some(result), published);
        assert_eq!(
            (
                result.0.record.copied,
                result.0.record.length,
                result.0.total_rights,
                result.0.available_rights
            ),
            (5, 5, 2, 1)
        );
        assert_eq!(&buffer.bytes[2..7], b"aabcd");
        assert!(closed().is_empty());
        receipts.push(result.1.unwrap());
    }
    assert_eq!(budget.used(), 4);
    let mut data = [0; 16];
    assert_eq!(streams.read(b, &mut data), Ok(5));
    assert_eq!(&data[..5], b"aabcd");
    assert_eq!(closed(), [502]);
    assert_eq!(budget.used(), 2);
    assert_eq!(streams.read(b, &mut data), Ok(2));
    assert_eq!(&data[..2], b"ee");
    streams.shutdown(a, Shutdown::Write).unwrap();
    let (info, receipt) = transfers
        .peek(
            &mut streams,
            b,
            902,
            0,
            8,
            1,
            close,
            |_, _| Ok(()),
            &mut buffer,
        )
        .unwrap();
    assert_eq!(info.record.copied, 0);
    assert!(receipt.is_none());
    for receipt in receipts {
        assert_eq!(
            transfers.deliver(receipt, 0, 4, |leases| {
                assert_eq!(leases.len(), 1);
                assert_eq!(leases[0].handle(), 501);
                assert_eq!(
                    leases[0].rights(),
                    mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER
                );
                Ok(())
            }),
            Ok(1)
        );
        transfers.release(receipt).unwrap();
    }
    assert_eq!(closed(), [502, 900, 501, 901]);
    assert_eq!(budget.used(), 0);
}

#[test]
fn stream_peek_without_visible_control_never_discards_queued_rights() {
    let (mut streams, [a, b]) = pair();
    let budget = Budget::new(1);
    streams.write(a, b"aa").unwrap();
    streams
        .commit_stream_with_rights(a, b"bcd", bundle_using(&[501], &budget))
        .ok()
        .unwrap();
    let mut transfers = posix_service::socket_transfer::Transfers::new(0);
    let mut buffer = Buffer {
        bytes: vec![0; 8],
        read: 0,
        fail: false,
    };
    for (length, maximum, total) in [(0, 1, 0), (2, 1, 0), (3, 0, 1)] {
        let (info, receipt) = transfers
            .peek(
                &mut streams,
                b,
                900,
                0,
                length,
                maximum,
                close,
                |id, info| {
                    assert!(id.is_none());
                    assert_eq!(info.total_rights, total);
                    Ok(())
                },
                &mut buffer,
            )
            .unwrap();
        assert_eq!(info.record.copied, length as usize);
        assert!(receipt.is_none());
        assert_eq!(budget.used(), 1);
        assert!(closed().is_empty());
        assert_eq!(streams.peek(b, 0, &mut [0; 8]), Ok(5));
    }
}

#[test]
fn stream_peek_failures_rollback_pins_before_another_read() {
    let mut failures = 0;
    for allocation in 0..4 {
        let (mut streams, [a, b]) = pair();
        let budget = Budget::new(2);
        streams
            .commit_stream_with_rights(a, b"abc", bundle_using(&[501], &budget))
            .ok()
            .unwrap();
        let mut transfers = posix_service::socket_transfer::Transfers::new(0);
        let mut buffer = Buffer {
            bytes: vec![0; 8],
            read: 0,
            fail: false,
        };
        FAIL.with(|remaining| remaining.set(allocation));
        let result = transfers.peek(
            &mut streams,
            b,
            900,
            0,
            8,
            1,
            close,
            |_, _| Ok(()),
            &mut buffer,
        );
        FAIL.with(|remaining| remaining.set(-1));
        match result {
            Err(error) => {
                assert_eq!(error, -12);
                failures += 1;
            }
            Ok((_, receipt)) => transfers.release(receipt.unwrap()).unwrap(),
        }
        assert_eq!(budget.used(), 1);
        assert_eq!(streams.peek(b, 0, &mut [0; 8]), Ok(3));
        buffer.fail = true;
        assert_eq!(
            transfers.peek(
                &mut streams,
                b,
                901,
                0,
                8,
                1,
                close,
                |_, _| panic!("copy failed"),
                &mut buffer
            ),
            Err(-5)
        );
        buffer.fail = false;
        assert_eq!(
            transfers.peek(
                &mut streams,
                b,
                901,
                0,
                8,
                1,
                close,
                |_, _| Err(-5),
                &mut buffer
            ),
            Err(-5)
        );
        assert_eq!(budget.used(), 1);
        assert_eq!(streams.read(b, &mut [0; 8]), Ok(3));
        assert_eq!(budget.used(), 0);
        assert_eq!(closed().last(), Some(&501));
    }
    assert_eq!(failures, 3);
}
impl posix_service::socket_record_io::RecordBuffer for Buffer {
    fn extent(&self) -> Result<u64, i32> {
        Ok(self.bytes.len() as u64)
    }
    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), i32> {
        if self.fail {
            return Err(-5);
        }
        self.read = output.len();
        output.copy_from_slice(&self.bytes[offset as usize..offset as usize + output.len()]);
        Ok(())
    }
    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), i32> {
        if self.fail {
            return Err(-5);
        }
        self.bytes[offset as usize..offset as usize + input.len()].copy_from_slice(input);
        Ok(())
    }
}
fn stage(
    transfers: &mut posix_service::socket_transfer::Transfers,
    streams: &Streams,
    socket: u64,
    length: u32,
    source: u32,
    file: u32,
) -> u64 {
    let id = transfers
        .start(streams, socket, source, length, 1, close)
        .unwrap();
    transfers
        .append(
            id,
            0,
            vec![
                Lease::adopt(
                    file,
                    mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
                    InheritedFdMetadata {
                        kind: 5,
                        open_flags: 0,
                        descriptor_flags: 0,
                    },
                    close,
                )
                .ok()
                .unwrap(),
            ],
        )
        .unwrap();
    id
}

#[test]
fn staged_stream_commit_copies_only_accepted_prefix_and_never_replays_rights() {
    let (mut streams, [a, b]) = pair();
    let mut transfers = posix_service::socket_transfer::Transfers::new(1);
    streams.set_receive_capacity(b, 256).unwrap();
    streams.write(a, &[0; 255]).unwrap();
    let id = stage(&mut transfers, &streams, a, 512, 900, 501);
    let mut buffer = Buffer {
        bytes: vec![b'x'; 512],
        read: 0,
        fail: true,
    };
    assert_eq!(transfers.commit(&mut streams, id, 0, &mut buffer), Err(-5));
    assert_eq!(transfers.progress(id).unwrap().2, 1);
    assert!(closed().is_empty());
    buffer.fail = false;
    assert_eq!(
        transfers.commit(&mut streams, id, 0, &mut buffer),
        Ok((1, [a, b]))
    );
    assert_eq!(buffer.read, 1);
    assert_eq!(
        transfers.commit(&mut streams, id, 0, &mut buffer),
        Err(-114)
    );
    transfers.release(id).unwrap();
    assert_eq!(closed(), [900]);
    let mut output = [0; 512];
    let (count, rights) = streams.read_stream_with_rights(b, &mut output).unwrap();
    assert_eq!(count, 256);
    assert_eq!(output[255], b'x');
    assert_eq!(rights.as_ref().unwrap().leases()[0].handle(), 501);
    drop(rights);
    assert_eq!(closed(), [900, 501]);
}

#[test]
fn ancillary_wait_needs_marker_capacity_even_when_plain_stream_is_writable() {
    let (mut streams, [a, b]) = pair();
    for index in 0..MAX_MARKERS {
        streams
            .commit_stream_with_rights(a, b"x", bundle(&[1000 + index as u32]))
            .ok()
            .unwrap();
    }
    assert!(streams.readiness(a).unwrap().writable);
    assert_eq!(streams.ancillary_send_ready(a, 1), Ok(false));
    let mut waits = posix_service::socket_receive_wait::ReceiveWaits::new();
    let job = waits.start_send(&streams, a, 1, 900u32).unwrap();
    waits.pump(&streams, |_| panic!("no busy wake on plain POLLOUT"));
    streams.read(b, &mut [0; 1]).unwrap();
    let mut signaled = vec![];
    waits.pump(&streams, |id| signaled.push(id));
    assert_eq!(signaled, [job]);
    waits.release(job, close).unwrap();
    assert_eq!(closed(), [1000, 900]);
}

#[test]
fn staged_empty_stream_send_drops_rights_without_creating_readability() {
    let (mut streams, [a, b]) = pair();
    let mut transfers = posix_service::socket_transfer::Transfers::new(1);
    let job = stage(&mut transfers, &streams, a, 0, 900, 501);
    let mut buffer = Buffer {
        bytes: vec![],
        read: 0,
        fail: false,
    };
    assert_eq!(
        transfers.commit(&mut streams, job, 0, &mut buffer),
        Ok((0, [a, a]))
    );
    assert!(!streams.readiness(b).unwrap().readable);
    assert_eq!(closed(), [501]);
    transfers.release(job).unwrap();
    assert_eq!(closed(), [501, 900]);
}

#[test]
fn stream_receipt_publication_is_atomic_and_delivery_truncates_once_at_the_barrier() {
    let (mut streams, [a, b]) = pair();
    streams.write(a, b"aa").unwrap();
    streams
        .commit_stream_with_rights(a, b"bcd", bundle(&[501, 502]))
        .ok()
        .unwrap();
    streams.write(a, b"ee").unwrap();
    let mut transfers = posix_service::socket_transfer::Transfers::new(2);
    let mut buffer = Buffer {
        bytes: vec![b'-'; 32],
        read: 0,
        fail: true,
    };
    assert_eq!(
        transfers.receive(
            &mut streams,
            b,
            900,
            3,
            16,
            1,
            close,
            |_, _| panic!("copy failed before publication"),
            &mut buffer
        ),
        Err(-5)
    );
    buffer.fail = false;
    assert_eq!(
        transfers.receive(
            &mut streams,
            b,
            900,
            3,
            16,
            1,
            close,
            |id, info| {
                assert_eq!(id, Some(1));
                assert_eq!(info.record.copied, 5);
                Err(-5)
            },
            &mut buffer
        ),
        Err(-5)
    );
    assert!(closed().is_empty());
    assert!(streams.has_ancillary_records());
    assert_eq!(streams.peek(b, 0, &mut [0; 16]), Ok(5));
    let (info, receipt) = transfers
        .receive(
            &mut streams,
            b,
            900,
            3,
            16,
            1,
            close,
            |id, info| {
                assert_eq!(id, Some(2)); // A failed publication's identity cannot be reused.
                assert_eq!(
                    (
                        info.record.copied,
                        info.record.length,
                        info.total_rights,
                        info.available_rights
                    ),
                    (5, 5, 2, 1)
                );
                Ok(())
            },
            &mut buffer,
        )
        .unwrap();
    assert_eq!(&buffer.bytes[3..8], b"aabcd");
    assert_eq!(info.record.length, 5);
    assert_eq!(closed(), [502]);
    let receipt = receipt.unwrap();
    assert_eq!(transfers.release(1), Err(-9));
    assert_eq!(
        transfers.deliver(receipt, 0, 4, |leases| {
            assert_eq!(leases.len(), 1);
            assert_eq!(leases[0].handle(), 501);
            Ok(())
        }),
        Ok(1)
    );
    assert_eq!(closed(), [502, 501]);
    transfers.release(receipt).unwrap();
    assert_eq!(closed(), [502, 501, 900]);
    assert_eq!(streams.read(b, &mut [0; 16]), Ok(2));
}

#[test]
fn zero_length_stream_receive_does_not_consume_rights_and_no_control_discards_them() {
    let (mut streams, [a, b]) = pair();
    streams
        .commit_stream_with_rights(a, b"abc", bundle(&[501]))
        .ok()
        .unwrap();
    let mut transfers = posix_service::socket_transfer::Transfers::new(1);
    let mut buffer = Buffer {
        bytes: vec![0; 8],
        read: 0,
        fail: false,
    };
    let (info, receipt) = transfers
        .receive(
            &mut streams,
            b,
            900,
            0,
            0,
            1,
            close,
            |id, info| {
                assert!(id.is_none());
                assert_eq!(info.total_rights, 0);
                Ok(())
            },
            &mut buffer,
        )
        .unwrap();
    assert_eq!(info.record.copied, 0);
    assert!(receipt.is_none() && closed().is_empty() && streams.has_ancillary_records());
    let (info, receipt) = transfers
        .receive(
            &mut streams,
            b,
            900,
            0,
            1,
            0,
            close,
            |id, _| {
                assert!(id.is_none());
                Ok(())
            },
            &mut buffer,
        )
        .unwrap();
    assert_eq!(
        (info.record.copied, info.record.length, info.total_rights),
        (1, 1, 1)
    );
    assert!(receipt.is_none());
    assert_eq!(closed(), [501]);
    assert!(!streams.has_ancillary_records());
    assert_eq!(streams.read(b, &mut [0; 8]), Ok(2));
}

#[test]
fn every_stream_receipt_allocation_failure_preserves_data_and_all_references() {
    let mut failures = 0;
    for fail in 0..4 {
        let (mut streams, [a, b]) = pair();
        streams
            .commit_stream_with_rights(a, b"abc", bundle(&[501]))
            .ok()
            .unwrap();
        let mut transfers = posix_service::socket_transfer::Transfers::new(1);
        let mut buffer = Buffer {
            bytes: vec![0; 8],
            read: 0,
            fail: false,
        };
        FAIL.with(|remaining| remaining.set(fail));
        let result = transfers.receive(
            &mut streams,
            b,
            900,
            0,
            8,
            1,
            close,
            |_, _| Ok(()),
            &mut buffer,
        );
        FAIL.with(|remaining| remaining.set(-1));
        match result {
            Err(error) => {
                assert_eq!(error, -12);
                assert!(closed().is_empty());
                assert_eq!(streams.peek(b, 0, &mut [0; 8]), Ok(3));
                assert!(streams.has_ancillary_records());
                failures += 1;
            }
            Ok((info, receipt)) => {
                assert_eq!(info.total_rights, 1);
                transfers.release(receipt.unwrap()).unwrap();
                assert_eq!(closed(), [900, 501]);
                break;
            }
        }
    }
    assert_eq!(failures, 2);
}

#[test]
fn external_peek_snapshot_is_a_gc_root_until_released_without_changing_the_queue() {
    let (mut streams, [a, b]) = pair();
    let budget = Budget::new(2);
    streams
        .commit_stream_with_rights(a, b"abc", bundle_using(&[501], &budget))
        .ok()
        .unwrap();
    let snapshot = streams.snapshot_queued_rights(b, 1, 1).unwrap().unwrap();
    assert_eq!(snapshot.leases()[0].handle(), 501);
    assert_eq!(
        streams.collect_record_cycles(|_| Ok(Some(b)), |_| Ok(1)),
        Ok(vec![])
    );
    assert_eq!(streams.peek(b, 0, &mut [0; 8]), Ok(3));
    assert!(closed().is_empty());
    drop(snapshot);
    assert_eq!(
        streams.collect_record_cycles(|_| Ok(Some(b)), |_| Ok(1)),
        Ok(vec![b])
    );
    assert_eq!(closed(), [501]);
}

#[test]
fn peek_snapshot_survives_another_reader_consuming_and_closing_the_source_queue() {
    let (mut streams, [a, b]) = pair();
    let budget = Budget::new(3);
    streams.write(a, b"aa").unwrap();
    streams
        .commit_stream_with_rights(a, b"bcd", bundle_using(&[501, 502], &budget))
        .ok()
        .unwrap();
    assert!(streams.snapshot_queued_rights(b, 2, 2).unwrap().is_none());
    let mut snapshot = streams.snapshot_queued_rights(b, 3, 1).unwrap().unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(streams.read(b, &mut [0; 8]), Ok(5));
    assert_eq!(closed(), [502]);
    streams.release(b).unwrap();
    assert_eq!(snapshot.leases()[0].handle(), 501);
    snapshot.discard_delivered_prefix(1).unwrap();
    assert_eq!(closed(), [502, 501]);
}
