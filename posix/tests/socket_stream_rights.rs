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
    let mut pending = Pending::new(handles.len(), &budget).unwrap();
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
