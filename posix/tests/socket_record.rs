use mochios_posix_protocol::socket::{Address, MAX_UNIX_NAME_BYTES};
use posix_service::socket_record::{
    RecordQueue, SourceAddress, MAX_QUEUED_RECORDS, MAX_RECORD_SIZE,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::VecDeque;

thread_local! {
    // Allocation fault injection is local to this test thread, not the harness
    // or concurrent tests. Fail exactly once; ordinary assertion output works.
    static FAIL_AFTER: Cell<isize> = const { Cell::new(-1) };
}
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
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn unnamed() -> SourceAddress {
    SourceAddress::new(Address::UnixUnnamed).unwrap()
}

#[test]
fn source_is_owned_and_preserves_all_unix_name_forms() {
    let mut name = [b'a'; MAX_UNIX_NAME_BYTES];
    name[1] = 0;
    let saved = SourceAddress::new(Address::UnixAbstract(&name)).unwrap();
    name.fill(0x55);
    let Address::UnixAbstract(original) = Address::decode(saved.encoded()).unwrap() else {
        panic!("abstract source changed type");
    };
    assert_eq!(original.len(), MAX_UNIX_NAME_BYTES);
    assert_eq!((original[0], original[1], original[2]), (b'a', 0, b'a'));
    for address in [
        Address::UnixUnnamed,
        Address::UnixAbstract(b""),
        Address::UnixPath(b"/socket"),
    ] {
        let saved = SourceAddress::new(address).unwrap();
        assert_eq!(Address::decode(saved.encoded()), Ok(address));
    }
    for address in [
        Address::UnixPath(b""),
        Address::UnixPath(b"bad\0name"),
        Address::UnixAbstract(&[1; MAX_UNIX_NAME_BYTES + 1]),
    ] {
        assert_eq!(SourceAddress::new(address), Err(-22));
    }
    assert_eq!(
        SourceAddress::new(Address::Ipv4 {
            address: [0; 4],
            port: 80
        }),
        Err(-97)
    );
}

#[test]
fn one_receive_cannot_merge_records_and_truncation_discards_only_the_head() {
    let mut queue = RecordQueue::new();
    let first = SourceAddress::new(Address::UnixPath(b"/first")).unwrap();
    let second = SourceAddress::new(Address::UnixAbstract(b"next\0sender")).unwrap();
    queue.push(first, b"abcdef", MAX_RECORD_SIZE).unwrap();
    queue.push(second, b"next", MAX_RECORD_SIZE).unwrap();
    let mut short = [0x55; 2];
    for _ in 0..3 {
        let record = queue.receive(&mut short, true).unwrap();
        assert_eq!((record.copied, record.length, record.source), (2, 6, first));
        assert!(record.truncated());
        assert_eq!(short, *b"ab");
        assert_eq!((queue.len(), queue.charged()), (2, 10));
    }
    assert!(queue.receive(&mut short, false).unwrap().truncated());
    let mut large = [0x55; 20];
    let record = queue.receive(&mut large, false).unwrap();
    assert_eq!(
        (record.copied, record.length, record.source),
        (4, 4, second)
    );
    assert!(!record.truncated());
    assert_eq!(&large[..4], b"next");
    assert_eq!(&large[4..], &[0x55; 16]);
    assert_eq!(
        (queue.len(), queue.charged(), queue.is_readable()),
        (0, 0, false)
    );
    assert_eq!(queue.receive(&mut large, false), Err(-11));
}

#[test]
fn empty_messages_are_readable_bounded_records_not_eof_or_noop() {
    let mut queue = RecordQueue::new();
    for _ in 0..MAX_QUEUED_RECORDS {
        assert_eq!(queue.push(unnamed(), b"", MAX_RECORD_SIZE), Ok(0));
    }
    assert!(queue.is_readable());
    assert_eq!(
        (queue.len(), queue.charged()),
        (MAX_QUEUED_RECORDS, MAX_QUEUED_RECORDS)
    );
    assert_eq!(queue.push(unnamed(), b"", MAX_RECORD_SIZE), Err(-11));
    assert_eq!(queue.receive(&mut [], true).unwrap().length, 0);
    assert_eq!(queue.len(), MAX_QUEUED_RECORDS);
    assert_eq!(queue.receive(&mut [], false).unwrap().copied, 0);
    assert_eq!(queue.push(unnamed(), b"", MAX_RECORD_SIZE), Ok(0));
    queue.clear();
    assert!(queue.is_empty());
    assert_eq!(queue.charged(), 0);
    assert_eq!(queue.receive(&mut [], false), Err(-11));
    queue.push(unnamed(), b"abc", MAX_RECORD_SIZE).unwrap();
    assert!(queue.receive(&mut [], false).unwrap().truncated());
    assert!(queue.is_empty());
}

#[test]
fn peer_filter_uses_internal_sender_identity_even_when_names_are_identical() {
    let mut queue = RecordQueue::new();
    queue
        .push_from(unnamed(), b"old", MAX_RECORD_SIZE, Some(1))
        .unwrap();
    queue
        .push_from(unnamed(), b"new", MAX_RECORD_SIZE, Some(2))
        .unwrap();
    queue
        .push_from(unnamed(), b"", MAX_RECORD_SIZE, Some(1))
        .unwrap();
    queue
        .push_from(unnamed(), b"", MAX_RECORD_SIZE, Some(2))
        .unwrap();
    queue.retain_sender(2);
    assert_eq!((queue.len(), queue.charged()), (2, 4));
    let mut bytes = [0; 8];
    assert_eq!(queue.receive(&mut bytes, false).unwrap().copied, 3);
    assert_eq!(&bytes[..3], b"new");
    assert_eq!(queue.receive(&mut bytes, false).unwrap().copied, 0);
    assert_eq!((queue.len(), queue.charged()), (0, 0));
}

#[test]
fn capacity_and_message_size_failures_never_commit_prefixes() {
    let mut queue = RecordQueue::new();
    let maximum = vec![0x77; MAX_RECORD_SIZE];
    assert_eq!(
        queue.push(unnamed(), &maximum, MAX_RECORD_SIZE - 1),
        Err(-90)
    );
    assert!(queue.is_empty());
    assert_eq!(queue.can_push(usize::MAX, usize::MAX), Err(-90));
    assert_eq!(
        queue.push(unnamed(), &maximum, MAX_RECORD_SIZE),
        Ok(MAX_RECORD_SIZE)
    );
    assert_eq!(queue.push(unnamed(), b"x", MAX_RECORD_SIZE), Err(-11));
    assert_eq!(queue.push(unnamed(), b"", MAX_RECORD_SIZE), Err(-11));
    assert_eq!(queue.capacity(), MAX_RECORD_SIZE);
    assert_eq!(queue.set_capacity(u32::MAX), Err(-22));
    assert_eq!(queue.capacity(), MAX_RECORD_SIZE);
    queue.set_capacity(0).unwrap();
    assert_eq!(
        queue.capacity(),
        posix_service::socket::MIN_RECEIVE_CAPACITY
    );
    assert_eq!(queue.charged(), MAX_RECORD_SIZE);
    assert_eq!(
        queue.can_push(queue.capacity() + 1, MAX_RECORD_SIZE),
        Err(-90)
    );
    let mut output = vec![0; MAX_RECORD_SIZE + 3];
    assert_eq!(
        queue.receive(&mut output, false).unwrap().length,
        MAX_RECORD_SIZE
    );
    assert_eq!(&output[..MAX_RECORD_SIZE], maximum.as_slice());
    assert_eq!(&output[MAX_RECORD_SIZE..], &[0; 3]);
    assert_eq!(queue.charged(), 0);
    assert_eq!(queue.push(unnamed(), b"x", MAX_RECORD_SIZE), Ok(1));
}

#[test]
fn allocation_failures_leave_no_record_or_budget_committed() {
    // First allocation owns payload; the second grows the record deque.
    // Failure at either boundary must return ENOMEM without visible progress.
    for failure in [0, 1] {
        let mut queue = RecordQueue::new();
        let source = unnamed();
        FAIL_AFTER.with(|remaining| remaining.set(failure));
        let result = queue.push(source, b"record", MAX_RECORD_SIZE);
        FAIL_AFTER.with(|remaining| remaining.set(-1));
        assert_eq!(result, Err(-12));
        assert_eq!((queue.len(), queue.charged()), (0, 0));
        assert!(!queue.is_readable());
        queue.push(source, b"retry", MAX_RECORD_SIZE).unwrap();
        let mut output = [0; 5];
        assert_eq!(queue.receive(&mut output, false).unwrap().length, 5);
        assert_eq!(output, *b"retry");
    }
}

#[test]
fn failed_queue_growth_preserves_existing_records_and_their_sources() {
    let mut growth_failures = 0;
    // Exercise deque growth without relying on the allocator's growth factor.
    for existing in 1..=128u64 {
        let mut queue = RecordQueue::new();
        for number in 0..existing {
            let name = number.to_le_bytes();
            let source = SourceAddress::new(Address::UnixAbstract(&name)).unwrap();
            queue.push(source, &name, MAX_RECORD_SIZE).unwrap();
        }
        FAIL_AFTER.with(|remaining| remaining.set(1));
        let result = queue.push(unnamed(), b"new", MAX_RECORD_SIZE);
        FAIL_AFTER.with(|remaining| remaining.set(-1));
        if result == Err(-12) {
            growth_failures += 1;
            assert_eq!(
                (queue.len(), queue.charged()),
                (existing as usize, existing as usize * 8)
            );
        } else {
            assert_eq!(result, Ok(3));
        }
        for number in 0..existing {
            let mut output = [0; 8];
            let record = queue.receive(&mut output, false).unwrap();
            assert_eq!(output, number.to_le_bytes());
            assert_eq!(
                Address::decode(record.source.encoded()).unwrap(),
                Address::UnixAbstract(&output)
            );
        }
        if result.is_ok() {
            assert_eq!(queue.receive(&mut [0; 3], false).unwrap().length, 3);
        }
        assert_eq!((queue.len(), queue.charged()), (0, 0));
    }
    assert!(
        growth_failures > 0,
        "the growth failure path must actually run"
    );
}

#[test]
fn wrapped_fifo_matches_record_oracle_across_peek_consume_resize_and_clear() {
    let mut queue = RecordQueue::new();
    let mut oracle: VecDeque<(SourceAddress, Vec<u8>)> = VecDeque::new();
    let mut sequence = 1u64;
    let mut capacity = MAX_RECORD_SIZE;
    let mut charged = 0usize;
    for step in 0..12000usize {
        sequence = sequence.wrapping_mul(6364136223846793005).wrapping_add(1);
        match (sequence >> 32) % 12 {
            0..=5 => {
                let length = (sequence as usize >> 8) % 350;
                let data = vec![step as u8; length];
                let name = (step as u64).to_le_bytes();
                let source = SourceAddress::new(Address::UnixAbstract(&name)).unwrap();
                let result = queue.push(source, &data, MAX_RECORD_SIZE);
                let expected = if length.max(1) > capacity {
                    Err(-90)
                } else if oracle.len() == MAX_QUEUED_RECORDS
                    || length.max(1) > capacity.saturating_sub(charged)
                {
                    Err(-11)
                } else {
                    Ok(length)
                };
                assert_eq!(result, expected);
                if result.is_ok() {
                    charged += length.max(1);
                    oracle.push_back((source, data));
                }
            }
            6..=9 => {
                let mut output = vec![0x55; (sequence as usize >> 4) % 450];
                let peek = sequence & 1 != 0;
                let result = queue.receive(&mut output, peek);
                if let Some((source, data)) = oracle.front() {
                    let record = result.unwrap();
                    let count = output.len().min(data.len());
                    assert_eq!(
                        (record.copied, record.length, record.source),
                        (count, data.len(), *source)
                    );
                    assert_eq!(&output[..count], &data[..count]);
                    assert!(output[count..].iter().all(|byte| *byte == 0x55));
                    if !peek {
                        charged -= data.len().max(1);
                        oracle.pop_front();
                    }
                } else {
                    assert_eq!(result, Err(-11));
                    assert!(output.iter().all(|byte| *byte == 0x55));
                }
            }
            10 => {
                let requested = ((sequence >> 16) % 1000) as u32;
                queue.set_capacity(requested).unwrap();
                capacity = (requested as usize)
                    .clamp(posix_service::socket::MIN_RECEIVE_CAPACITY, MAX_RECORD_SIZE);
            }
            _ => {
                queue.clear();
                oracle.clear();
                charged = 0;
            }
        }
        assert_eq!(
            (queue.len(), queue.charged(), queue.capacity()),
            (oracle.len(), charged, capacity)
        );
        assert_eq!(queue.is_readable(), !oracle.is_empty());
    }
}
