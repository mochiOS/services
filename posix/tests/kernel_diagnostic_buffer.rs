extern crate alloc;

include!("../../../core/src/util/diagnostic_buffer.rs");

// Compile the actual audit adapter, not a copy. No filesystem, configuration,
// or persistence dependencies are supplied by this host fixture.
mod interrupt {
    pub mod spinlock {
        pub struct SpinLock<T>(std::sync::Mutex<T>);
        impl<T> SpinLock<T> {
            pub const fn new(value: T) -> Self {
                Self(std::sync::Mutex::new(value))
            }
            pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
                self.0.lock().unwrap()
            }
        }
    }
}
mod util {
    pub mod diagnostic_buffer {
        pub use crate::{ByteRing, CursorError, ReadResult};
    }
}
#[macro_export]
macro_rules! warn {
    ($($argument:tt)*) => {{ let _ = format_args!($($argument)*); }};
}
#[path = "../../../core/src/audit.rs"]
#[allow(dead_code)]
mod audit;

#[test]
fn cursors_are_independent_and_advance_only_after_the_caller_accepts_a_read() {
    let mut ring = ByteRing::<8>::new();
    ring.append(b"abcde").unwrap();
    let mut first = [0; 2];
    let read = ring.read(0, &mut first).unwrap();
    assert_eq!(
        (first, read),
        (
            *b"ab",
            ReadResult {
                bytes: 2,
                next: 2,
                dropped: 0
            }
        )
    );
    let mut second = [0; 5];
    assert_eq!(ring.read(0, &mut second).unwrap().next, 5);
    assert_eq!(&second, b"abcde");
    assert_eq!(ring.read(0, &mut first).unwrap(), read); // retry before commit
    assert_eq!(ring.read(read.next, &mut first).unwrap().next, 4);
    assert_eq!(&first, b"cd");
}

#[test]
fn overwrites_report_the_exact_gap_and_resume_from_the_oldest_retained_byte() {
    let mut ring = ByteRing::<8>::new();
    ring.append(b"abcdef").unwrap();
    ring.append(b"ghijk").unwrap();
    assert_eq!((ring.oldest(), ring.end(), ring.len()), (3, 11, 8));
    let mut output = [0; 8];
    assert_eq!(
        ring.read(1, &mut output),
        Ok(ReadResult {
            bytes: 8,
            next: 11,
            dropped: 2
        })
    );
    assert_eq!(&output, b"defghijk");
    assert_eq!(ring.read(11, &mut output).unwrap().bytes, 0);
}

#[test]
fn oversized_appends_and_zero_capacity_reads_keep_absolute_position() {
    let mut ring = ByteRing::<4>::new();
    ring.append(b"0123456789").unwrap();
    assert_eq!(
        ring.read(0, &mut []),
        Ok(ReadResult {
            bytes: 0,
            next: 6,
            dropped: 6
        })
    );
    let mut bytes = [0; 4];
    assert_eq!(ring.read(6, &mut bytes).unwrap().next, 10);
    assert_eq!(&bytes, b"6789");
    ring.append(&[]).unwrap();
    assert_eq!((ring.oldest(), ring.end()), (6, 10));
}

#[test]
fn invalid_or_exhausted_cursors_do_not_modify_retained_data_or_output() {
    let mut ring = ByteRing::<8> {
        data: *b"last....",
        start: 0,
        length: 4,
        head: u64::MAX - 4,
    };
    assert_eq!(ring.append(b"!"), Err(CursorError::Exhausted));
    let mut bytes = [0; 4];
    assert_eq!(ring.read(u64::MAX - 4, &mut bytes).unwrap().next, u64::MAX);
    assert_eq!(&bytes, b"last");
    let ring = ByteRing::<8>::new();
    assert_eq!(ring.read(1, &mut bytes), Err(CursorError::Ahead));
    assert_eq!(&bytes, b"last");
}

#[test]
fn ring_matches_a_linear_history_across_repeated_wraps() {
    let mut ring = ByteRing::<17>::new();
    let mut history = Vec::new();
    for index in 0..100usize {
        let bytes: Vec<_> = (0..index % 31).map(|byte| (index + byte) as u8).collect();
        history.extend_from_slice(&bytes);
        ring.append(&bytes).unwrap();
        let oldest = history.len().saturating_sub(17);
        for cursor in 0..=history.len() {
            let mut output = [0xff; 11];
            let read = ring.read(cursor as u64, &mut output).unwrap();
            let begin = cursor.max(oldest);
            let count = (history.len() - begin).min(output.len());
            assert_eq!(
                read,
                ReadResult {
                    bytes: count,
                    next: (begin + count) as u64,
                    dropped: oldest.saturating_sub(cursor) as u64
                }
            );
            assert_eq!(&output[..count], &history[begin..begin + count]);
        }
    }
}

#[test]
fn actual_audit_retention_supports_independent_chunked_reads_without_storage() {
    for _ in 0..600 {
        audit::log(
            audit::AuditEventKind::Deny,
            "diagnostic cursor retention test: abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
        );
    }
    let mut snapshot = vec![0; 64 * 1024];
    let read = audit::read_cursor(0, &mut snapshot).unwrap();
    assert!(read.dropped > 0);
    assert_eq!(read.bytes, snapshot.len());
    let mut collected = Vec::new();
    let mut cursor = 0;
    loop {
        let mut chunk = [0; 257];
        let batch = audit::read_cursor(cursor, &mut chunk).unwrap();
        if batch.bytes == 0 {
            break;
        }
        collected.extend_from_slice(&chunk[..batch.bytes]);
        cursor = batch.next;
    }
    assert_eq!(collected, snapshot);
    assert_eq!(cursor, read.next);
    assert_eq!(audit::read_cursor(read.next, &mut [0; 4]).unwrap().bytes, 0);
}
