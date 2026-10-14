use std::collections::VecDeque;

#[path = "../../logger/src/diagnostic_drain.rs"]
mod drain;
use drain::{Backend, Batch, Drain, Error};

#[derive(Default)]
struct Storage {
    history: Vec<u8>,
    oldest: usize,
    disk: Vec<u8>,
    writes: VecDeque<Result<usize, &'static str>>,
    syncs: VecDeque<Result<(), &'static str>>,
    reads: Vec<u64>,
    sync_count: usize,
    read_error: Option<&'static str>,
    invalid_read: bool,
}

impl Backend for Storage {
    type Error = &'static str;

    fn read(&mut self, cursor: u64, output: &mut [u8]) -> Result<Batch, Self::Error> {
        self.reads.push(cursor);
        if let Some(error) = self.read_error.take() {
            return Err(error);
        }
        if self.invalid_read {
            return Ok(Batch {
                bytes: output.len() + 1,
                next_cursor: 0,
                dropped: 0,
            });
        }
        let start = (cursor as usize).max(self.oldest);
        let count = (self.history.len() - start).min(output.len());
        output[..count].copy_from_slice(&self.history[start..start + count]);
        Ok(Batch {
            bytes: count,
            next_cursor: (start + count) as u64,
            dropped: (start as u64) - cursor,
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        let written = self.writes.pop_front().unwrap_or(Ok(bytes.len()))?;
        if written <= bytes.len() {
            self.disk.extend_from_slice(&bytes[..written]);
        }
        Ok(written)
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        self.sync_count += 1;
        self.syncs.pop_front().unwrap_or(Ok(()))
    }
}

fn storage(history: &[u8]) -> Storage {
    Storage {
        history: history.into(),
        ..Storage::default()
    }
}

#[test]
fn logger_requests_read_only_diagnostics_without_kernel_debug_authority() {
    let manifest =
        mochi_user_platform::package::parse_manifest(include_str!("../../logger/manifest.toml"))
            .unwrap();
    let capabilities = manifest
        .binary_requires("/system/services/logger.service")
        .unwrap();
    assert!(capabilities.iter().any(|cap| cap == "diagnostics.read"));
    assert!(!capabilities.iter().any(|cap| cap == "kernel.debug"));
}

#[test]
fn short_write_then_failure_resumes_at_the_first_unwritten_byte() {
    let mut backend = storage(b"abcdef");
    backend.writes.extend([Ok(2), Err("full")]);
    let mut reader = Drain::new();
    assert_eq!(reader.step(&mut backend), Err(Error::Backend("full")));
    assert_eq!(backend.disk, b"ab");
    assert_eq!(backend.reads, [0]);
    assert_eq!(backend.sync_count, 0);
    assert_eq!(reader.step(&mut backend), Ok(true));
    assert_eq!(backend.disk, b"abcdef");
    assert_eq!(backend.reads, [0]);
    assert_eq!(reader.step(&mut backend), Ok(false));
    assert_eq!(backend.reads, [0, 6]);
}

#[test]
fn failed_sync_retries_sync_without_reappending_or_reading_new_history() {
    let mut backend = storage(b"first");
    backend.syncs.extend([Err("sync failed"), Ok(())]);
    let mut reader = Drain::new();
    assert_eq!(
        reader.step(&mut backend),
        Err(Error::Backend("sync failed"))
    );
    backend.history.extend_from_slice(b"second");
    assert_eq!(reader.step(&mut backend), Ok(true));
    assert_eq!(backend.disk, b"first");
    assert_eq!(backend.reads, [0]);
    assert_eq!(backend.sync_count, 2);
    assert_eq!(reader.step(&mut backend), Ok(true));
    assert_eq!(backend.disk, b"firstsecond");
    assert_eq!(backend.reads, [0, 5]);
}

#[test]
fn byte_history_does_not_require_utf8_or_record_boundaries() {
    let history = [0xff, 0xe3, 0x81, 0, b'a'];
    let mut backend = storage(&history);
    backend.disk.extend_from_slice(b"previous boot\n");
    let mut reader = Drain::new();
    assert_eq!(reader.step(&mut backend), Ok(true));
    assert_eq!(&backend.disk[b"previous boot\n".len()..], history);
    assert_eq!(reader.step(&mut backend), Ok(false));
    assert_eq!(backend.sync_count, 1);
}

#[test]
fn overwritten_history_is_reported_durably_once_even_across_partial_writes() {
    let mut backend = storage(b"abcdef");
    backend.oldest = 3;
    backend.writes.extend([Ok(4), Err("busy")]);
    let mut reader = Drain::new();
    assert_eq!(reader.step(&mut backend), Err(Error::Backend("busy")));
    assert_eq!(reader.step(&mut backend), Ok(true));
    assert_eq!(
        backend.disk,
        b"\n[diagnostics: 3 bytes overwritten before persistence]\ndef"
    );
    assert_eq!(reader.step(&mut backend), Ok(false));
    assert_eq!(backend.reads, [0, 6]);
}

#[test]
fn gap_without_payload_is_committed_and_empty_reads_do_not_sync() {
    let mut backend = storage(b"lost");
    backend.oldest = 4;
    let mut reader = Drain::new();
    assert_eq!(reader.step(&mut backend), Ok(true));
    assert_eq!(reader.step(&mut backend), Ok(false));
    assert_eq!(backend.sync_count, 1);
    assert_eq!(
        backend.disk,
        b"\n[diagnostics: 4 bytes overwritten before persistence]\n"
    );
}

#[test]
fn zero_or_impossible_write_counts_preserve_pending_bytes() {
    for (count, error) in [(0, Error::WriteZero), (99, Error::InvalidWrite)] {
        let mut backend = storage(b"keep");
        backend.writes.push_back(Ok(count));
        let mut reader = Drain::new();
        assert_eq!(reader.step(&mut backend), Err(error));
        assert!(backend.disk.is_empty());
        assert_eq!(reader.step(&mut backend), Ok(true));
        assert_eq!(backend.disk, b"keep");
        assert_eq!(backend.reads, [0]);
    }
}

#[test]
fn source_errors_and_invalid_metadata_never_reach_storage() {
    let mut backend = storage(b"retry");
    let mut reader = Drain::new();
    backend.read_error = Some("denied");
    assert_eq!(reader.step(&mut backend), Err(Error::Backend("denied")));
    backend.invalid_read = true;
    assert_eq!(reader.step(&mut backend), Err(Error::InvalidRead));
    assert!(backend.disk.is_empty());
    assert_eq!(backend.sync_count, 0);
    backend.invalid_read = false;
    assert_eq!(reader.step(&mut backend), Ok(true));
    assert_eq!(backend.disk, b"retry");
    assert_eq!(backend.reads, [0, 0, 0]);
}

#[test]
fn work_is_bounded_and_pending_bytes_survive_later_source_overwrites() {
    let mut backend = storage(&vec![b'x'; 8192]);
    backend.writes.push_back(Err("unavailable"));
    let mut reader = Drain::new();
    assert_eq!(
        reader.step(&mut backend),
        Err(Error::Backend("unavailable"))
    );
    backend.oldest = 5000;
    backend.history[..5000].fill(b'?');
    assert_eq!(reader.step(&mut backend), Ok(true));
    assert_eq!(backend.disk, vec![b'x'; 4096]);
    assert_eq!(backend.reads, [0]);
    assert_eq!(reader.step(&mut backend), Ok(true));
    let expected = b"\n[diagnostics: 904 bytes overwritten before persistence]\n";
    assert_eq!(&backend.disk[4096..4096 + expected.len()], expected);
    assert_eq!(&backend.disk[4096 + expected.len()..], vec![b'x'; 3192]);
}
