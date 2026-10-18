extern crate alloc;
mod syscall {
    pub use mochi_user_platform::syscall::{NativeError, SysError};
}
mod native_mpkg_reader {
    pub struct NativeMpkgReader;
}
#[allow(dead_code, unused_imports)]
#[path = "../../../user/crates/platform/src/package.rs"]
mod package;

use package::{MpkgReader, index_mpkg_reader, read_mpkg_range_reader};
use syscall::{NativeError, SysError};

struct Reader {
    length: u64,
    bytes: Vec<u8>,
    reads: usize,
    queries: usize,
    failure: Option<SysError>,
}
impl MpkgReader for Reader {
    fn len(&mut self) -> Result<u64, SysError> {
        self.queries += 1;
        self.failure.map_or(Ok(self.length), Err)
    }
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), SysError> {
        self.reads += 1;
        if let Some(error) = self.failure {
            return Err(error);
        }
        let start = usize::try_from(offset).unwrap();
        output.copy_from_slice(&self.bytes[start..start + output.len()]);
        Ok(())
    }
}
fn reader(bytes: Vec<u8>, length: u64) -> Reader {
    Reader {
        bytes,
        length,
        reads: 0,
        queries: 0,
        failure: None,
    }
}

fn archive(count: usize) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(b"MPKG");
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&32u16.to_le_bytes());
    for index in 0..count {
        let mut block = [0u8; 512];
        let name = if index == 0 {
            "manifest.toml".into()
        } else {
            format!("payload/{index}")
        };
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[156] = b'0';
        block[124..136].copy_from_slice(if index == 0 {
            b"00000000003\0"
        } else {
            b"00000000000\0"
        });
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        block[148..156].fill(b' ');
        let sum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        bytes.extend_from_slice(&block);
        if index == 0 {
            let start = bytes.len();
            bytes.resize(start + 512, 0);
            bytes[start..start + 3].copy_from_slice(b"abc");
        }
    }
    bytes.resize(bytes.len() + 512, 0);
    let expanded = (bytes.len() - 32) as u64;
    bytes[12..20].copy_from_slice(&expanded.to_le_bytes());
    bytes
}

#[test]
fn invalid_header_size_and_exceeded_native_size_limit_do_no_reads() {
    for length in [0, 1, 31] {
        let mut input = reader(vec![], length);
        assert_eq!(
            index_mpkg_reader(&mut input).unwrap_err().native_error(),
            Some(NativeError::InvalidArgument)
        );
        assert_eq!((input.queries, input.reads), (1, 0));
    }
    for length in [256 * 1024 * 1024 + 1, u64::MAX] {
        let mut input = reader(vec![], length);
        assert_eq!(
            index_mpkg_reader(&mut input).unwrap_err().native_error(),
            Some(NativeError::LimitExceeded)
        );
        assert_eq!((input.queries, input.reads), (1, 0));
    }
}

#[test]
fn range_overflow_is_native_and_invalid_extent_never_allocates_or_reads() {
    let mut input = reader(vec![1, 2, 3, 4], 4);
    assert_eq!(
        read_mpkg_range_reader(&mut input, u64::MAX, 1)
            .unwrap_err()
            .native_error(),
        Some(NativeError::LimitExceeded)
    );
    assert_eq!((input.queries, input.reads), (0, 0));
    assert_eq!(
        read_mpkg_range_reader(&mut input, 3, 2)
            .unwrap_err()
            .native_error(),
        Some(NativeError::InvalidArgument)
    );
    assert_eq!(input.reads, 0);
    assert_eq!(read_mpkg_range_reader(&mut input, 1, 3).unwrap(), [2, 3, 4]);
}

#[test]
fn entry_budget_includes_the_exact_limit_but_not_an_extra_entry() {
    for count in [1, 4096, 4097] {
        let bytes = archive(count);
        let mut input = reader(bytes.clone(), bytes.len() as u64);
        let result = index_mpkg_reader(&mut input);
        if count <= 4096 {
            let index = result.unwrap();
            assert_eq!(index.entries.len(), count);
            assert_eq!(index.manifest, b"abc");
        } else {
            assert_eq!(
                result.unwrap_err().native_error(),
                Some(NativeError::LimitExceeded)
            );
        }
    }
}

#[test]
fn metadata_failure_is_not_relabelled_as_range_or_format_error() {
    for native in [
        NativeError::AccessDenied,
        NativeError::BackingFailure,
        NativeError::NotReady,
    ] {
        let error = SysError::from_raw(native.into_raw() as i64);
        let mut input = reader(vec![], 0);
        input.failure = Some(error);
        assert_eq!(index_mpkg_reader(&mut input).unwrap_err(), error);
        assert_eq!(input.reads, 0);
    }
}

#[test]
fn allocation_admission_failure_is_native_and_does_not_start_reading() {
    // A Vec cannot represent more than isize::MAX bytes. This fails capacity
    // admission deterministically, without exhausting host memory.
    let length = isize::MAX as u64 + 1;
    let mut input = reader(vec![], length);
    assert_eq!(
        read_mpkg_range_reader(&mut input, 0, length)
            .unwrap_err()
            .native_error(),
        Some(NativeError::ResourceUnavailable)
    );
    assert_eq!((input.queries, input.reads), (1, 0));
}

#[test]
fn accepting_the_full_entry_budget_does_not_skip_archive_termination_checks() {
    let mut bytes = archive(4096);
    bytes.resize(bytes.len() + 512, 1);
    let expanded = (bytes.len() - 32) as u64;
    bytes[12..20].copy_from_slice(&expanded.to_le_bytes());
    let mut input = reader(bytes.clone(), bytes.len() as u64);
    assert_eq!(
        index_mpkg_reader(&mut input).unwrap_err().native_error(),
        Some(NativeError::InvalidArgument)
    );
}
