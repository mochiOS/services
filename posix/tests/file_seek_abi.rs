extern crate alloc;

#[path = "../../../user/crates/platform/src/file_read.rs"]
mod file_read;

#[test]
fn bootstrap_reads_continue_after_short_reads_until_explicit_eof() {
    let mut pieces = [
        b"ab".as_slice(),
        b"c".as_slice(),
        b"def".as_slice(),
        b"".as_slice(),
    ]
    .into_iter();
    let bytes = file_read::read_to_end(4, |buffer| {
        let piece = pieces.next().expect("stop after EOF");
        buffer[..piece.len()].copy_from_slice(piece);
        Ok::<_, ()>(piece.len())
    })
    .unwrap();
    assert_eq!(bytes, b"abcdef");
    assert!(pieces.next().is_none());
}

#[test]
fn bootstrap_read_errors_are_not_returned_as_truncated_success() {
    let mut calls = 0;
    let result = file_read::read_to_end(4, |buffer| {
        calls += 1;
        if calls == 1 {
            buffer[..2].copy_from_slice(b"ab");
            Ok(2)
        } else {
            Err(13)
        }
    });
    assert_eq!(result, Err(file_read::ReadError::Read(13)));
    assert_eq!(calls, 2);
}

#[test]
fn bootstrap_reader_rejects_overcounts_and_allocation_overflow() {
    assert_eq!(
        file_read::read_to_end(4, |_| Ok::<_, ()>(5)),
        Err(file_read::ReadError::InvalidLength)
    );
    assert_eq!(
        file_read::read_to_end(0, |_| -> Result<usize, ()> { panic!("invalid length") }),
        Err(file_read::ReadError::InvalidLength)
    );
    assert_eq!(
        file_read::read_to_end(usize::MAX, |_| -> Result<usize, ()> {
            panic!("allocation must fail before reading")
        }),
        Err(file_read::ReadError::Allocation)
    );
    assert_eq!(
        file_read::read_to_end(4, |_| Ok::<_, ()>(0)),
        Ok(Vec::new())
    );
}

#[test]
fn legacy_seek_is_removed_from_abi_dispatch_and_kernel_fd_semantics() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let filesystem = include_str!("../../../core/src/syscall/fs.rs");
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    assert!(!abi.contains("FileSeek"));
    assert!(!abi.contains("= 565"));
    assert!(!dispatch.contains("SyscallNumber::FileSeek"));
    assert!(!filesystem.contains("pub fn file_seek("));
    assert!(!filesystem.contains("pub fn seek(fd:"));
    assert!(!platform.contains("SyscallNumber::FileSeek"));
    assert!(platform.contains("file_read::read_to_end"));
    assert!(dispatch.contains("SyscallNumber::HandleSeek"));
    assert!(filesystem.contains("pub(crate) fn seek_file_handle("));
}
