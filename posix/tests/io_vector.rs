use mochios_posix_client::io_vector::{IOV_MAX, VectorError, validate};

#[test]
fn invalid_counts_are_rejected_without_reading_caller_metadata() {
    for count in [-1, i32::MIN, IOV_MAX as i32 + 1, i32::MAX] {
        assert_eq!(
            validate(count, |_| panic!("invalid count dereferenced metadata")),
            Err(VectorError::InvalidCount)
        );
    }
    assert_eq!(
        validate(0, |_| panic!("empty vector dereferenced metadata")),
        Ok(0)
    );
    assert_eq!(validate(IOV_MAX as i32, |_| (false, 1)), Ok(IOV_MAX));
}

#[test]
fn total_lengths_must_fit_ssize_t_before_io() {
    assert_eq!(
        validate(1, |_| (false, isize::MAX as usize)),
        Ok(isize::MAX as usize)
    );
    for lengths in [
        [isize::MAX as usize, 1],
        [usize::MAX, 0],
        [usize::MAX, usize::MAX],
    ] {
        assert_eq!(
            validate(2, |index| (false, lengths[index])),
            Err(VectorError::InvalidLength)
        );
    }
    assert_eq!(validate(3, |index| (false, [3, 0, 7][index])), Ok(10));
}

#[test]
fn late_invalid_buffer_cannot_start_io() {
    let mut io_started = false;
    let result = validate(2, |index| (index == 1, 8)).map(|_| io_started = true);
    assert_eq!(result, Err(VectorError::NullBuffer));
    assert!(!io_started);
    assert_eq!(validate(1, |_| (true, 0)), Ok(0));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn excessive_vector_count_matches_host_writev_without_writing_a_prefix() {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[repr(C)]
    struct Iovec {
        base: *const u8,
        length: usize,
    }
    unsafe extern "C" {
        fn writev(fd: i32, vectors: *const Iovec, count: i32) -> isize;
    }
    let (writer, mut reader) = UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    let bytes = b"abc";
    let vectors = [Iovec {
        base: bytes.as_ptr(),
        length: bytes.len(),
    }];
    let count = IOV_MAX as i32 + 1;
    assert_eq!(
        validate(count, |_| panic!("invalid count dereferenced metadata")),
        Err(VectorError::InvalidCount)
    );
    // The invalid count must be rejected before the host accesses metadata.
    assert_eq!(
        unsafe { writev(writer.as_raw_fd(), vectors.as_ptr(), count) },
        -1
    );
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(22));
    assert_eq!(
        reader.read(&mut [0u8; 3]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn both_runtime_vector_operations_validate_before_the_first_io() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for (name, io) in [
        ("writev", "syscall_write(entry,"),
        ("readv", "syscall_read(entry,"),
    ] {
        let start = source
            .find(&format!("pub unsafe extern \"C\" fn {name}("))
            .unwrap();
        let body = &source[start..];
        assert!(body.find("io_vector::validate(iovcnt").unwrap() < body.find(io).unwrap());
        let end = body[1..].find("#[unsafe(no_mangle)]").unwrap() + 1;
        let body = &body[..end];
        assert_eq!(body.matches(io).count(), 1);
        assert!(!body.contains("for index in"));
    }
    let limits = include_str!("../../../libraries/newlib/newlib/libc/include/sys/syslimits.h");
    assert!(limits.lines().any(|line| line.starts_with("#define\tIOV_MAX") && line.contains(&IOV_MAX.to_string())));
}

#[test]
fn gathered_write_is_one_operation_and_preserves_vector_order() {
    let vectors: [&[u8]; 4] = [b"ab", b"", b"cde", b"f"];
    let total = validate(4, |i| (false, vectors[i].len())).unwrap();
    let mut calls = 0;
    let count = mochios_posix_client::io_vector::write(
        4,
        &mut vec![0; total],
        |i| vectors[i].len(),
        |i, bytes| bytes.copy_from_slice(&vectors[i][..bytes.len()]),
        |bytes| {
            calls += 1;
            assert_eq!(bytes, b"abcdef");
            Ok::<_, i32>(4)
        },
    )
    .unwrap();
    assert_eq!(count, 4);
    assert_eq!(calls, 1);
}

#[test]
fn short_read_scatters_only_returned_bytes_without_a_second_read() {
    let mut vectors = [vec![b'!'; 2], vec![b'!'; 4], vec![b'!'; 2]];
    let lengths = [2, 4, 2];
    let mut calls = 0;
    let count = mochios_posix_client::io_vector::read(
        3,
        &mut [0; 8],
        |i| lengths[i],
        |i, bytes| vectors[i][..bytes.len()].copy_from_slice(bytes),
        |bytes| {
            calls += 1;
            bytes[..3].copy_from_slice(b"abc");
            Ok::<_, i32>(3)
        },
    )
    .unwrap();
    assert_eq!(count, 3);
    assert_eq!(calls, 1);
    assert_eq!(vectors, [b"ab".to_vec(), b"c!!!".to_vec(), b"!!".to_vec()]);
}

#[test]
fn bounded_transfer_returns_a_prefix_without_splitting_the_io() {
    let vectors: [&[u8]; 2] = [b"abc", b"def"];
    assert_eq!(
        mochios_posix_client::io_vector::write(
            2,
            &mut [0; 4],
            |i| vectors[i].len(),
            |i, bytes| bytes.copy_from_slice(&vectors[i][..bytes.len()]),
            |bytes| {
                assert_eq!(bytes, b"abcd");
                Ok::<_, i32>(bytes.len())
            },
        ),
        Ok(4)
    );
}

#[test]
fn failed_read_and_invalid_backend_count_never_touch_output_vectors() {
    use mochios_posix_client::io_vector::{TransferError, read, write};
    for response in [Err(11), Err(4), Ok(9)] {
        let result = read(
            2,
            &mut [0; 8],
            |_| 4,
            |_, _| panic!("failed I/O modified the caller buffer"),
            |_| response,
        );
        assert_eq!(
            result,
            match response {
                Err(errno) => Err(TransferError::Io(errno)),
                Ok(_) => Err(TransferError::InvalidResult),
            }
        );
    }
    assert_eq!(
        write(1, &mut [0; 1], |_| 1, |_, b| b[0] = 1, |_| Ok::<_, i32>(2)),
        Err(TransferError::InvalidResult)
    );
}

#[test]
fn empty_vectors_still_check_the_backend_without_dereferencing_buffers() {
    use mochios_posix_client::io_vector::{TransferError, read, write};
    assert_eq!(
        read(
            0,
            &mut [],
            |_| panic!("no metadata"),
            |_, _| panic!("no copy"),
            |_| Err::<usize, _>(9)
        ),
        Err(TransferError::Io(9))
    );
    assert_eq!(
        write(
            2,
            &mut [],
            |_| 0,
            |_, _| panic!("no copy"),
            |bytes| {
                assert!(bytes.is_empty());
                Ok::<_, i32>(0)
            }
        ),
        Ok(0)
    );
}
