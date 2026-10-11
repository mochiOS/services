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
    for (name, io) in [("writev", "_write(fd,"), ("readv", "_read(fd,")] {
        let start = source
            .find(&format!("pub unsafe extern \"C\" fn {name}("))
            .unwrap();
        let body = &source[start..];
        assert!(body.find("io_vector::validate(iovcnt").unwrap() < body.find(io).unwrap());
    }
    let limits = include_str!("../../../libraries/newlib/newlib/libc/include/sys/syslimits.h");
    assert!(limits.lines().any(|line| line.starts_with("#define\tIOV_MAX") && line.contains(&IOV_MAX.to_string())));
}
