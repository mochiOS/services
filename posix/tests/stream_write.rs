use mochios_posix_client::stream::{PIPE_BUF, WriteError, write};

#[test]
fn short_writes_request_one_atomic_operation() {
    for length in [0, 1, PIPE_BUF] {
        let mut calls = 0;
        assert_eq!(
            write(length, false, |offset, count, complete| {
                calls += 1;
                assert_eq!(offset, 0);
                assert_eq!(count, length);
                assert!(complete);
                Ok::<_, i32>(count)
            }),
            Ok(length)
        );
        assert_eq!(calls, 1);
    }
    assert_eq!(
        write(PIPE_BUF, true, |_, _, complete| {
            assert!(complete);
            Err::<usize, _>(11)
        }),
        Err(WriteError::Io(11))
    );
    assert_eq!(
        write(PIPE_BUF, false, |_, _, _| Ok::<_, i32>(1)),
        Err(WriteError::InvalidResult)
    );
}

#[test]
fn large_blocking_writes_continue_from_the_transferred_prefix() {
    let mut calls = Vec::new();
    assert_eq!(
        write(90000, false, |offset, count, complete| {
            calls.push((offset, count, complete));
            Ok::<_, i32>(count.min(65536))
        }),
        Ok(90000)
    );
    assert_eq!(calls, [(0, 90000, false), (65536, 24464, false)]);
}

#[test]
fn nonblocking_writes_return_available_progress_without_retrying() {
    let mut calls = 0;
    assert_eq!(
        write(PIPE_BUF + 1, true, |_, _, complete| {
            calls += 1;
            assert!(!complete);
            Ok::<_, i32>(17)
        }),
        Ok(17)
    );
    assert_eq!(calls, 1);
}

#[test]
fn errors_after_progress_report_the_successful_prefix() {
    for error in [4, 11, 32] {
        assert_eq!(
            write(4096, false, |offset, _, _| {
                if offset == 0 { Ok(1000) } else { Err(error) }
            }),
            Ok(1000)
        );
        assert_eq!(
            write(4096, false, |_, _, _| Err::<usize, _>(error)),
            Err(WriteError::Io(error))
        );
    }
    assert_eq!(
        write(4096, false, |_, _, _| Ok::<_, i32>(4097)),
        Err(WriteError::InvalidResult)
    );
}

#[test]
fn pipe_buf_matches_the_public_headers_and_native_stream_checks_rights() {
    assert_eq!(mnu_abi::SyscallNumber::StreamWrite as u64, 675);
    assert_eq!(
        mnu_abi::STREAM_WRITE_OPTIONS_ALL,
        mnu_abi::STREAM_WRITE_COMPLETE
    );
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/syslimits.h");
    assert!(
        header
            .lines()
            .any(|line| line.starts_with("#define\tPIPE_BUF")
                && line.contains(&PIPE_BUF.to_string()))
    );
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let handler = include_str!("../../../core/src/syscall/handle.rs");
    assert!(abi.contains("StreamWrite = 675"));
    let start = handler.find("pub fn stream_write(").unwrap();
    let end = handler[start..].find("pub fn seek(").unwrap() + start;
    assert!(handler[start..end].contains("object(raw, HandleRights::WRITE)"));
    assert!(handler[start..end].contains("options & !mnu_abi::STREAM_WRITE_OPTIONS_ALL"));
    let kernel = include_str!("../../../core/src/syscall/fs.rs");
    assert!(!kernel.contains("PIPE_BUF:"));
}
