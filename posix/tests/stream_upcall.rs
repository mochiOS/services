use mnu_abi::{
    STREAM_IO_TRY, STREAM_READ_OPTIONS_ALL, STREAM_WRITE_COMPLETE, STREAM_WRITE_OPTIONS_ALL,
    SyscallNumber,
};

#[test]
fn try_stream_operations_are_native_resource_options_not_posix_flags() {
    assert_eq!(SyscallNumber::StreamRead as u64, 681);
    assert_eq!(STREAM_READ_OPTIONS_ALL, STREAM_IO_TRY);
    assert_eq!(
        STREAM_WRITE_OPTIONS_ALL,
        STREAM_IO_TRY | STREAM_WRITE_COMPLETE
    );
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    let read = handles
        .split("pub fn stream_read(")
        .nth(1)
        .unwrap()
        .split("pub fn stream_write(")
        .next()
        .unwrap();
    assert!(read.contains("HandleRights::READ"));
    assert!(read.contains("STREAM_READ_OPTIONS_ALL"));
    let fs = include_str!("../../../core/src/syscall/fs.rs");
    let streams = fs
        .split("pub(crate) fn read_stream_handle(")
        .nth(1)
        .unwrap()
        .split("fn write_pipe(")
        .next()
        .unwrap();
    assert_eq!(
        streams.matches("options & mnu_abi::STREAM_IO_TRY").count(),
        2
    );
    assert!(!streams.contains("open.io_options ="));
    assert!(!streams.contains("SA_RESTART"));
}

#[test]
fn legacy_blocking_streams_release_their_waiter_before_upcall_delivery() {
    let fs = include_str!("../../../core/src/syscall/fs.rs");
    for name in ["fn read_pipe(", "fn write_pipe("] {
        let function = fs.split(name).nth(1).unwrap().split("\n}").next().unwrap();
        let check = function.find("thread.has_deliverable_upcall()").unwrap();
        assert!(function[..check].contains("drop(table);"));
        let release = function[check..]
            .find("remove_stream_waiter(pipe_id, current)")
            .unwrap();
        assert!(release < function[check..].find("return EAGAIN").unwrap());
    }
}

#[test]
fn userspace_stream_io_preserves_the_generation_across_native_attempts() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let io = source
        .split("fn stream_io_since<")
        .nth(1)
        .unwrap()
        .split("fn syscall_write(")
        .next()
        .unwrap();
    assert!(
        io.find("nonrestart_signal_generation.load").unwrap()
            < io.find("match operation()").unwrap()
    );
    assert!(io.contains("wait_for_handle_since(entry, interests, control, caught)"));
    let read = source
        .split("fn syscall_read(")
        .nth(1)
        .unwrap()
        .split("fn refill_dir_stream(")
        .next()
        .unwrap();
    assert!(read.contains("SyscallNumber::StreamRead"));
    assert!(read.contains("STREAM_IO_TRY"));
    let write = source
        .split("fn syscall_write(")
        .nth(1)
        .unwrap()
        .split("fn syscall_read(")
        .next()
        .unwrap();
    assert!(write.contains("flags | mnu_abi::STREAM_IO_TRY"));
    assert!(write.contains("stream_io_since("));
}
