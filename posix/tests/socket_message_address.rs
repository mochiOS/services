//! Production recvfrom adapter with real user copies and a retained FD fixture.
#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void};
#[path = "../../../user/crates/newlib-runtime/src/socket_receive_address.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/socket_memory.rs"]
mod socket_memory;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}
#[derive(Clone, Copy)]
enum Kind {
    Stream,
    Datagram,
}
impl Kind {
    fn is_socket(self) -> bool {
        true
    }
}
#[derive(Clone, Copy)]
struct Object {
    kind: Kind,
    id: u32,
}
#[derive(Clone, Copy)]
struct FdEntry {
    handle: Object,
}
struct State {
    result: Result<isize, c_int>,
    query_error: c_int,
    calls: usize,
    fd_target: u32,
}
thread_local! {
    static STATE: RefCell<State> = const { RefCell::new(State {
        result: Ok(3), query_error: 0, calls: 0, fd_target: 17,
    }) };
}
mod socket {
    use super::*;
    pub fn is_record(entry: FdEntry) -> bool {
        matches!(entry.handle.kind, Kind::Datagram)
    }
    pub fn message_entry(
        entry: FdEntry,
        buffer: u64,
        length: usize,
        flags: c_int,
        sending: bool,
    ) -> Result<isize, c_int> {
        assert_eq!(
            (entry.handle.id, buffer, length, flags, sending),
            (17, 0x1234, 8, 0x102, false)
        );
        STATE.with_borrow_mut(|state| {
            state.calls += 1;
            state.result
        })
    }
    pub fn socket_name_entry(
        entry: FdEntry,
        address: *mut c_void,
        length: *mut u32,
        peer: bool,
    ) -> Result<c_int, c_int> {
        assert_eq!(entry.handle.id, 17);
        assert!(peer);
        STATE.with_borrow_mut(|state| {
            if state.query_error != 0 {
                return Err(state.query_error);
            }
            // Simulate a callback closing/reusing the FD label. Subsequent
            // payload I/O must still use entry 17, not this replacement.
            state.fd_target = 99;
            socket_memory::write_output(address, length, b"source", 6)?;
            Ok(0)
        })
    }
}
mod socket_record {
    use super::*;
    pub struct Record {
        pub count: isize,
        pub source: [u8; 128],
        pub source_length: usize,
    }
    pub fn io(
        entry: FdEntry,
        buffer: u64,
        length: usize,
        flags: c_int,
        sending: bool,
    ) -> Result<Record, c_int> {
        let count = socket::message_entry(entry, buffer, length, flags, sending)?;
        let mut source = [0; 128];
        let source_length = posix_protocol::socket::Address::UnixPath(b"/sender")
            .encode(&mut source)
            .unwrap();
        Ok(Record {
            count,
            source,
            source_length,
        })
    }
}
fn receive(kind: Kind, address: *mut c_void, length: *mut u32) -> Result<isize, c_int> {
    implementation::receive(
        FdEntry {
            handle: Object { kind, id: 17 },
        },
        0x1234 as *mut _,
        8,
        0x102,
        address,
        length,
    )
}

#[test]
fn stream_preserves_errors_eof_truncation_and_original_open_description() {
    assert_eq!(
        receive(Kind::Stream, std::ptr::null_mut(), 1usize as *mut _),
        Ok(3)
    );
    let mut address = [0x55; 12];
    let mut length = 12;
    let calls = STATE.with_borrow(|s| s.calls);
    STATE.with_borrow_mut(|s| s.query_error = 107);
    assert_eq!(
        receive(Kind::Stream, address.as_mut_ptr().cast(), &mut length),
        Err(107)
    );
    assert_eq!(STATE.with_borrow(|s| s.calls), calls);
    STATE.with_borrow_mut(|s| {
        s.query_error = 0;
        s.result = Err(11);
    });
    assert_eq!(
        receive(Kind::Stream, address.as_mut_ptr().cast(), &mut length),
        Err(11)
    );
    assert_eq!((length, address), (12, [0x55; 12]));
    for count in [0, 3, 8] {
        for capacity in [0u32, 2, 6, 12] {
            STATE.with_borrow_mut(|s| s.result = Ok(count));
            address.fill(0x55);
            length = capacity;
            assert_eq!(
                receive(Kind::Stream, address.as_mut_ptr().cast(), &mut length),
                Ok(count)
            );
            assert_eq!(length, 6);
            let copied = (capacity as usize).min(6);
            assert_eq!(&address[..copied], &b"source"[..copied]);
            assert!(address[copied..].iter().all(|&b| b == 0x55));
            assert_eq!(STATE.with_borrow(|s| s.fd_target), 99);
        }
    }
}

#[test]
fn invalid_input_length_never_consumes_data_and_output_errors_are_returned() {
    for kind in [Kind::Stream, Kind::Datagram] {
        let mut address = [0x55; 110];
        for pointer in [0, 1, usize::MAX] {
            let before = STATE.with_borrow(|s| s.calls);
            assert_eq!(
                receive(kind, address.as_mut_ptr().cast(), pointer as *mut _),
                Err(EFAULT)
            );
            assert_eq!(STATE.with_borrow(|s| s.calls), before);
        }
        let mut length = 110;
        assert_eq!(receive(kind, 1usize as *mut _, &mut length), Err(EFAULT));
        assert_eq!(length, 110);
    }
}

#[test]
fn datagram_source_is_returned_with_the_record() {
    let mut address = [0x55; 110];
    let mut length = 3;
    assert_eq!(
        receive(Kind::Datagram, address.as_mut_ptr().cast(), &mut length),
        Ok(3)
    );
    assert_eq!(&address[..3], &[1, 0, b'/']);
    assert_eq!(length, 10);
    assert!(address[3..].iter().all(|&byte| byte == 0x55));
}

#[test]
fn wrapper_retains_one_fd_and_stream_sendto_ignores_destination() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/socket.rs");
    let body = &source[source.find("pub unsafe extern \"C\" fn recvfrom(").unwrap()..];
    assert_eq!(body.matches("with_fd_entry(fd)").count(), 1);
    assert!(body.contains("io_resources::with("));
    assert!(body.contains("socket_receive_address::receive("));
    assert!(!body.contains("recv(fd,"));
    let start = source.find("fn send_record_to(").unwrap();
    let end = start + source[start..].find("\n#[unsafe(no_mangle)]").unwrap();
    let body = &source[start..end];
    assert!(body.find("if !is_datagram").unwrap() < body.find("user_copy::read").unwrap());
}
