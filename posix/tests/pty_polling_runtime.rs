//! Production runtime -> real PTY provider, with controlled native clock/waits.
#![allow(dead_code)]
use mnu_abi::provider;
use mochios_posix_protocol as posix_protocol;
use posix_service::pty::{PtyManager, PtyPair};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

const EAGAIN: i32 = 11;
const EIO: i32 = 5;
const EFAULT: i32 = 14;
const EINTR: i32 = 4;
#[derive(Clone, Copy)]
struct Handle {
    lower_handle: u64,
}
#[derive(Clone, Copy)]
struct FdEntry {
    handle: Handle,
}
struct ThreadControl {
    nonrestart_signal_generation: AtomicU64,
}
static CONTROL: ThreadControl = ThreadControl {
    nonrestart_signal_generation: AtomicU64::new(0),
};
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
enum Wake {
    Input(&'static [u8], u64),
    Timeout,
    Error(i32),
}
struct State {
    ptys: PtyManager,
    pair: PtyPair,
    now: u64,
    nonblocking: bool,
    wake: VecDeque<Wake>,
    deadlines: Vec<u64>,
    queries: usize,
    reads: usize,
}
thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
fn state<T>(f: impl FnOnce(&mut State) -> T) -> T {
    STATE.with_borrow_mut(|s| f(s.as_mut().unwrap()))
}
fn configure(minimum: u8, deciseconds: u8, canonical: bool) -> FdEntry {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let mut attributes = posix_protocol::TerminalAttributes::sane();
    attributes.input_flags = 0;
    attributes.output_flags = 0;
    attributes.local_flags = if canonical {
        posix_protocol::TERMINAL_LFLAG_ICANON
    } else {
        0
    };
    attributes.control_characters[posix_protocol::TERMINAL_CC_VMIN] = minimum;
    attributes.control_characters[posix_protocol::TERMINAL_CC_VTIME] = deciseconds;
    ptys.set_attributes(pair.slave_object_id, attributes)
        .unwrap();
    STATE.with_borrow_mut(|s| {
        *s = Some(State {
            ptys,
            pair,
            now: 1_000_000_000,
            nonblocking: false,
            wake: VecDeque::new(),
            deadlines: Vec::new(),
            queries: 0,
            reads: 0,
        })
    });
    FdEntry {
        handle: Handle {
            lower_handle: pair.slave_object_id,
        },
    }
}
fn input(bytes: &[u8]) {
    state(|s| {
        assert_eq!(
            s.ptys.write(s.pair.master_object_id, bytes),
            Ok(bytes.len())
        )
    });
}
fn handle_is_nonblocking(_: FdEntry) -> Result<bool, i32> {
    Ok(state(|s| s.nonblocking))
}
fn monotonic_nanoseconds() -> Result<u64, i32> {
    Ok(state(|s| s.now))
}
fn retry_terminal_operation<T>(
    signal: u32,
    mut f: impl FnMut() -> Result<T, i32>,
) -> Result<T, i32> {
    assert_eq!(signal, posix_protocol::SIGNAL_TTIN);
    f()
}
fn syscall_errno(value: Result<u64, i32>) -> Result<u64, i32> {
    value
}
mod syscall {
    pub use mnu_abi::{
        HANDLE_SIGNAL_PEER_CLOSED, HANDLE_SIGNAL_READABLE, HANDLE_WAIT_INFINITE, SyscallNumber,
    };
    pub fn raw_syscall6(
        number: SyscallNumber,
        handle: u64,
        code: u64,
        input: u64,
        input_len: u64,
        output: u64,
        output_len: u64,
    ) -> Result<u64, i32> {
        assert!(matches!(number, SyscallNumber::HandleQuery));
        assert_eq!((input, input_len), (0, 0));
        assert_eq!(code, crate::posix_protocol::PTY_QUERY_READ_SETTINGS);
        crate::state(|s| s.queries += 1);
        exchange(crate::provider::OP_QUERY, handle, code, output, output_len)
    }
    pub fn raw_syscall3(
        number: SyscallNumber,
        handle: u64,
        output: u64,
        length: u64,
    ) -> Result<u64, i32> {
        assert!(matches!(number, SyscallNumber::HandleRead));
        crate::state(|s| s.reads += 1);
        exchange(crate::provider::OP_READ, handle, 0, output, length)
    }
    fn exchange(opcode: u16, handle: u64, code: u64, output: u64, length: u64) -> Result<u64, i32> {
        use crate::provider;
        let mut request = [0; provider::REQUEST_HEADER_LEN];
        let count = provider::RequestHeader {
            opcode,
            object_id: handle,
            basis: code,
            argument: 0,
            length: length.min(provider::MAX_DATA_LEN as u64) as u32,
            data_length: 0,
        }
        .encode(&[], &mut request)
        .unwrap();
        let mut response = vec![0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
        let count = crate::state(|s| {
            posix_service::pty::handle_provider_request(
                &mut s.ptys,
                &request[..count],
                &mut response,
            )
            .unwrap()
        });
        let (header, payload) = provider::ResponseHeader::decode(&response[..count]).unwrap();
        if header.status != 0 {
            return Err((-header.status) as i32);
        }
        assert!(payload.len() <= length as usize);
        // These host buffers are owned by the test, never untrusted addresses.
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), output as *mut u8, payload.len())
        };
        Ok(header.value)
    }
}
fn wait_for_handle_capacity(
    _: FdEntry,
    interests: u64,
    _: &ThreadControl,
    _: u64,
    minimum_write_bytes: u32,
    deadline: u64,
) -> Result<u64, i32> {
    assert_eq!(minimum_write_bytes, 0);
    assert_eq!(
        interests,
        syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED
    );
    state(|s| {
        s.deadlines.push(deadline);
        match s.wake.pop_front().expect("unexpected extra wait") {
            Wake::Input(bytes, elapsed) => {
                s.now += elapsed;
                assert_eq!(
                    s.ptys.write(s.pair.master_object_id, bytes),
                    Ok(bytes.len())
                );
                Ok(syscall::HANDLE_SIGNAL_READABLE)
            }
            Wake::Timeout => {
                assert_ne!(deadline, syscall::HANDLE_WAIT_INFINITE);
                s.now = deadline;
                Err(EAGAIN)
            }
            Wake::Error(error) => Err(error),
        }
    })
}
#[path = "../../../user/crates/newlib-runtime/src/terminal_read.rs"]
mod implementation;
fn read(entry: FdEntry, capacity: usize) -> Result<Vec<u8>, i32> {
    let mut bytes = vec![0xcc; capacity];
    let count = implementation::read(entry, bytes.as_mut_ptr().cast(), capacity)?;
    bytes.truncate(count as usize);
    Ok(bytes)
}

#[test]
fn all_four_min_time_combinations_use_real_provider_bytes_and_per_read_deadlines() {
    let fd = configure(0, 0, false);
    assert_eq!(read(fd, 32), Ok(vec![]));
    input(b"abc");
    assert_eq!(read(fd, 32), Ok(b"abc".to_vec()));
    state(|s| assert!(s.deadlines.is_empty()));

    let fd = configure(3, 0, false);
    input(b"ab");
    state(|s| s.wake.push_back(Wake::Input(b"c", 9_000_000_000)));
    assert_eq!(read(fd, 32), Ok(b"abc".to_vec()));
    state(|s| assert_eq!(s.deadlines, [syscall::HANDLE_WAIT_INFINITE]));
    // MIN is capped by this read's capacity, not by a shared OFD threshold.
    input(b"xy");
    assert_eq!(read(fd, 2), Ok(b"xy".to_vec()));

    let fd = configure(0, 2, false);
    state(|s| s.wake.push_back(Wake::Timeout));
    assert_eq!(read(fd, 32), Ok(vec![]));
    state(|s| assert_eq!(s.deadlines, [1_200_000_000]));
    state(|s| s.wake.push_back(Wake::Input(b"a", 50_000_000)));
    assert_eq!(read(fd, 32), Ok(b"a".to_vec()));
    state(|s| assert_eq!(s.deadlines[1], 1_400_000_000));

    let fd = configure(5, 2, false);
    // No timer before the first byte; each newly received batch restarts it.
    state(|s| {
        s.wake.extend([
            Wake::Input(b"ab", 500_000_000),
            Wake::Input(b"c", 50_000_000),
            Wake::Timeout,
        ])
    });
    assert_eq!(read(fd, 32), Ok(b"abc".to_vec()));
    state(|s| {
        assert_eq!(
            s.deadlines,
            [syscall::HANDLE_WAIT_INFINITE, 1_700_000_000, 1_750_000_000]
        )
    });
    // A second read starts afresh, rather than reusing the previous deadline.
    state(|s| {
        s.wake
            .extend([Wake::Input(b"d", 1_000_000_000), Wake::Timeout])
    });
    assert_eq!(read(fd, 32), Ok(b"d".to_vec()));
    state(|s| assert_eq!(s.deadlines[3], syscall::HANDLE_WAIT_INFINITE));
}

#[test]
fn nonblocking_canonical_master_hangup_and_interrupted_prefixes_remain_distinct() {
    let fd = configure(7, 2, false);
    state(|s| s.nonblocking = true);
    assert_eq!(read(fd, 32), Err(EAGAIN));
    input(b"x");
    assert_eq!(read(fd, 32), Ok(b"x".to_vec()));
    state(|s| assert!(s.deadlines.is_empty()));

    let fd = configure(7, 0, false);
    state(|s| s.wake.push_back(Wake::Error(EINTR)));
    assert_eq!(read(fd, 32), Err(EINTR));
    input(b"xy");
    state(|s| s.wake.push_back(Wake::Error(EINTR)));
    assert_eq!(read(fd, 32), Ok(b"xy".to_vec()));
    input(b"tail");
    state(|s| {
        s.ptys.release(s.pair.master_object_id).unwrap();
    });
    assert_eq!(read(fd, 32), Ok(b"tail".to_vec()));
    assert_eq!(read(fd, 32), Ok(vec![]));

    let fd = configure(255, 255, true);
    input(b"first\nsecond\n");
    assert_eq!(read(fd, 32), Ok(b"first\n".to_vec()));
    assert_eq!(read(fd, 32), Ok(b"second\n".to_vec()));
    state(|s| assert!(s.deadlines.is_empty()));
    // Master output is never subject to the slave's MIN/TIME settings.
    state(|s| {
        s.ptys.write(s.pair.slave_object_id, b"out").unwrap();
    });
    let master = FdEntry {
        handle: Handle {
            lower_handle: state(|s| s.pair.master_object_id),
        },
    };
    assert_eq!(read(master, 32), Ok(b"out".to_vec()));
}
