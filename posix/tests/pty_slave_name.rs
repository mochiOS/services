#![allow(dead_code, non_camel_case_types)]
use mochios_posix_protocol as posix_protocol;
use posix_service::{
    pty::PtyManager,
    terminal_publication::{Lease as NameLease, Name},
};
use std::ffi::{c_char, c_int};
use std::sync::mpsc;

const EFAULT: i32 = 14;
const EIO: i32 = 5;
const ERANGE: i32 = 34;
#[derive(Clone, Copy)]
struct FdEntry;
struct FdLease(FdEntry);
impl std::ops::Deref for FdLease {
    type Target = FdEntry;
    fn deref(&self) -> &FdEntry {
        &self.0
    }
}
impl Drop for FdLease {
    fn drop(&mut self) {
        LEASES.set(LEASES.get() - 1);
    }
}
thread_local! {
    static LEASES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static ERROR: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
    static LENGTH: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REPLY: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    static COPIED: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}
fn with_fd_entry(fd: i32) -> Result<FdLease, i32> {
    if fd != 4 {
        return Err(9);
    }
    LEASES.set(LEASES.get() + 1);
    Ok(FdLease(FdEntry))
}
mod io_resources {
    pub fn with<R, T>(
        prepare: impl FnOnce() -> Result<R, i32>,
        operation: impl FnOnce(&mut R) -> Result<T, i32>,
    ) -> Result<T, i32> {
        let mut resource = prepare()?;
        operation(&mut resource)
    }
}
fn terminal_control(_: FdEntry, code: u64, input: &[u8], output: &mut [u8]) -> Result<usize, i32> {
    assert_eq!(code, posix_protocol::PTY_CONTROL_GET_SLAVE_NAME);
    assert!(input.is_empty());
    assert_eq!(output.len(), posix_protocol::pty_name::MAX_LEN);
    assert_eq!(LEASES.get(), 1);
    CALLS.set(CALLS.get() + 1);
    if ERROR.get() != 0 {
        return Err(ERROR.get());
    }
    REPLY.with_borrow(|bytes| {
        output[..bytes.len()].copy_from_slice(bytes);
        Ok(LENGTH.get().unwrap_or(bytes.len()))
    })
}
mod user_copy {
    pub fn write(output: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        assert!(!output.is_null());
        assert_eq!(super::LEASES.get(), 1);
        if super::FAULT.get() {
            return Err(super::EFAULT);
        }
        super::COPIED.with_borrow_mut(|value| value.extend_from_slice(bytes));
        Ok(())
    }
}
#[path = "../../../user/crates/newlib-runtime/src/terminal_name.rs"]
mod implementation;

fn reset(reply: &[u8]) {
    assert_eq!(LEASES.get(), 0);
    CALLS.set(0);
    ERROR.set(0);
    LENGTH.set(None);
    FAULT.set(false);
    REPLY.with_borrow_mut(|bytes| *bytes = reply.to_vec());
    COPIED.with_borrow_mut(Vec::clear);
}

#[test]
fn master_control_returns_the_registered_name_not_a_guessed_object_number() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let code = posix_protocol::PTY_CONTROL_GET_SLAVE_NAME;
    assert_eq!(
        manager.control(pair.master_object_id, code, &[], 64),
        Err(6)
    );
    let (sender, receiver) = mpsc::channel();
    manager
        .attach_slave_name(
            pair.master_object_id,
            NameLease::new(
                Name {
                    component: b"81-37".to_vec(),
                    device: 3,
                    node_id: 5,
                },
                sender,
            ),
        )
        .unwrap();
    let expected = b"/dev/pts/81-37\0";
    for capacity in 0..expected.len() {
        assert_eq!(
            manager.control(pair.master_object_id, code, &[], capacity),
            Err(34)
        );
    }
    assert_eq!(
        manager
            .control(pair.master_object_id, code, &[], expected.len())
            .unwrap(),
        expected
    );
    assert_eq!(
        manager.control(pair.master_object_id, code, &[0], 64),
        Err(22)
    );
    assert_eq!(
        manager.control(pair.slave_object_id, code, &[], 64),
        Err(25)
    );
    let grant = manager.create_slave_factory(pair.master_object_id).unwrap();
    assert_eq!(manager.control(grant, code, &[], 64), Err(9));
    assert!(receiver.try_recv().is_err());
    manager.release(pair.master_object_id).unwrap();
    assert_eq!(
        manager.control(pair.master_object_id, code, &[], 64),
        Err(9)
    );
    assert_eq!(receiver.try_recv().unwrap().component, b"81-37");
    manager.release(pair.slave_object_id).unwrap();
    manager.release(grant).unwrap();
}

#[test]
fn slave_name_wire_requires_one_bounded_component_and_exact_final_nul() {
    let mut bytes = [0xcc; posix_protocol::pty_name::MAX_LEN];
    let component = format!("{}-{}", u64::MAX, u64::MAX);
    let length = posix_protocol::pty_name::encode(component.as_bytes(), &mut bytes).unwrap();
    assert_eq!(
        posix_protocol::pty_name::decode(&bytes[..length]).unwrap(),
        format!("/dev/pts/{component}").as_bytes()
    );
    for capacity in 0..length {
        let mut output = [0xcc; posix_protocol::pty_name::MAX_LEN];
        assert!(
            posix_protocol::pty_name::encode(component.as_bytes(), &mut output[..capacity])
                .is_err()
        );
        assert!(output.iter().all(|b| *b == 0xcc));
    }
    for malformed in [
        &b""[..],
        b"/dev/pts/a",
        b"/dev/pts/\0",
        b"/dev/pts/.\0",
        b"/dev/pts/..\0",
        b"/dev/pts/a/b\0",
        b"/dev/pts/a\0\0",
        b"/dev/pts/a\0b\0",
        b"/tmp/a\0",
    ] {
        assert!(posix_protocol::pty_name::decode(malformed).is_err());
    }
    for component in [&b""[..], b".", b"..", b"x/y", b"x\0y", &[b'x'; 64]] {
        assert!(posix_protocol::pty_name::encode(component, &mut bytes).is_err());
    }
}

#[test]
fn runtime_pins_master_and_copies_only_complete_validated_names() {
    let name = b"/dev/pts/81-37\0";
    let mut destination = [0u8; 64];
    reset(name);
    assert_eq!(
        implementation::get(4, destination.as_mut_ptr().cast(), name.len()),
        Ok(0)
    );
    COPIED.with_borrow(|bytes| assert_eq!(bytes, name));
    assert_eq!(LEASES.get(), 0);
    for capacity in 0..name.len() {
        reset(name);
        assert_eq!(
            implementation::get(4, destination.as_mut_ptr().cast(), capacity),
            Err(ERANGE)
        );
        assert_eq!(LEASES.get(), 0);
        COPIED.with_borrow(|bytes| assert!(bytes.is_empty()));
    }
    for malformed in [&b""[..], b"/tmp/x\0", b"/dev/pts/x", b"/dev/pts/x\0\0"] {
        reset(malformed);
        assert_eq!(
            implementation::get(4, destination.as_mut_ptr().cast(), 64),
            Err(EIO)
        );
        assert_eq!(LEASES.get(), 0);
        COPIED.with_borrow(|bytes| assert!(bytes.is_empty()));
    }
    reset(name);
    LENGTH.set(Some(65));
    assert_eq!(
        implementation::get(4, destination.as_mut_ptr().cast(), 64),
        Err(EIO)
    );
    assert_eq!(LEASES.get(), 0);
}

#[test]
fn runtime_preserves_native_errors_and_faults_and_does_not_publish_partial_names() {
    let name = b"/dev/pts/81-37\0";
    let mut destination = [0u8; 64];
    for error in [9, 25, 13, 5, 6, 32] {
        reset(name);
        ERROR.set(error);
        assert_eq!(
            implementation::get(4, destination.as_mut_ptr().cast(), 64),
            Err(error)
        );
        assert_eq!(LEASES.get(), 0);
        COPIED.with_borrow(|bytes| assert!(bytes.is_empty()));
    }
    reset(name);
    assert_eq!(
        implementation::get(-1, destination.as_mut_ptr().cast(), 64),
        Err(9)
    );
    assert_eq!(CALLS.get(), 0);
    assert_eq!(
        implementation::get(4, core::ptr::null_mut(), 64),
        Err(EFAULT)
    );
    assert_eq!(CALLS.get(), 0);
    reset(name);
    FAULT.set(true);
    assert_eq!(
        implementation::get(4, destination.as_mut_ptr().cast(), 64),
        Err(EFAULT)
    );
    assert_eq!(LEASES.get(), 0);
    COPIED.with_borrow(|bytes| assert!(bytes.is_empty()));
}
