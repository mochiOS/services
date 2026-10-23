#![allow(dead_code)]
use mochios_posix_client::{
    Client as PosixClient, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as posix_protocol;
use std::ffi::c_int;
const EBADF: i32 = 9;
const EINVAL: i32 = 22;
const EACCES: i32 = 13;
#[derive(Clone, Copy, PartialEq)]
enum FdKind {
    ObjectPty,
    ObjectFile,
}
#[derive(Clone, Copy)]
struct FdObject {
    kind: FdKind,
    lower_handle: u64,
}
#[derive(Clone, Copy)]
struct FdEntry {
    handle: FdObject,
    rights: u64,
}
struct Lease(FdEntry);
impl std::ops::Deref for Lease {
    type Target = FdEntry;
    fn deref(&self) -> &FdEntry {
        &self.0
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        LEASES.set(LEASES.get() - 1)
    }
}
thread_local! {
    static LEASES:std::cell::Cell<u32>=const{std::cell::Cell::new(0)};
    static CALLS:std::cell::Cell<u32>=const{std::cell::Cell::new(0)};
    static STATUS:std::cell::Cell<i32>=const{std::cell::Cell::new(0)};
}
mod syscall {
    pub use mnu_abi::{HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_TRANSFER, HANDLE_RIGHT_WRITE};
}
fn with_fd_entry(fd: i32) -> Result<Lease, i32> {
    let required = posix_service::pty_grant::RIGHTS;
    let (kind, rights) = match fd {
        4 => (
            FdKind::ObjectPty,
            required | mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_DUPLICATE,
        ),
        5 => (FdKind::ObjectPty, required & !syscall::HANDLE_RIGHT_WRITE),
        6 => (FdKind::ObjectFile, required),
        7 => (FdKind::ObjectPty, required & !syscall::HANDLE_RIGHT_CONTROL),
        8 => (
            FdKind::ObjectPty,
            required & !syscall::HANDLE_RIGHT_TRANSFER,
        ),
        _ => return Err(EBADF),
    };
    LEASES.set(LEASES.get() + 1);
    Ok(Lease(FdEntry {
        handle: FdObject {
            kind,
            lower_handle: 77,
        },
        rights,
    }))
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
struct Wire;
impl Transport for Wire {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        unreachable!()
    }
}
impl ObjectTransport for Wire {
    type Handle = u32;
    fn close_received_handle(&self, _: u32) {
        panic!("no new resource in grantpt reply")
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        reply: &mut [u8],
        objects: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        assert_eq!(LEASES.get(), 1);
        let (header, payload) = posix_protocol::decode(request).unwrap();
        assert_eq!(header.opcode, posix_protocol::OP_PTY_GRANT_MASTER);
        assert!(payload.is_empty());
        assert_eq!(objects.len(), 1);
        assert_eq!(
            objects.get(0),
            Some(ObjectHandleAttachment {
                handle: 77,
                rights: posix_service::pty_grant::RIGHTS
            })
        );
        CALLS.set(CALLS.get() + 1);
        objects.clear();
        posix_protocol::encode(
            posix_protocol::Header {
                opcode: posix_protocol::OP_STATUS,
                request_id: header.request_id,
                status: STATUS.get(),
                ..Default::default()
            },
            &[],
            reply,
        )
        .map_err(|_| ())
    }
}
fn posix_client() -> Result<PosixClient<Wire>, mochios_posix_client::ClientError<()>> {
    Ok(PosixClient::new(Wire))
}
fn map_posix_client_error(error: mochios_posix_client::ClientError<()>) -> i32 {
    match error {
        mochios_posix_client::ClientError::Remote(status) => -status,
        _ => 5,
    }
}
#[path = "../../../user/crates/newlib-runtime/src/terminal_grant.rs"]
mod implementation;
#[test]
fn grantpt_pins_the_fd_and_transfers_only_required_controller_rights() {
    for (fd, error) in [
        (99, EBADF),
        (5, EBADF),
        (6, EINVAL),
        (7, EACCES),
        (8, EACCES),
    ] {
        assert_eq!(implementation::grant(fd), Err(error));
        assert_eq!(LEASES.get(), 0);
    }
    assert_eq!(CALLS.get(), 0);
    assert_eq!(implementation::grant(4), Ok(0));
    assert_eq!(LEASES.get(), 0);
    for error in [13, 22, 116] {
        STATUS.set(-error);
        assert_eq!(implementation::grant(4), Err(error));
        assert_eq!(LEASES.get(), 0);
    }
    assert_eq!(CALLS.get(), 4);
}
