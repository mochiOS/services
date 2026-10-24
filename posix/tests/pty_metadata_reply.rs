//! Execute the production reply adapter with deterministic native-reference calls.
extern crate self as mochi_user_platform;
pub use posix_service::OpenedObject;
use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};
pub mod pty {
    pub use posix_service::pty::*;
}
pub mod filesystem_transport {
    pub use posix_service::filesystem_transport::call_native;
}
#[path = "../src/pty_metadata_ipc.rs"]
mod implementation;
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_TRANSFER as T,
    IpcObjectHandle, IpcObjectHandles,
};
use posix_service::filesystem_reference::{Backend, Reference};
#[derive(Debug)]
pub struct Error;
impl Error {
    pub fn raw(&self) -> i64 {
        -5
    }
}
#[derive(Default)]
struct Calls {
    object: u64,
    reply_fails: bool,
    closed: Vec<u32>,
    status: Vec<i64>,
    duplicates: Vec<u64>,
}
thread_local! {static CALLS:RefCell<Calls>=RefCell::new(Calls::default());}
pub mod handle {
    use super::*;
    pub fn identify_provider_object(handle: u32) -> Result<u64, Error> {
        assert_eq!(handle, 73);
        Ok(CALLS.with_borrow(|c| c.object))
    }
    pub fn close(handle: u32) -> Result<(), Error> {
        CALLS.with_borrow_mut(|c| c.closed.push(handle));
        Ok(())
    }
}
pub mod ipc {
    use super::*;
    pub fn reply(sender: u64, bytes: &[u8]) -> Result<(), Error> {
        assert_eq!(sender, 19);
        CALLS.with_borrow_mut(|c| c.status.push(i64::from_le_bytes(bytes.try_into().unwrap())));
        Ok(())
    }
    pub fn reply_object_handles(
        sender: u64,
        bytes: &[u8],
        objects: &IpcObjectHandles,
    ) -> Result<(), Error> {
        assert_eq!(objects.delivery_flags, 0);
        assert_eq!(objects.count, 1);
        assert_eq!(
            objects.handles[0],
            IpcObjectHandle {
                handle: 92,
                reserved: 0,
                rights: T
            }
        );
        reply(sender, bytes)?;
        CALLS.with_borrow(|c| if c.reply_fails { Err(Error) } else { Ok(()) })
    }
    pub fn call_object_handles(
        _: u32,
        _: &[u8],
        _: &mut [u8],
        _: &mut IpcObjectHandles,
    ) -> Result<u64, Error> {
        panic!("server does not make peer calls")
    }
}
#[derive(Debug)]
struct Metadata;
impl Backend for Metadata {
    fn duplicate(&self, rights: u64) -> Result<u32, i32> {
        CALLS.with_borrow_mut(|c| c.duplicates.push(rights));
        Ok(92)
    }
}
fn source() -> IpcObjectHandles {
    let mut a = IpcObjectHandles::default();
    a.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    a.count = 1;
    a.handles[0] = IpcObjectHandle {
        handle: 73,
        reserved: 0,
        rights: T,
    };
    a
}

#[test]
fn successful_and_failed_replies_close_only_temporary_local_references_not_the_data_open() {
    for reply_fails in [false, true] {
        let mut manager = pty::PtyManager::new();
        let pair = manager.open().unwrap();
        let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
        let slave = manager
            .open_slave_with_metadata(
                factory,
                Reference::new(Box::new(Metadata), C | D | T).unwrap(),
            )
            .unwrap();
        CALLS.set(Calls {
            object: slave,
            reply_fails,
            ..Calls::default()
        });
        let manager = Arc::new(Mutex::new(manager));
        implementation::serve(
            &manager,
            19,
            &mochios_filesystem_protocol::device_metadata::Request { rights: T }.encode(),
            source(),
        );
        CALLS.with_borrow(|c| {
            assert_eq!(c.closed, vec![73, 92]);
            assert_eq!(c.status, vec![0]);
            assert_eq!(c.duplicates, vec![T]);
        });
        assert!(manager.lock().unwrap().attributes(slave).is_ok());
        assert_eq!(manager.lock().unwrap().take_terminal_signal(), None);
    }
}

#[test]
fn rejected_lookup_reclaims_input_and_replies_without_a_metadata_reference() {
    CALLS.set(Calls {
        object: u64::MAX,
        ..Calls::default()
    });
    implementation::serve(
        &Mutex::new(pty::PtyManager::new()),
        19,
        &mochios_filesystem_protocol::device_metadata::Request { rights: T }.encode(),
        source(),
    );
    CALLS.with_borrow(|c| {
        assert_eq!(c.closed, vec![73]);
        assert_eq!(c.status, vec![-9]);
        assert!(c.duplicates.is_empty());
    });
}
