//! Run the production native adapter with deterministic reference/reply failures.
extern crate self as mochi_user_platform;
use std::{cell::RefCell, sync::Mutex};
pub mod pty {
    pub use posix_service::pty::*;
}
#[path = "../src/pty_factory.rs"]
mod adapter;

#[derive(Debug)]
pub struct Error;
impl Error {
    pub fn raw(&self) -> i64 {
        -5
    }
}
#[derive(Default)]
struct Calls {
    master: u64,
    factory: u64,
    identify_fails: bool,
    publish_fails: bool,
    reply_fails: bool,
    closed: Vec<u32>,
    replies: Vec<i64>,
}
thread_local! { static CALLS: RefCell<Calls> = RefCell::new(Calls::default()); }
pub mod handle {
    use super::*;
    pub fn identify_provider_object(handle: u32) -> Result<u64, Error> {
        assert_eq!(handle, 73);
        CALLS.with_borrow(|calls| {
            if calls.identify_fails {
                Err(Error)
            } else {
                Ok(calls.master)
            }
        })
    }
    pub fn create_provider_object(endpoint: u32, object: u64, rights: u64) -> Result<u32, Error> {
        assert_eq!(endpoint, 11);
        assert_eq!(rights, adapter::FACTORY_RIGHTS);
        CALLS.with_borrow_mut(|calls| {
            calls.factory = object;
            if calls.publish_fails {
                Err(Error)
            } else {
                Ok(91)
            }
        })
    }
    pub fn close(handle: u32) -> Result<(), Error> {
        CALLS.with_borrow_mut(|calls| calls.closed.push(handle));
        Ok(())
    }
}
pub mod ipc {
    use super::*;
    pub fn reply(sender: u64, bytes: &[u8]) -> Result<(), Error> {
        assert_eq!(sender, 19);
        CALLS.with_borrow_mut(|calls| {
            calls
                .replies
                .push(i64::from_le_bytes(bytes.try_into().unwrap()))
        });
        Ok(())
    }
    pub fn reply_object_handles(
        sender: u64,
        bytes: &[u8],
        objects: &mnu_abi::IpcObjectHandles,
    ) -> Result<(), Error> {
        assert_eq!(objects.delivery_flags, 0);
        assert_eq!(objects.count, 1);
        assert_eq!(
            objects.handles[0],
            mnu_abi::IpcObjectHandle {
                handle: 91,
                reserved: 0,
                rights: adapter::FACTORY_RIGHTS
            }
        );
        reply(sender, bytes)?;
        CALLS.with_borrow(|calls| {
            if calls.reply_fails {
                Err(Error)
            } else {
                Ok(())
            }
        })
    }
}

#[test]
fn reply_success_and_failure_close_local_references_and_native_release_retires_factory() {
    for reply_fails in [false, true] {
        let mut manager = pty::PtyManager::new();
        let pair = manager.open().unwrap();
        CALLS.set(Calls {
            master: pair.master_object_id,
            reply_fails,
            ..Calls::default()
        });
        let manager = Mutex::new(manager);
        adapter::serve(
            &manager,
            11,
            19,
            &mochios_posix_protocol::pty_factory::CREATE_REQUEST,
            attached(),
        );
        let factory = CALLS.with_borrow(|calls| {
            assert_eq!(calls.closed, vec![73, 91]);
            assert_eq!(calls.replies, vec![0]);
            calls.factory
        });
        // Model the final native reference release (immediate after a failed
        // reply, or later after the recipient closes a successful reply).
        let mut manager = manager.lock().unwrap();
        manager.release(factory).unwrap();
        assert_eq!(manager.open_slave_from_factory(factory), Err(pty::EBADF));
        assert!(manager.attributes(pair.master_object_id).is_ok());
        assert_eq!(manager.take_terminal_signal(), None);
    }
}

fn attached() -> mnu_abi::IpcObjectHandles {
    let mut attached = mnu_abi::IpcObjectHandles::default();
    attached.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    attached.count = 1;
    attached.handles[0] = mnu_abi::IpcObjectHandle {
        handle: 73,
        reserved: 0,
        rights: adapter::MASTER_RIGHTS,
    };
    attached
}

#[test]
fn identification_and_publication_failures_reply_without_a_handle_and_reclaim_input() {
    for identify_fails in [false, true] {
        let mut manager = pty::PtyManager::new();
        let pair = manager.open().unwrap();
        CALLS.set(Calls {
            master: pair.master_object_id,
            identify_fails,
            publish_fails: true,
            ..Calls::default()
        });
        let manager = Mutex::new(manager);
        adapter::serve(
            &manager,
            11,
            19,
            &mochios_posix_protocol::pty_factory::CREATE_REQUEST,
            attached(),
        );
        CALLS.with_borrow(|calls| {
            assert_eq!(calls.closed, vec![73]);
            assert_eq!(calls.replies, vec![if identify_fails { -9 } else { -5 }]);
            assert_eq!(
                manager.lock().unwrap().release(calls.factory),
                Err(pty::EBADF)
            );
        });
        assert!(
            manager
                .lock()
                .unwrap()
                .attributes(pair.master_object_id)
                .is_ok()
        );
    }
}
