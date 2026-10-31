//! Run the shared transport with controlled native replies and ownership.
#![allow(dead_code)]
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
mod capability {
    pub use mochios_capability_protocol::application_launch;
}
mod syscall {
    pub use mochi_user_syscall::{NativeError, SysError, SysResult};
}
static SERIAL: Mutex<()> = Mutex::new(());
static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static MODE: AtomicU32 = AtomicU32::new(0);
mod handle {
    pub fn close(value: u32) -> super::syscall::SysResult<()> {
        super::CLOSED.lock().unwrap().push(value);
        Ok(())
    }
}
mod ipc {
    use super::*;
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
    pub fn call_object_handles(
        destination: u32,
        bytes: &[u8],
        reply: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> syscall::SysResult<u64> {
        assert_eq!(destination, 88);
        let request = capability::application_launch::decode(bytes).unwrap();
        assert_eq!(request.path, "/msh");
        assert_eq!(request.arguments.iter().collect::<Vec<_>>(), ["msh", ""]);
        assert_eq!(handles.count, 4);
        for (index, object) in handles.handles.iter().enumerate() {
            assert_eq!(object.handle, 7 + index as u32);
            assert_eq!(object.reserved, 0);
        }
        let mode = MODE.load(Ordering::Relaxed);
        if mode == 1 {
            return Err(syscall::SysError::from_raw(
                syscall::NativeError::NotReady.into_raw() as i64,
            ));
        }
        *handles = IpcObjectHandles::default();
        if mode == 2 || mode == 3 {
            handles.count = 3;
            handles.handles[0].handle = 67;
            handles.handles[1].handle = 67;
            handles.handles[2].handle = 7;
            if mode == 3 {
                return Err(syscall::SysError::from_raw(
                    syscall::NativeError::BackingFailure.into_raw() as i64,
                ));
            }
        }
        if mode == 7 {
            handles.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
        }
        reply[..8].copy_from_slice(&(if mode == 5 { 13u64 } else { 0 }).to_le_bytes());
        reply[8..]
            .copy_from_slice(&(if mode == 5 || mode == 6 { 0u64 } else { 123 }).to_le_bytes());
        Ok(((if mode == 4 { 99u64 } else { 88u64 }) << 32) | reply.len() as u64)
    }
}
#[path = "../../../user/crates/platform/src/application.rs"]
mod production;

fn invoke() -> syscall::SysResult<u64> {
    production::spawn_with_stdio(
        88,
        "/msh",
        &["msh", ""],
        &[],
        ipc::IpcObjectHandle {
            handle: 7,
            reserved: 0,
            rights: 17,
        },
        &core::array::from_fn(|index| production::Descriptor {
            handle: 8 + index as u32,
            rights: 17,
            metadata: index as u64,
        }),
    )
}

#[test]
fn successful_reply_and_remote_error_preserve_all_borrowed_sources() {
    let _serial = SERIAL.lock().unwrap();
    for (mode, result) in [(0, Ok(123)), (5, Err(syscall::SysError::from_raw(-13)))] {
        MODE.store(mode, Ordering::Relaxed);
        CLOSED.lock().unwrap().clear();
        assert_eq!(invoke(), result);
        assert!(CLOSED.lock().unwrap().is_empty());
    }
}
#[test]
fn early_failure_never_closes_outbound_sources_and_bad_replies_drain_each_new_reference_once() {
    let _serial = SERIAL.lock().unwrap();
    for (mode, closed) in [
        (1, vec![]),
        (2, vec![67]),
        (3, vec![67]),
        (4, vec![]),
        (6, vec![]),
        (7, vec![]),
    ] {
        MODE.store(mode, Ordering::Relaxed);
        CLOSED.lock().unwrap().clear();
        assert!(invoke().is_err(), "{mode}");
        assert_eq!(*CLOSED.lock().unwrap(), closed);
    }
}
