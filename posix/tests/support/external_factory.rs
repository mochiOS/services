//! Deterministic factory, never a native IPC/Handle-transfer emulator.
use filesystem_service::{devfs::ExternalDevice, device_factory::Factory};
use mnu_abi::IpcObjectHandle;
use mochios_filesystem_protocol::device_open::Request;
use std::sync::{Arc, Mutex};
#[derive(Debug, Default)]
pub struct Calls {
    pub requests: Vec<(IpcObjectHandle, Request)>,
    pub dropped: usize,
}
#[derive(Debug)]
struct Recording(Arc<Mutex<Calls>>);
impl Factory for Recording {
    fn open(&self, metadata: IpcObjectHandle, request: Request) -> Result<IpcObjectHandle, i32> {
        let mut calls = self.0.lock().unwrap();
        calls.requests.push((metadata, request));
        Ok(IpcObjectHandle {
            handle: 100 + calls.requests.len() as u32,
            reserved: 0,
            rights: request.rights,
        })
    }
}
impl Drop for Recording {
    fn drop(&mut self) {
        self.0.lock().unwrap().dropped += 1;
    }
}
pub fn definition(calls: &Arc<Mutex<Calls>>, special_device: u64) -> ExternalDevice {
    ExternalDevice {
        special_device,
        factory: Arc::new(Recording(calls.clone())),
    }
}
pub fn metadata() -> IpcObjectHandle {
    IpcObjectHandle {
        handle: 70,
        reserved: 0,
        rights: mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER,
    }
}
