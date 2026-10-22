//! Publish data from its actual owner. Native final-reference release, not an
//! unsuccessful reply, retires metadata after a provider object was created.
use crate::service::FilesystemService;
use mnu_abi::{
    HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_TRANSFER, IpcObjectHandle,
};

pub const METADATA_RIGHTS: u64 =
    HANDLE_RIGHT_CONTROL | HANDLE_RIGHT_DUPLICATE | HANDLE_RIGHT_TRANSFER;

pub trait Publisher {
    /// Errors are positive wire errno; all operations are local native calls.
    fn create(&mut self, open_id: u64, rights: u64) -> Result<u32, i32>;
    fn close(&mut self, handle: u32);
}

/// Success owns one data reference. Failure closes every reference created
/// here. Only creation failure before any native reference permits directly
/// retiring the service entry: a factory may already hold a metadata reference
/// even when transport or reply publication fails later.
pub fn publish(
    service: &mut FilesystemService,
    open_id: u64,
    ordinary_rights: u64,
    publisher: &mut impl Publisher,
) -> Result<IpcObjectHandle, i32> {
    let external = service.external_open(open_id)?;
    let rights = if external.is_some() {
        METADATA_RIGHTS
    } else {
        ordinary_rights
    };
    let handle = match publisher.create(open_id, rights) {
        Ok(handle) if handle != 0 => handle,
        result => {
            let _ = service.provider_close(open_id);
            return Err(terminal_error(result.err().unwrap_or(5)));
        }
    };
    let metadata = IpcObjectHandle {
        handle,
        reserved: 0,
        rights,
    };
    let Some(external) = external else {
        return Ok(metadata);
    };
    let result = external.publish(metadata).and_then(|opened| {
        if opened.handle == 0
            || opened.handle == handle
            || opened.reserved != 0
            || opened.rights != external.data_rights()
        {
            if opened.handle != 0 && opened.handle != handle {
                publisher.close(opened.handle);
            }
            return Err(5);
        }
        Ok(opened)
    });
    publisher.close(handle);
    result.map_err(terminal_error)
}

fn terminal_error(error: i32) -> i32 {
    // Publication may already have reached the device owner. Never advertise
    // a pre-mutation retry promise without an admission ticket here.
    if error <= 0 || error == mochios_filesystem_protocol::ERROR_MEMORY_ADMISSION_BUSY {
        5
    } else {
        error
    }
}

pub fn publish_native(
    service: &mut FilesystemService,
    endpoint: u32,
    open_id: u64,
    ordinary_rights: u64,
) -> Result<IpcObjectHandle, i32> {
    struct Native(u32);
    impl Publisher for Native {
        fn create(&mut self, id: u64, rights: u64) -> Result<u32, i32> {
            mochi_user_platform::handle::create_provider_object(self.0, id, rights).map_err(|_| 5)
        }
        fn close(&mut self, handle: u32) {
            let _ = mochi_user_platform::handle::close(handle);
        }
    }
    publish(service, open_id, ordinary_rights, &mut Native(endpoint))
}
