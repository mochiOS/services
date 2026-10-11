//! Initial boot policy reads from the selected immutable System partition.
//! Reuse the userspace filesystem reader; no POSIX endpoint exists yet.

use std::sync::{Arc, Mutex};

use filesystem_service::bootstrap_read::BootstrapReader;
use filesystem_service::platform_storage::{MochiDisk, find_system_partition};
use filesystem_service::storage::PartitionIo;
use mochi_user_platform as platform;
use mochi_user_syscall::{EIO, SysError};
use mochios_filesystem_protocol as wire;

const MAX_BOOT_POLICY_BYTES: usize = 256 * 1024;
static READER: Mutex<Option<BootstrapReader>> = Mutex::new(None);

pub(super) fn read(path: &str) -> Result<Vec<u8>, SysError> {
    let mut reader = READER.lock().map_err(|_| SysError::from_raw(EIO as i64))?;
    if reader.is_none() {
        let (first_lba, sector_count) =
            find_system_partition(0).map_err(|_| SysError::from_raw(EIO as i64))?;
        let partition = Arc::new(PartitionIo::new(MochiDisk::new(0), first_lba, sector_count));
        *reader =
            Some(BootstrapReader::load(partition).map_err(|_| SysError::from_raw(EIO as i64))?);
    }
    reader
        .as_ref()
        .ok_or_else(|| SysError::from_raw(EIO as i64))?
        .read(path, MAX_BOOT_POLICY_BYTES)
        .map_err(|_| SysError::from_raw(EIO as i64))
}

/// Dispatch only messages from the process to which SEND authority was
/// delegated. The identity is kernel-authenticated IPC metadata, never a PID
/// supplied in a request. This also rejects guessed transitional endpoint IDs.
pub(super) fn serve(endpoint: u32, expected_process: u64) -> ! {
    let mut request = vec![0; wire::HEADER_LEN + wire::MAX_PATH_LEN];
    let mut reply = vec![0; wire::HEADER_LEN + wire::BOOTSTRAP_MAX_TRANSFER];
    loop {
        let mut handles = platform::ipc::IpcObjectHandles::default();
        let received =
            match platform::ipc::wait_object_handles(endpoint as u64, &mut request, &mut handles) {
                Ok(message) => message,
                Err(error) => {
                    platform::logln!(
                        "core.service: bootstrap receive failed errno={}",
                        error.errno().unwrap_or(0)
                    );
                    platform::process::exit(1);
                }
            };
        let sender = received >> 32;
        let length = (received & 0xffff_ffff) as usize;
        let attached = handles.count != 0 || handles.reserved != 0;
        for entry in handles
            .handles
            .iter()
            .take((handles.count as usize).min(handles.handles.len()))
        {
            if entry.handle != 0 {
                let _ = platform::handle::close(entry.handle);
            }
        }
        let bytes = request.get(..length).unwrap_or(&[]);
        let result = if platform::ipc::endpoint_owner_process(sender) != Ok(expected_process) {
            Err(-13)
        } else if attached || length > request.len() {
            Err(-22)
        } else {
            READER.lock().map_err(|_| -5).and_then(|reader| {
                let reader = reader.as_ref().ok_or(-5)?;
                filesystem_service::bootstrap_ipc::respond(reader, bytes, &mut reply)
                    .map_err(|_| -5)
            })
        };
        let length = match result {
            Ok(length) => length,
            Err(status) => {
                let request_id = wire::decode(bytes)
                    .map(|(header, _)| header.request_id)
                    .unwrap_or(0);
                // Fixed buffer and empty payload always fit.
                match wire::encode(
                    wire::Header {
                        opcode: wire::OP_STATUS,
                        request_id,
                        status,
                        ..wire::Header::default()
                    },
                    &[],
                    &mut reply,
                ) {
                    Ok(length) => length,
                    Err(_) => platform::process::exit(1),
                }
            }
        };
        if let Err(error) = platform::ipc::reply(sender, &reply[..length]) {
            platform::logln!(
                "core.service: bootstrap reply failed errno={}",
                error.errno().unwrap_or(0)
            );
        }
    }
}
