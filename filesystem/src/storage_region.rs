//! Native provider objects own a single driver-pinned, bounded storage region.
use crate::service::FilesystemService;
use mnu_abi::provider;
use mochios_filesystem_protocol::storage_region as wire;

pub const RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ
    | mnu_abi::HANDLE_RIGHT_WRITE
    | mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_TRANSFER;

pub struct Admission(wire::Request);
pub fn admit(
    bytes: &[u8],
    handles: &mnu_abi::IpcObjectHandles,
    authorized: impl FnOnce() -> bool,
) -> Result<Admission, i32> {
    if !authorized()
        || handles.count != 0
        || handles.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
    {
        return Err(13);
    }
    wire::Request::decode(bytes).map(Admission).ok_or(22)
}
trait Device: Send {
    fn read(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), i32>;
    fn write(&mut self, lba: u64, bytes: &[u8]) -> Result<(), i32>;
    fn flush(&mut self) -> Result<(), i32>;
    fn close(&mut self) -> Result<(), i32>;
}
pub struct Region {
    device: Box<dyn Device>,
    bytes: u64,
    failed: bool,
}
impl Region {
    fn range(&self, offset: u64, length: usize) -> Result<(), i32> {
        if self.failed {
            return Err(116);
        }
        if offset % 512 != 0
            || length == 0
            || length % 512 != 0
            || length > mnu_abi::provider::MAX_DATA_LEN
            || offset
                .checked_add(length as u64)
                .is_none_or(|end| end > self.bytes)
        {
            return Err(22);
        }
        Ok(())
    }
    pub(crate) fn close(&mut self) -> Result<(), i32> {
        self.device.close()
    }
    fn request(
        &mut self,
        h: provider::RequestHeader,
        payload: &[u8],
        attached: u32,
    ) -> Result<(u64, Vec<u8>), i32> {
        if attached != 0 {
            return Err(22);
        }
        let result = match h.opcode {
            provider::OP_READ_AT if payload.is_empty() => {
                self.range(h.basis, h.length as usize)?;
                let mut bytes = vec![0; h.length as usize];
                self.device
                    .read(h.basis / 512, &mut bytes)
                    .map(|()| (bytes.len() as u64, bytes))
            }
            provider::OP_WRITE_AT if h.length as usize == payload.len() => {
                self.range(h.basis, payload.len())?;
                self.device
                    .write(h.basis / 512, payload)
                    .map(|()| (payload.len() as u64, vec![]))
            }
            provider::OP_SYNC | provider::OP_CONTROL
                if payload.is_empty()
                    && h.length == 0
                    && h.argument == 0
                    && (h.opcode == provider::OP_SYNC || h.basis == wire::FLUSH) =>
            {
                if self.failed {
                    return Err(116);
                }
                self.device.flush().map(|()| (0, vec![]))
            }
            _ => return Err(95),
        };
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}
#[cfg(target_os = "mochios")]
struct Native(u32);
#[cfg(target_os = "mochios")]
impl Device for Native {
    fn read(&mut self, lba: u64, b: &mut [u8]) -> Result<(), i32> {
        mochi_user_platform::storage::block_read(self.0, lba, b)
            .map(|_| ())
            .map_err(|_| 5)
    }
    fn write(&mut self, lba: u64, b: &[u8]) -> Result<(), i32> {
        mochi_user_platform::storage::block_write(self.0, lba, b)
            .map(|_| ())
            .map_err(|_| 5)
    }
    fn flush(&mut self) -> Result<(), i32> {
        mochi_user_platform::storage::block_flush(self.0)
            .map(|_| ())
            .map_err(|_| 5)
    }
    fn close(&mut self) -> Result<(), i32> {
        let r = control(mnu_abi::STORAGE_CONTROL_CLOSE_REGION, self.0, [0; 4])?;
        if r.status != 0 {
            return Err(5);
        }
        Ok(())
    }
}
#[cfg(target_os = "mochios")]
fn control(op: u16, id: u32, args: [u64; 4]) -> Result<mnu_abi::StorageControlResponse, i32> {
    mochi_user_platform::storage::control(mnu_abi::StorageControlRequest {
        operation: op,
        device_id: id,
        arguments: args,
        reserved0: 0,
    })
    .map_err(|_| 5)
}
impl FilesystemService {
    pub fn acquire_storage_region(&mut self, admission: Admission) -> Result<u64, i32> {
        #[cfg(not(target_os = "mochios"))]
        {
            let _ = admission;
            Err(95)
        }
        #[cfg(target_os = "mochios")]
        {
            let r = admission.0;
            let before = self.selected_storage(r.generation, r.disk)?;
            let identity = control(
                mnu_abi::STORAGE_CONTROL_INSPECT,
                before.device,
                [mnu_abi::STORAGE_QUERY_DEVICE_IDENTITY, 0, 0, 0],
            )?;
            if identity.status != 0
                || identity.values[0] != r.epoch
                || identity.values[2] != 512
                || identity.values[3] != 0
                || identity.values[1].checked_mul(512) != Some(before.capacity)
                || r.first
                    .checked_add(r.sectors)
                    .is_none_or(|n| n > identity.values[1])
            {
                return Err(95);
            }
            self.refresh_storage_inventory()?;
            let current = self.reservable_disk(r.disk)?;
            if before != current {
                return Err(116);
            }
            let object = self.retain_storage_reservation(r.disk, current)?;
            let opened = control(
                mnu_abi::STORAGE_CONTROL_OPEN_REGION,
                before.device,
                [identity.values[0], r.first, r.sectors, 0],
            );
            match opened {
                Ok(o)
                    if o.status == 0
                        && o.device_id & 0x80000000 != 0
                        && o.values == [r.sectors, 512, identity.values[0], 0] =>
                {
                    self.storage_regions.insert(
                        object,
                        Region {
                            device: Box::new(Native(o.device_id)),
                            bytes: r.sectors.checked_mul(512).ok_or(75)?,
                            failed: false,
                        },
                    );
                    Ok(object)
                }
                // An uncertain open remains reserved: the driver might own it.
                Err(error) => Err(error),
                _ => {
                    let _ = self.provider_close(object);
                    Err(5)
                }
            }
        }
    }
    pub fn is_storage_region(&self, object: u64) -> bool {
        self.storage_regions.contains_key(&object)
    }
    pub fn storage_region_request(
        &mut self,
        h: provider::RequestHeader,
        payload: &[u8],
        attached: u32,
    ) -> Result<(u64, Vec<u8>), i32> {
        self.storage_regions
            .get_mut(&h.object_id)
            .ok_or(9)?
            .request(h, payload, attached)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    struct Memory(Arc<Mutex<Vec<u8>>>);
    impl Device for Memory {
        fn read(&mut self, lba: u64, b: &mut [u8]) -> Result<(), i32> {
            b.copy_from_slice(
                &self.0.lock().unwrap()[lba as usize * 512..lba as usize * 512 + b.len()],
            );
            Ok(())
        }
        fn write(&mut self, lba: u64, b: &[u8]) -> Result<(), i32> {
            self.0.lock().unwrap()[lba as usize * 512..lba as usize * 512 + b.len()]
                .copy_from_slice(b);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), i32> {
            Err(5)
        }
        fn close(&mut self) -> Result<(), i32> {
            Ok(())
        }
    }
    #[test]
    fn bounded_io_and_irreversible_failure() {
        let bytes = Arc::new(Mutex::new(vec![0; 1024]));
        let mut r = Region {
            device: Box::new(Memory(bytes.clone())),
            bytes: 1024,
            failed: false,
        };
        let mut h = provider::RequestHeader {
            opcode: provider::OP_WRITE_AT,
            object_id: 1,
            basis: 512,
            length: 512,
            argument: 0,
            data_length: 512,
        };
        assert!(r.request(h, &[7; 512], 0).is_ok());
        assert_eq!(bytes.lock().unwrap()[512], 7);
        h.basis = 1024;
        assert_eq!(r.request(h, &[8; 512], 0), Err(22));
        assert!(!r.failed);
        h.opcode = provider::OP_SYNC;
        h.length = 0;
        h.data_length = 0;
        assert_eq!(r.request(h, &[], 0), Err(5));
        assert!(r.failed);
        h.opcode = provider::OP_READ_AT;
        h.basis = 0;
        h.length = 512;
        assert_eq!(r.request(h, &[], 0), Err(116));
    }
    #[test]
    fn admission_has_no_self_asserted_permission() {
        let b = wire::Request {
            generation: 1,
            disk: 2,
            first: 0,
            sectors: 10,
            epoch: 7,
        }
        .encode();
        let mut h = mnu_abi::IpcObjectHandles::default();
        assert!(admit(&b, &h, || true).is_err());
        h.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
        assert!(admit(&b, &h, || false).is_err());
        assert!(admit(&b, &h, || true).is_ok());
        h.count = 1;
        assert!(admit(&b, &h, || true).is_err());
    }
}
