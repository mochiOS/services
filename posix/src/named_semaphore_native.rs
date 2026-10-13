//! Native MemoryObject ownership for the POSIX named semaphore namespace.

use mochi_user_platform::{handle, memory};
use mochios_posix_client::semaphore::Semaphore;
use posix_service::named_semaphore::Backing;

pub struct NativeBacking;
const PAGE_SIZE: u64 = 4096;

impl Backing<u32> for NativeBacking {
    fn create_initialized(&mut self, value: u32) -> Result<u32, i32> {
        let semaphore = Semaphore::new(value, true).map_err(|_| -22)?;
        let raw = memory::create_object(PAGE_SIZE).map_err(|err| err.raw() as i32)?;
        let object = u32::try_from(raw).map_err(|_| -5)?;
        let address = match memory::map(
            0,
            PAGE_SIZE,
            mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE,
            mnu_abi::MEMORY_MAP_SHARED,
            raw,
        ) {
            Ok(address) => address,
            Err(error) => {
                let _ = handle::close(object);
                return Err(error.raw() as i32);
            }
        };
        // Native mapping is page-aligned and owns a writable, zero-filled page.
        // Initialize before the namespace or any client can observe the object.
        unsafe { (address as *mut Semaphore).write(semaphore) };
        if let Err(error) = memory::munmap(address, PAGE_SIZE) {
            let _ = handle::close(object);
            return Err(error.raw() as i32);
        }
        Ok(object)
    }

    fn duplicate(&mut self, object: u32, rights: u64) -> Result<u32, i32> {
        handle::duplicate(object, rights).map_err(|error| error.raw() as i32)
    }

    fn close(&mut self, object: u32) -> Result<(), i32> {
        handle::close(object).map_err(|error| error.raw() as i32)
    }
}
