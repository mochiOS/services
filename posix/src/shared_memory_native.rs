//! Native RAM ownership for the userspace shared-memory namespace.

use mochi_user_platform::{handle, memory_object::MemoryObject, syscall};
use posix_service::shared_memory::{Backing, Delegation};

pub struct NativeBacking;

impl Backing<u32> for NativeBacking {
    fn create_zero_length(&mut self) -> Result<u32, i32> {
        MemoryObject::create_resizable(0)
            .map(MemoryObject::into_handle)
            .map_err(|error| error.raw() as i32)
    }

    fn truncate_zero(&mut self, backing: u32) -> Result<(), i32> {
        syscall::call2(
            syscall::SyscallNumber::MemoryObjectResize,
            backing as u64,
            0,
        )
        .map(|_| ())
        .map_err(|error| error.raw() as i32)
    }
}

impl Delegation<u32> for NativeBacking {
    fn duplicate(&mut self, backing: u32, rights: u64) -> Result<u32, i32> {
        handle::duplicate(backing, rights).map_err(|error| error.raw() as i32)
    }

    fn close(&mut self, backing: u32) -> Result<(), i32> {
        handle::close(backing).map_err(|error| error.raw() as i32)
    }
}
