//! Native resource mechanisms for package-checked, scoped application loading.
use alloc::vec::Vec;
use core::ffi::c_void;
use mochi_user_platform as p;
use mochios_posix_client::image_preparation::{Backend, Source};
use mochios_posix_client::newlib_errno as errno;
use mochios_posix_client::{ClientError, ObjectHandleAttachment};

use crate::image_catalog::Catalog;
type Error = p::syscall::SysError;

pub(crate) fn native(error: Error) -> i32 {
    errno::from_status(error.raw())
}
pub(crate) fn status(error: i32) -> Error {
    Error::from_raw(errno::to_status(error) as i64)
}
pub(crate) fn remote(error: ClientError<Error>) -> i32 {
    match error {
        ClientError::Transport(error) => native(error),
        ClientError::Remote(error) => errno::from_status(error as i64),
        _ => errno::EIO,
    }
}

/// Capture once without moving the shared open-file cursor. No path is reopened.
pub(crate) fn capture(handle: u32) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let mut chunk = [0; mnu_abi::provider::MAX_DATA_LEN];
    loop {
        let count = p::handle::read_at(handle, &mut chunk, bytes.len() as u64)?;
        if count > chunk.len() {
            return Err(status(errno::EIO));
        }
        if count == 0 {
            return Ok(bytes);
        }
        if bytes
            .len()
            .checked_add(count)
            .is_none_or(|n| n > mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES)
        {
            return Err(status(errno::EFBIG));
        }
        bytes
            .try_reserve(count)
            .map_err(|_| status(errno::ENOMEM))?;
        bytes.extend_from_slice(&chunk[..count]);
    }
}

pub(crate) fn readonly(bytes: &[u8]) -> Result<p::memory_object::MemoryObject, Error> {
    let image = p::memory_object::MemoryObject::create_resizable(bytes.len() as u64)?;
    let mut written = 0;
    while written < bytes.len() {
        let count = p::handle::write_at(image.handle(), &bytes[written..], written as u64)?;
        if count == 0 || count > bytes.len() - written {
            return Err(status(errno::EIO));
        }
        written += count;
    }
    let read = p::handle::duplicate(
        image.handle(),
        mochios_posix_protocol::CHECK_EXECUTABLE_RIGHTS,
    )?;
    // Only the attenuated reference survives. Native creation captures it again
    // and verifies the approved output digest before installing any mappings.
    drop(image);
    Ok(unsafe { p::memory_object::MemoryObject::from_owned_handle(read) })
}

pub(crate) struct Mechanisms<'a>(pub(crate) &'a Catalog);
unsafe extern "C" {
    fn malloc(length: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
}
// This Rust broker installs no callbacks that abandon Rust frames. Its C
// allocator supplies max_align_t storage; owned references are always fresh.
unsafe impl Backend for Mechanisms<'_> {
    fn critical<T>(operation: impl FnOnce() -> T) -> T {
        operation()
    }
    fn allocate(length: usize) -> *mut u8 {
        unsafe { malloc(length) }.cast()
    }
    unsafe fn deallocate(pointer: *mut u8) {
        unsafe { free(pointer.cast()) };
    }
    fn close(handle: u32) {
        let _ = p::handle::close(handle);
    }
    fn read_at(&self, image: u32, output: &mut [u8], offset: usize) -> Result<usize, i32> {
        p::handle::read_at(image, output, offset as u64).map_err(native)
    }
    fn open_library(&self, _: &[u8]) -> Result<ObjectHandleAttachment<u32>, i32> {
        Err(errno::EACCES)
    }
    fn validate_library(&self, _: ObjectHandleAttachment<u32>) -> Result<(), i32> {
        Err(errno::EACCES)
    }
    fn validate_captured(&self, source: Source<'_>, bytes: &[u8]) -> Result<(), i32> {
        self.0.validate(source, bytes).map_err(native)
    }
    fn entropy(&self, output: &mut [u8]) -> Result<(), i32> {
        let count = p::syscall::call2(
            p::syscall::SyscallNumber::RandomFill,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        )
        .map_err(native)?;
        if count != output.len() as u64 {
            return Err(errno::EIO);
        }
        Ok(())
    }
    fn create_image(&self, length: usize) -> Result<u32, i32> {
        p::memory_object::MemoryObject::create_resizable(length as u64)
            .map(|image| image.into_handle())
            .map_err(native)
    }
    fn write_at(&self, image: u32, bytes: &[u8], offset: usize) -> Result<usize, i32> {
        p::handle::write_at(image, bytes, offset as u64).map_err(native)
    }
    fn readonly_image(&self, image: u32) -> Result<u32, i32> {
        p::handle::duplicate(image, mochios_posix_protocol::CHECK_EXECUTABLE_RIGHTS).map_err(native)
    }
    fn readonly_metadata(&self, image: u32) -> Result<u32, i32> {
        p::handle::duplicate(image, mochios_posix_client::startup_metadata::READER_RIGHTS)
            .map_err(native)
    }
}
