//! User-space boot policy for the terminal namespace. The returned reference
//! is an owned directory, never a pathname or an inline filesystem object ID.
use crate::OpenedObject;
use mnu_abi::{
    HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_READ, HANDLE_RIGHT_TRANSFER,
};

pub const RIGHTS: u64 =
    HANDLE_RIGHT_READ | HANDLE_RIGHT_CONTROL | HANDLE_RIGHT_DUPLICATE | HANDLE_RIGHT_TRANSFER;

pub trait Backend {
    /// Open with DIRECTORY|NOFOLLOW. A parent is an explicitly borrowed Handle.
    fn open_directory(
        &mut self,
        path: &[u8],
        parent: Option<OpenedObject<u32>>,
    ) -> Result<OpenedObject<u32>, i32>;
    /// Service-owner configuration, authorized by the parent's CONTROL right.
    fn create_directory(&mut self, parent: OpenedObject<u32>, name: &[u8]) -> Result<(), i32>;
    fn close(&mut self, handle: u32);
}

fn valid(object: OpenedObject<u32>) -> bool {
    object.handle != 0 && object.rights & RIGHTS == RIGHTS
}

/// Errors use negative POSIX wire status. Creation is idempotent, but an
/// existing wrong-kind or symlink child must fail the DIRECTORY|NOFOLLOW open.
pub fn prepare(backend: &mut impl Backend) -> Result<OpenedObject<u32>, i32> {
    let parent = backend.open_directory(b"/dev", None)?;
    if !valid(parent) {
        if parent.handle != 0 {
            backend.close(parent.handle);
        }
        return Err(-13);
    }
    let result = (|| {
        match backend.create_directory(parent, b"pts") {
            Ok(()) | Err(-17) => {}
            Err(error) => return Err(error),
        }
        let child = backend.open_directory(b"pts", Some(parent))?;
        if child.handle == parent.handle {
            return Err(-5);
        }
        if !valid(child) {
            if child.handle != 0 {
                backend.close(child.handle);
            }
            return Err(-13);
        }
        Ok(OpenedObject {
            handle: child.handle,
            rights: RIGHTS,
        })
    })();
    backend.close(parent.handle);
    result
}
