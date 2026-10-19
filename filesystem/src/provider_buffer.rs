/// Private, bounded scratch storage for the single provider request loop.
/// Never retain a caller's mapping or handle between requests.
#[derive(Default)]
pub struct ProviderReadBuffer {
    bytes: Vec<u8>,
}

impl ProviderReadBuffer {
    pub fn get(&mut self, length: usize) -> Result<&mut [u8], i32> {
        if length == 0 || length > mnu_abi::provider::MAX_SHARED_READ_LEN {
            return Err(22);
        }
        if length > self.bytes.len() {
            self.bytes
                .try_reserve_exact(length - self.bytes.len())
                .map_err(|_| 12)?;
            self.bytes.resize(length, 0);
        }
        // Only the bytes reported as read by the provider may be copied out.
        // Old contents remain private; retaining them avoids re-faulting and
        // re-zeroing an allocation for every chunk of a large read.
        Ok(&mut self.bytes[..length])
    }
}

/// Publish only the initialized read prefix into a transferred memory object.
/// Translate native write failures at the filesystem wire boundary, not by
/// taking their numeric magnitude. Native status tags are not POSIX errno.
pub fn publish_native(
    bytes: &[u8],
    offset: u64,
    mut write: impl FnMut(&[u8], u64) -> Result<usize, mochi_user_platform::syscall::SysError>,
) -> Result<(), i32> {
    publish(bytes, offset, |bytes, offset| {
        write(bytes, offset).map_err(crate::memory_updates::native_error)
    })
}

/// Publish only the initialized read prefix into a transferred memory object.
/// A short write is retried at its new offset; never acknowledge stale bytes.
pub fn publish(
    bytes: &[u8],
    offset: u64,
    mut write: impl FnMut(&[u8], u64) -> Result<usize, i32>,
) -> Result<(), i32> {
    offset.checked_add(bytes.len() as u64).ok_or(22)?;
    let mut done = 0;
    while done < bytes.len() {
        match write(&bytes[done..], offset + done as u64) {
            Ok(count) if count > 0 && count <= bytes.len() - done => done += count,
            Ok(_) => return Err(5),
            Err(4) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
