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
