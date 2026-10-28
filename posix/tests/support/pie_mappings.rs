//! Install locally compiled fixture LOADs on the Linux test host.
use super::word;
use std::sync::{Mutex, MutexGuard};
static ADDRESS_SPACE: Mutex<()> = Mutex::new(());
pub struct Mappings {
    ranges: Vec<(*mut libc::c_void, usize)>,
    _address_space: MutexGuard<'static, ()>,
}
impl Default for Mappings {
    fn default() -> Self {
        Self {
            ranges: Vec::new(),
            // Fixtures use fixed virtual addresses in this shared host
            // process. Keep that reservation until their mappings are gone.
            _address_space: ADDRESS_SPACE
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        }
    }
}
impl Drop for Mappings {
    fn drop(&mut self) {
        for &(pointer, length) in self.ranges.iter().rev() {
            assert_eq!(unsafe { libc::munmap(pointer, length) }, 0);
        }
    }
}
impl Mappings {
    pub fn install(&mut self, image: &[u8]) {
        let count = u16::from_le_bytes(image[56..58].try_into().unwrap()) as usize;
        for header in image[64..64 + count * 56].chunks_exact(56) {
            if header[0] != 1 || word(header, 40) == 0 {
                continue;
            }
            let address = word(header, 16) as usize;
            let base = address & !4095;
            let length = (address - base + word(header, 40) as usize + 4095) & !4095;
            let pointer = unsafe {
                libc::mmap(
                    base as *mut _,
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            assert_ne!(
                pointer,
                libc::MAP_FAILED,
                "{}",
                std::io::Error::last_os_error()
            );
            self.ranges.push((pointer, length));
            assert_eq!(pointer as usize, base);
            let offset = word(header, 8) as usize;
            let file = word(header, 32) as usize;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    image[offset..offset + file].as_ptr(),
                    address as *mut u8,
                    file,
                );
            }
            let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
            let protection = if flags & 4 != 0 { libc::PROT_READ } else { 0 }
                | if flags & 2 != 0 { libc::PROT_WRITE } else { 0 }
                | if flags & 1 != 0 { libc::PROT_EXEC } else { 0 };
            assert_eq!(unsafe { libc::mprotect(pointer, length, protection) }, 0);
        }
    }
}
