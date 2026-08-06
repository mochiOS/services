use mochi_user_platform as platform;
use plugkit::virtio::{DmaMemory, VirtioResult};

pub(super) struct DmaRegion {
    allocation: platform::DmaAllocation,
    length: usize,
}

impl DmaRegion {
    pub(super) fn allocate(length: usize) -> Result<Self, u64> {
        if length == 0 {
            return Err(mochi_user_syscall::EINVAL);
        }
        let allocation = platform::memory::dma_alloc(length as u64)
            .map_err(|error| error.errno().unwrap_or(mochi_user_syscall::EIO))?;
        if allocation.virt_addr == 0 || allocation.phys_addr == 0 || allocation.len < length as u64
        {
            if allocation.handle != 0 {
                let _ = platform::memory::dma_free(allocation.handle);
            }
            return Err(mochi_user_syscall::EIO);
        }
        let mut region = Self { allocation, length };
        region.bytes_mut().fill(0);
        Ok(region)
    }
}

impl DmaMemory for DmaRegion {
    fn len(&self) -> usize {
        self.length
    }

    fn device_address(&self) -> u64 {
        self.allocation.phys_addr
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: dma_alloc returns a process mapping valid until dma_free in Drop.
        unsafe { core::slice::from_raw_parts(self.allocation.virt_addr as *const u8, self.length) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: this region uniquely owns the writable mapping.
        unsafe {
            core::slice::from_raw_parts_mut(self.allocation.virt_addr as *mut u8, self.length)
        }
    }

    fn sync_for_device(&self) -> VirtioResult<()> {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn sync_for_cpu(&self) -> VirtioResult<()> {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        Ok(())
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        let _ = platform::memory::dma_free(self.allocation.handle);
    }
}
