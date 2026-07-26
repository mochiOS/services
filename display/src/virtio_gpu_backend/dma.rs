use alloc::vec::Vec;

use mochi_user_platform as platform;
use mochios_virtio_gpu_protocol::MemoryEntry;
use plugkit::virtio::{DmaMemory, VirtioResult};

use crate::present::BYTES_PER_PIXEL;

const BACKING_CHUNK_SIZE: usize = 1024 * 1024;

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

    pub(super) fn physical_address(&self) -> u64 {
        self.allocation.phys_addr
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
        unsafe { core::slice::from_raw_parts(self.allocation.virt_addr as *const u8, self.length) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
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

pub(super) struct BackingStore {
    regions: Vec<DmaRegion>,
    entries: Vec<MemoryEntry>,
    length: usize,
}

impl BackingStore {
    pub(super) fn allocate(length: usize) -> Result<Self, u64> {
        if length == 0 {
            return Err(mochi_user_syscall::EINVAL);
        }
        let mut regions = Vec::new();
        let mut entries = Vec::new();
        let mut remaining = length;
        while remaining != 0 {
            let chunk = remaining.min(BACKING_CHUNK_SIZE);
            let region = DmaRegion::allocate(chunk)?;
            entries.push(MemoryEntry {
                address: region.physical_address(),
                length: u32::try_from(chunk).map_err(|_| mochi_user_syscall::ERANGE)?,
            });
            regions.push(region);
            remaining -= chunk;
        }
        Ok(Self {
            regions,
            entries,
            length,
        })
    }

    pub(super) fn entries(&self) -> &[MemoryEntry] {
        &self.entries
    }

    pub(super) fn write_cursor_rgba(&mut self, rgba: &[u8]) -> Result<(), u64> {
        if rgba.len() > self.length || rgba.len() % 4 != 0 {
            return Err(mochi_user_syscall::EINVAL);
        }
        for (index, pixel) in rgba.chunks_exact(4).enumerate() {
            let bgra = [pixel[2], pixel[1], pixel[0], pixel[3]];
            self.write_at(index * 4, &bgra)?;
        }
        Ok(())
    }

    pub(super) fn write_all(&mut self, bytes: &[u8]) -> Result<(), u64> {
        if bytes.len() > self.length {
            return Err(mochi_user_syscall::ERANGE);
        }
        self.write_at(0, bytes)
    }

    pub(super) fn read_u32_at(&mut self, mut offset: usize) -> Result<u32, u64> {
        if offset.checked_add(4).is_none_or(|end| end > self.length) {
            return Err(mochi_user_syscall::ERANGE);
        }
        for region in &mut self.regions {
            region.sync_for_cpu().map_err(|_| mochi_user_syscall::EIO)?;
            if offset >= region.len() {
                offset -= region.len();
                continue;
            }
            let bytes = region
                .bytes()
                .get(offset..offset + 4)
                .ok_or(mochi_user_syscall::ERANGE)?;
            return Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        }
        Err(mochi_user_syscall::ERANGE)
    }

    pub(super) fn copy_rect(
        &mut self,
        source: &[u8],
        source_stride: u32,
        destination_stride: u32,
        rect: crate::present::DamageRect,
    ) -> Result<(), u64> {
        let source_row = (source_stride as usize)
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(mochi_user_syscall::ERANGE)?;
        let destination_row = (destination_stride as usize)
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(mochi_user_syscall::ERANGE)?;
        let x = (rect.x as usize)
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(mochi_user_syscall::ERANGE)?;
        let width = (rect.width as usize)
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(mochi_user_syscall::ERANGE)?;
        let bottom = rect
            .y
            .checked_add(rect.height)
            .ok_or(mochi_user_syscall::ERANGE)?;
        for y in rect.y as usize..bottom as usize {
            let source_offset = y
                .checked_mul(source_row)
                .and_then(|offset| offset.checked_add(x))
                .ok_or(mochi_user_syscall::ERANGE)?;
            let destination_offset = y
                .checked_mul(destination_row)
                .and_then(|offset| offset.checked_add(x))
                .ok_or(mochi_user_syscall::ERANGE)?;
            let source_end = source_offset
                .checked_add(width)
                .ok_or(mochi_user_syscall::ERANGE)?;
            let row = source
                .get(source_offset..source_end)
                .ok_or(mochi_user_syscall::EINVAL)?;
            self.write_at(destination_offset, row)?;
        }
        Ok(())
    }

    pub(super) fn write_at(&mut self, mut offset: usize, mut bytes: &[u8]) -> Result<(), u64> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.length)
        {
            return Err(mochi_user_syscall::ERANGE);
        }
        for region in &mut self.regions {
            if offset >= region.len() {
                offset -= region.len();
                continue;
            }
            let available = region.len() - offset;
            let copied = available.min(bytes.len());
            region.bytes_mut()[offset..offset + copied].copy_from_slice(&bytes[..copied]);
            bytes = &bytes[copied..];
            offset = 0;
            if bytes.is_empty() {
                return Ok(());
            }
        }
        Err(mochi_user_syscall::ERANGE)
    }
}
