use mochi_user_platform as platform;
use mochi_user_syscall::{EIO, ERANGE};

use crate::present::{BYTES_PER_PIXEL, DisplayGeometry, PresentFrame};

const FB_VIRT: u64 = 0x0000_6000_0000_0000;

pub(crate) struct FramebufferBackend {
    geometry: DisplayGeometry,
    pixels: *mut u8,
    mapped_size: u64,
}

impl FramebufferBackend {
    pub(crate) fn initialize() -> Result<Self, u64> {
        let info = platform::memory::framebuffer_info().map_err(|_| EIO)?;
        let visible_height = visible_height(&info)?;
        let geometry = DisplayGeometry {
            width: info.width,
            height: visible_height,
            stride: info.stride,
            format: crate::present::PIXEL_FORMAT_XRGB8888,
        };
        let _ = geometry.byte_len()?;
        let offset = info.addr & 0xfff;
        let mapped_size = page_align_up(info.size.checked_add(offset).ok_or(ERANGE)?)?;
        platform::memory::map_framebuffer(FB_VIRT, mapped_size).map_err(|_| EIO)?;
        Ok(Self {
            geometry,
            pixels: (FB_VIRT + offset) as *mut u8,
            mapped_size,
        })
    }

    pub(crate) const fn geometry(&self) -> DisplayGeometry {
        self.geometry
    }

    pub(crate) fn present(&mut self, frame: &PresentFrame<'_>) -> Result<(), u64> {
        frame.validate()?;
        if frame.damage.is_empty() {
            return Ok(());
        }
        let copy_right = frame
            .damage
            .x
            .checked_add(frame.damage.width)
            .ok_or(ERANGE)?
            .min(self.geometry.width);
        let copy_bottom = frame
            .damage
            .y
            .checked_add(frame.damage.height)
            .ok_or(ERANGE)?
            .min(self.geometry.height);
        let copy_width = copy_right
            .saturating_sub(frame.damage.x)
            .min(frame.geometry.width.saturating_sub(frame.damage.x));
        if copy_width == 0 || copy_bottom <= frame.damage.y {
            return Ok(());
        }
        let bytes = (copy_width as usize)
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(ERANGE)?;
        let source_row = (frame.geometry.stride as usize)
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(ERANGE)?;
        let destination_row = (self.geometry.stride as usize)
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(ERANGE)?;
        let x_offset = (frame.damage.x as usize)
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(ERANGE)?;
        for y in frame.damage.y as usize..copy_bottom as usize {
            let source = y
                .checked_mul(source_row)
                .and_then(|offset| offset.checked_add(x_offset))
                .ok_or(ERANGE)?;
            let destination = y
                .checked_mul(destination_row)
                .and_then(|offset| offset.checked_add(x_offset))
                .ok_or(ERANGE)?;
            let source_end = source.checked_add(bytes).ok_or(ERANGE)?;
            let source = frame.pixels.get(source..source_end).ok_or(ERANGE)?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source.as_ptr(),
                    self.pixels.add(destination),
                    bytes,
                );
            }
        }
        Ok(())
    }
}

impl Drop for FramebufferBackend {
    fn drop(&mut self) {
        let _ = platform::memory::munmap(FB_VIRT, self.mapped_size);
    }
}

fn visible_height(info: &platform::memory::FramebufferInfo) -> Result<u32, u64> {
    let row_bytes = (info.stride as usize)
        .checked_mul(BYTES_PER_PIXEL)
        .ok_or(ERANGE)?;
    if row_bytes == 0 {
        return Err(ERANGE);
    }
    let rows = (info.size as usize) / row_bytes;
    let reported = info.height as usize;
    let visible = if rows > reported && rows <= crate::present::MAX_DIMENSION as usize {
        rows
    } else {
        reported
    };
    u32::try_from(visible).map_err(|_| ERANGE)
}

fn page_align_up(value: u64) -> Result<u64, u64> {
    value
        .checked_add(0xfff)
        .map(|value| value & !0xfff)
        .ok_or(ERANGE)
}
