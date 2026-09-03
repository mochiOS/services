use mochi_user_platform as platform;
use mochi_user_syscall::{EIO, ERANGE};

use crate::present::{BYTES_PER_PIXEL, DisplayGeometry, PresentFrame};

const FB_VIRT: u64 = 0x0000_6000_0000_0000;
const FORMAT_MEDIATED_FIRMWARE: u32 = 1 << 31;
const FORMAT_SHARED_SURFACE: u32 = 1 << 30;

pub(crate) struct FramebufferBackend {
    geometry: DisplayGeometry,
    pixels: *mut u8,
    mapped_size: u64,
    mdriver: bool,
    firmware_mediated: bool,
    shared_surface: bool,
    transfer_limit: usize,
    transfer_buffer: Vec<u8>,
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
        if info.addr == 0 {
            let firmware_mediated = info.format & FORMAT_MEDIATED_FIRMWARE != 0;
            let transfer_limit = platform::memory::framebuffer_transfer_limit()
                .map_err(|error| error.errno().unwrap_or(EIO))?;
            if transfer_limit < BYTES_PER_PIXEL {
                return Err(ERANGE);
            }
            platform::logln!(
                "display.driver: backend={}",
                if firmware_mediated {
                    "mBoot-firmware-display"
                } else {
                    "mDriver-display"
                }
            );
            return Ok(Self {
                geometry,
                pixels: core::ptr::null_mut(),
                mapped_size: 0,
                mdriver: !firmware_mediated,
                firmware_mediated,
                shared_surface: false,
                transfer_limit,
                transfer_buffer: Vec::new(),
            });
        }
        let offset = info.addr & 0xfff;
        let mapped_size = page_align_up(info.size.checked_add(offset).ok_or(ERANGE)?)?;
        platform::memory::map_framebuffer(FB_VIRT, mapped_size).map_err(|_| EIO)?;
        Ok(Self {
            geometry,
            pixels: (FB_VIRT + offset) as *mut u8,
            mapped_size,
            mdriver: false,
            firmware_mediated: false,
            shared_surface: info.format & FORMAT_SHARED_SURFACE != 0,
            transfer_limit: 0,
            transfer_buffer: Vec::new(),
        })
    }

    pub(crate) const fn geometry(&self) -> DisplayGeometry {
        self.geometry
    }

    /// Replaces the firmware boot screen as soon as the mediated display is
    /// usable.  This also verifies the complete mDriver display path before
    /// the service announces readiness to the compositor.
    pub(crate) fn present_startup_frame(&mut self, color: u32) -> Result<(), u64> {
        const MARKER_WIDTH: u32 = 512;
        const MARKER_HEIGHT: u32 = 128;
        let width = self.geometry.width.min(MARKER_WIDTH);
        let height = self.geometry.height.min(MARKER_HEIGHT);
        let origin_x = self.geometry.width.saturating_sub(width) / 2;
        let origin_y = self.geometry.height.saturating_sub(height) / 2;

        if self.mdriver || self.firmware_mediated {
            let pixel = color.to_le_bytes();
            self.transfer_buffer.resize(self.transfer_limit, 0);
            for chunk in self.transfer_buffer.chunks_exact_mut(BYTES_PER_PIXEL) {
                chunk.copy_from_slice(&pixel);
            }
            let row_bytes = usize::try_from(width)
                .ok()
                .and_then(|width| width.checked_mul(BYTES_PER_PIXEL))
                .ok_or(ERANGE)?;
            let rows_per_tile = u32::try_from(self.transfer_buffer.len() / row_bytes)
                .map_err(|_| ERANGE)?
                .max(1);
            let mut y = 0u32;
            while y < height {
                let rows = (height - y).min(rows_per_tile);
                let byte_len = row_bytes
                    .checked_mul(usize::try_from(rows).map_err(|_| ERANGE)?)
                    .ok_or(ERANGE)?;
                platform::memory::present_framebuffer(
                    origin_x,
                    origin_y + y,
                    width,
                    rows,
                    &self.transfer_buffer[..byte_len],
                )
                .map_err(|error| error.errno().unwrap_or(EIO))?;
                y += rows;
            }
            return Ok(());
        }

        for y in origin_y as usize..(origin_y + height) as usize {
            let row = y
                .checked_mul(self.geometry.stride as usize)
                .and_then(|pixels| pixels.checked_mul(BYTES_PER_PIXEL))
                .ok_or(ERANGE)?;
            for x in origin_x as usize..(origin_x + width) as usize {
                unsafe {
                    self.pixels
                        .add(row + x * BYTES_PER_PIXEL)
                        .cast::<u32>()
                        .write_volatile(color)
                };
            }
        }
        if self.shared_surface {
            platform::memory::commit_framebuffer(origin_x, origin_y, width, height)
                .map_err(|error| error.errno().unwrap_or(EIO))?;
        }
        Ok(())
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
        if self.mdriver || self.firmware_mediated {
            return self.present_mediated(frame, copy_right, copy_bottom, source_row);
        }
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
        if self.shared_surface {
            platform::memory::commit_framebuffer(
                frame.damage.x,
                frame.damage.y,
                copy_width,
                copy_bottom - frame.damage.y,
            )
            .map_err(|error| error.errno().unwrap_or(EIO))?;
        }
        Ok(())
    }

    fn present_mediated(
        &mut self,
        frame: &PresentFrame<'_>,
        copy_right: u32,
        copy_bottom: u32,
        source_row: usize,
    ) -> Result<(), u64> {
        let max_width = self.transfer_limit / BYTES_PER_PIXEL;
        if max_width == 0 {
            return Err(ERANGE);
        }
        let mut x = frame.damage.x as usize;
        while x < copy_right as usize {
            let tile_width = core::cmp::min(copy_right as usize - x, max_width);
            let tile_bytes = tile_width.checked_mul(BYTES_PER_PIXEL).ok_or(ERANGE)?;
            let rows_per_transfer = (self.transfer_limit / tile_bytes).max(1);
            let mut y = frame.damage.y as usize;
            while y < copy_bottom as usize {
                let rows = core::cmp::min(copy_bottom as usize - y, rows_per_transfer);
                let byte_len = tile_bytes.checked_mul(rows).ok_or(ERANGE)?;
                let source = y
                    .checked_mul(source_row)
                    .and_then(|offset| {
                        x.checked_mul(BYTES_PER_PIXEL)
                            .and_then(|x_offset| offset.checked_add(x_offset))
                    })
                    .ok_or(ERANGE)?;
                if tile_bytes == source_row {
                    let source_end = source.checked_add(byte_len).ok_or(ERANGE)?;
                    let pixels = frame.pixels.get(source..source_end).ok_or(ERANGE)?;
                    platform::memory::present_framebuffer(
                        x as u32,
                        y as u32,
                        tile_width as u32,
                        rows as u32,
                        pixels,
                    )
                    .map_err(|error| error.errno().unwrap_or(EIO))?;
                } else {
                    self.transfer_buffer.resize(byte_len, 0);
                    for row in 0..rows {
                        let source_start = source
                            .checked_add(row.checked_mul(source_row).ok_or(ERANGE)?)
                            .ok_or(ERANGE)?;
                        let source_end = source_start.checked_add(tile_bytes).ok_or(ERANGE)?;
                        let destination = row.checked_mul(tile_bytes).ok_or(ERANGE)?;
                        self.transfer_buffer[destination..destination + tile_bytes]
                            .copy_from_slice(
                                frame.pixels.get(source_start..source_end).ok_or(ERANGE)?,
                            );
                    }
                    platform::memory::present_framebuffer(
                        x as u32,
                        y as u32,
                        tile_width as u32,
                        rows as u32,
                        &self.transfer_buffer,
                    )
                    .map_err(|error| error.errno().unwrap_or(EIO))?;
                }
                y += rows;
            }
            x += tile_width;
        }
        Ok(())
    }
}

impl Drop for FramebufferBackend {
    fn drop(&mut self) {
        if self.mapped_size != 0 {
            let _ = platform::memory::munmap(FB_VIRT, self.mapped_size);
        }
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
