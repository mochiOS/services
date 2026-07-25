use mochi_user_platform as platform;

use crate::cursor::CursorImage;
use crate::display::{DISPLAY_PRESENT_REQ, DISPLAY_REP_BUF};
use crate::geometry::{Rect, choose_frame_size, clip_present_rect};
use crate::protocol::{
    OP_DISPLAY_PRESENT, OP_DISPLAY_PRESENT_RECT, PIXEL_FORMAT_ARGB8888_PREMULTIPLIED,
    PIXEL_FORMAT_XRGB8888, errno_status, put_u32, read_u32,
};
use crate::state::{MAX_SHARED_PAGES, MAX_SURFACES, PAGE_SIZE};
use crate::surface::{Surface, read_current_pixel, shared_page_count, surface_has_current_pixels};
use crate::window::{Window, point_inside_window_frame};

#[derive(Default)]
pub(crate) struct PresentFrame {
    virt: u64,
    page_count: usize,
    pixel_capacity: usize,
    sent_to_display: bool,
}

impl PresentFrame {
    fn pixels(&mut self, pixel_count: usize, byte_count: usize) -> Result<&mut [u32], u32> {
        let page_count = shared_page_count(byte_count)
            .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        if page_count == 0 || page_count > MAX_SHARED_PAGES {
            return Err(errno_status(mochi_user_syscall::ERANGE));
        }
        if self.virt == 0 || self.page_count < page_count {
            let virt = platform::memory::alloc_shared_page_count(page_count)
                .map_err(errno_from_platform)?;
            if virt == 0 || (virt as usize) & (PAGE_SIZE - 1) != 0 {
                return Err(errno_status(mochi_user_syscall::EIO));
            }
            self.virt = virt;
            self.page_count = page_count;
            self.sent_to_display = false;
            self.pixel_capacity = page_count
                .checked_mul(PAGE_SIZE)
                .and_then(|bytes| bytes.checked_div(4))
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        }
        if self.pixel_capacity < pixel_count {
            return Err(errno_status(mochi_user_syscall::ERANGE));
        }
        Ok(unsafe { core::slice::from_raw_parts_mut(self.virt as *mut u32, pixel_count) })
    }
}

fn errno_from_platform(err: mochi_user_syscall::SysError) -> u32 {
    errno_status(err.errno().unwrap_or(mochi_user_syscall::EIO))
}

#[allow(dead_code)]
fn blend_argb_over_xrgb(dst: u32, src: u32) -> u32 {
    let alpha = (src >> 24) & 0xff;
    if alpha == 0 {
        return dst;
    }
    if alpha == 0xff {
        return 0xff00_0000 | (src & 0x00ff_ffff);
    }
    let inv = 255 - alpha;
    let sr = (src >> 16) & 0xff;
    let sg = (src >> 8) & 0xff;
    let sb = src & 0xff;
    let dr = (dst >> 16) & 0xff;
    let dg = (dst >> 8) & 0xff;
    let db = dst & 0xff;
    let r = (sr * alpha + dr * inv + 127) / 255;
    let g = (sg * alpha + dg * inv + 127) / 255;
    let b = (sb * alpha + db * inv + 127) / 255;
    0xff00_0000 | (r << 16) | (g << 8) | b
}

pub(crate) fn composite_and_present(
    surfaces: &[Surface],
    windows: &[Window],
    present_frame: &mut PresentFrame,
    display_tid: u64,
    display_width: u32,
    display_height: u32,
    _display_stride: u32,
    display_format: u32,
    cursor_x: i32,
    cursor_y: i32,
    cursor_visible: bool,
    cursor_image: &CursorImage,
    damage: Option<Rect>,
) -> u32 {
    if display_format != PIXEL_FORMAT_XRGB8888 {
        return errno_status(mochi_user_syscall::ENOTSUP);
    }
    let Some((frame_w, frame_h)) = choose_frame_size(display_width, display_height) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let Some(frame_pixels) = frame_w.checked_mul(frame_h) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let Some(frame_bytes) = frame_pixels.checked_mul(4) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let Some(present_rect) = clip_present_rect(damage, frame_w, frame_h) else {
        return 0;
    };
    let rect_left = present_rect.x as usize;
    let rect_top = present_rect.y as usize;
    let rect_right = rect_left.saturating_add(present_rect.width as usize);
    let rect_bottom = rect_top.saturating_add(present_rect.height as usize);
    {
        let frame = match present_frame.pixels(frame_pixels, frame_bytes) {
            Ok(frame) => frame,
            Err(status) => return status,
        };
        for y in rect_top..rect_bottom {
            let Some(row) = y.checked_mul(frame_w) else {
                return errno_status(mochi_user_syscall::ERANGE);
            };
            for x in rect_left..rect_right {
                let shade = 0x00c8_c8c8u32;
                let Some(pixel) = frame.get_mut(row + x) else {
                    return errno_status(mochi_user_syscall::ERANGE);
                };
                *pixel = 0xff00_0000 | shade;
            }
        }
        let mut drawn = [false; MAX_SURFACES];
        for _ in 0..surfaces.len() {
            let mut selected: Option<usize> = None;
            for (index, surface) in surfaces.iter().enumerate() {
                if drawn[index] || !surface.live || !surface.visible {
                    continue;
                }
                if selected.is_none_or(|selected_index| {
                    let selected = &surfaces[selected_index];
                    (surface.role.stack_layer(), surface.z)
                        < (selected.role.stack_layer(), selected.z)
                }) {
                    selected = Some(index);
                }
            }
            let Some(index) = selected else {
                break;
            };
            drawn[index] = true;
            let surface = &surfaces[index];
            if !surface_has_current_pixels(surface) {
                continue;
            }
            let surface_left = surface.x.max(0) as i64;
            let surface_top = surface.y.max(0) as i64;
            let surface_right = (surface.x as i64)
                .saturating_add(surface.current_width as i64)
                .min(frame_w as i64)
                .max(0);
            let surface_bottom = (surface.y as i64)
                .saturating_add(surface.current_height as i64)
                .min(frame_h as i64)
                .max(0);
            let copy_left = surface_left.max(rect_left as i64);
            let copy_top = surface_top.max(rect_top as i64);
            let copy_right = surface_right.min(rect_right as i64);
            let copy_bottom = surface_bottom.min(rect_bottom as i64);
            if copy_right <= copy_left || copy_bottom <= copy_top {
                continue;
            }
            for dy in copy_top as usize..copy_bottom as usize {
                let sy = (dy as i64).saturating_sub(surface.y as i64) as usize;
                for dx in copy_left as usize..copy_right as usize {
                    let sx = (dx as i64).saturating_sub(surface.x as i64) as usize;
                    let Some(dst) = (dy as usize)
                        .checked_mul(frame_w)
                        .and_then(|row| row.checked_add(dx as usize))
                    else {
                        return errno_status(mochi_user_syscall::ERANGE);
                    };
                    let Some(pixel) = read_current_pixel(surface, sx, sy) else {
                        continue;
                    };
                    if !point_inside_window_frame(surfaces, windows, surface, dx as i32, dy as i32)
                    {
                        continue;
                    }
                    let Some(slot) = frame.get_mut(dst) else {
                        return errno_status(mochi_user_syscall::ERANGE);
                    };
                    if surface.current_format == PIXEL_FORMAT_ARGB8888_PREMULTIPLIED {
                        *slot = blend_premultiplied_argb_over_xrgb(*slot, pixel);
                    } else {
                        *slot = pixel;
                    }
                }
            }
        }
        if cursor_visible {
            for dy in rect_top..rect_bottom {
                for dx in rect_left..rect_right {
                    let Some(pixel) = cursor_image.pixel(dx as i32, dy as i32, cursor_x, cursor_y)
                    else {
                        continue;
                    };
                    let Some(dst) = dy.checked_mul(frame_w).and_then(|row| row.checked_add(dx))
                    else {
                        return errno_status(mochi_user_syscall::ERANGE);
                    };
                    let Some(slot) = frame.get_mut(dst) else {
                        return errno_status(mochi_user_syscall::ERANGE);
                    };
                    *slot = blend_premultiplied_argb_over_xrgb(*slot, pixel);
                }
            }
        }
    }
    if !present_frame.sent_to_display {
        let page_count = present_frame.page_count;
        let virt = present_frame.virt;
        if let Err(err) = platform::ipc::send_page_count(display_tid, page_count, virt) {
            return errno_from_platform(err);
        }
        present_frame.sent_to_display = true;
    }
    let request = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(DISPLAY_PRESENT_REQ).cast::<u8>(),
            36,
        )
    };
    request.fill(0);
    let partial_present = damage.is_some()
        && (present_rect.x != 0
            || present_rect.y != 0
            || present_rect.width as usize != frame_w
            || present_rect.height as usize != frame_h);
    put_u32(
        request,
        0,
        if partial_present {
            OP_DISPLAY_PRESENT_RECT
        } else {
            OP_DISPLAY_PRESENT
        },
    );
    put_u32(request, 4, frame_w as u32);
    put_u32(request, 8, frame_h as u32);
    put_u32(request, 12, frame_w as u32);
    put_u32(request, 16, PIXEL_FORMAT_XRGB8888);
    let request_len = if partial_present {
        put_u32(request, 20, present_rect.x as u32);
        put_u32(request, 24, present_rect.y as u32);
        put_u32(request, 28, present_rect.width);
        put_u32(request, 32, present_rect.height);
        36
    } else {
        20
    };
    let reply = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REP_BUF).cast::<u8>(), 32)
    };
    reply.fill(0);
    let Ok(msg) = platform::ipc::call(display_tid, &request[..request_len], reply) else {
        return errno_status(mochi_user_syscall::EIO);
    };
    let len = (msg & 0xffff_ffff) as usize;
    if len < 4 {
        return errno_status(mochi_user_syscall::EIO);
    }
    let status = read_u32(reply, 0).unwrap_or(errno_status(mochi_user_syscall::EIO));
    if status != 0 {
        present_frame.sent_to_display = false;
        return status;
    }
    0
}

fn blend_premultiplied_argb_over_xrgb(dst: u32, src: u32) -> u32 {
    let alpha = (src >> 24) & 0xff;
    if alpha == 0xff {
        return 0xff00_0000 | (src & 0x00ff_ffff);
    }
    let inv = 255 - alpha;
    let sr = (src >> 16) & 0xff;
    let sg = (src >> 8) & 0xff;
    let sb = src & 0xff;
    let dr = (dst >> 16) & 0xff;
    let dg = (dst >> 8) & 0xff;
    let db = dst & 0xff;
    let r = sr + (dr * inv + 127) / 255;
    let g = sg + (dg * inv + 127) / 255;
    let b = sb + (db * inv + 127) / 255;
    0xff00_0000 | (r.min(255) << 16) | (g.min(255) << 8) | b.min(255)
}
