use mochi_user_platform as platform;

use crate::cursor::CursorImage;
use crate::display::{
    DISPLAY_PRESENT_REQ, DISPLAY_REP_BUF, display_present_gpu_panel, display_present_gpu_scene,
};
use crate::fps_overlay;
use crate::frame_buffer::FrameBuffer;
use crate::geometry::{Rect, choose_frame_size, clip_present_rect};
use crate::gpu_compositor::GpuCompositor;
use crate::protocol::{
    OP_DISPLAY_PRESENT, OP_DISPLAY_PRESENT_RECT, PIXEL_FORMAT_ARGB8888_PREMULTIPLIED,
    PIXEL_FORMAT_XRGB8888, errno_status, put_u32, read_u32,
};
use crate::state::{MAX_SHARED_PAGES, MAX_SURFACES, MAX_WINDOWS, PAGE_SIZE};
use crate::surface::{Surface, read_current_pixel, shared_page_count, surface_has_current_pixels};
use crate::window::{
    ACTIVE_WINDOW_BORDER_ALPHA, WINDOW_CORNER_RADIUS, Window, WindowId,
    content_surface_index_for_window, window_frame_rect, window_index_by_id,
};

#[derive(Default)]
pub(crate) struct PresentFrame {
    buffer: Option<FrameBuffer>,
    cpu_contents_valid: bool,
    gpu_contents_valid: bool,
    gpu_panel_disabled: bool,
    gpu_compositor: GpuCompositor,
    metrics: RendererMetrics,
    last_present_ms: u32,
}

#[derive(Default)]
struct RendererMetrics {
    next_report_tick: u64,
    frames: u64,
    gpu_frames: u64,
    cpu_frames: u64,
    composition_millis: u64,
    present_millis: u64,
    scene_bytes: u64,
}

impl PresentFrame {
    fn pixels(&mut self, pixel_count: usize, byte_count: usize) -> Result<&mut [u32], u32> {
        let page_count = shared_page_count(byte_count)
            .ok_or_else(|| errno_status(crate::protocol::SIZE_LIMIT))?;
        if page_count == 0 || page_count > MAX_SHARED_PAGES {
            return Err(errno_status(crate::protocol::SIZE_LIMIT));
        }
        let capacity = page_count
            .checked_mul(PAGE_SIZE)
            .ok_or_else(|| errno_status(crate::protocol::SIZE_LIMIT))?;
        if self
            .buffer
            .as_ref()
            .is_none_or(|buffer| buffer.capacity() < capacity as u64)
        {
            let buffer = FrameBuffer::new(capacity as u64).map_err(errno_from_platform)?;
            self.buffer = Some(buffer);
            self.cpu_contents_valid = false;
            self.gpu_contents_valid = false;
        }
        let buffer = self
            .buffer
            .as_ref()
            .ok_or_else(|| errno_status(mochi_user_syscall::EIO))?;
        if buffer.capacity() / 4 < pixel_count as u64 {
            return Err(errno_status(crate::protocol::SIZE_LIMIT));
        }
        // SAFETY: this process is the sole writer, the retained mapping covers
        // the checked slice, and attached display handles are read-only.
        Ok(unsafe { core::slice::from_raw_parts_mut(buffer.address() as *mut u32, pixel_count) })
    }

    fn offer(&mut self, display_tid: u64) -> Result<(), platform::syscall::SysError> {
        self.buffer
            .as_mut()
            .ok_or_else(|| platform::syscall::SysError::from_raw(mochi_user_syscall::EIO as i64))?
            .offer(display_tid)
    }

    fn bytes(&mut self, byte_count: usize) -> Result<&mut [u8], u32> {
        let pixel_count = byte_count
            .checked_add(3)
            .map(|bytes| bytes / 4)
            .ok_or_else(|| errno_status(crate::protocol::SIZE_LIMIT))?;
        let pixels = self.pixels(pixel_count, byte_count)?;
        Ok(unsafe {
            core::slice::from_raw_parts_mut(pixels.as_mut_ptr().cast::<u8>(), pixel_count * 4)
        })
    }

    fn record_metrics(
        &mut self,
        gpu: bool,
        composition_millis: u64,
        present_millis: u64,
        scene_bytes: usize,
    ) {
        self.metrics.frames = self.metrics.frames.saturating_add(1);
        if gpu {
            self.metrics.gpu_frames = self.metrics.gpu_frames.saturating_add(1);
        } else {
            self.metrics.cpu_frames = self.metrics.cpu_frames.saturating_add(1);
        }
        self.metrics.composition_millis = self
            .metrics
            .composition_millis
            .saturating_add(composition_millis);
        self.metrics.present_millis = self.metrics.present_millis.saturating_add(present_millis);
        self.metrics.scene_bytes = self.metrics.scene_bytes.saturating_add(scene_bytes as u64);
        let now = platform::time::ticks().unwrap_or(0);
        if self.metrics.next_report_tick == 0 {
            self.metrics.next_report_tick = now.saturating_add(500);
        } else if now >= self.metrics.next_report_tick {
            self.metrics = RendererMetrics {
                next_report_tick: now.saturating_add(500),
                ..RendererMetrics::default()
            };
        }
    }
}

fn perf_counter() -> u64 {
    platform::time::monotonic_milliseconds().unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn try_gpu_scene_present(
    surfaces: &[Surface],
    windows: &[Window],
    present_frame: &mut PresentFrame,
    display_tid: u64,
    display_width: u32,
    display_height: u32,
    cursor_x: i32,
    cursor_y: i32,
    cursor_visible: bool,
    cursor_image: &CursorImage,
    fps: Option<u32>,
    damage: Option<Rect>,
) -> Option<u32> {
    if present_frame.gpu_panel_disabled {
        return None;
    }
    let force_atlas_upload = !present_frame.gpu_contents_valid;
    if !force_atlas_upload
        && damage.is_some()
        && clip_present_rect(damage, display_width as usize, display_height as usize).is_none()
    {
        return Some(0);
    }
    let mut gpu_compositor = core::mem::take(&mut present_frame.gpu_compositor);
    if force_atlas_upload {
        gpu_compositor.invalidate_textures();
    }
    let composition_start = perf_counter();
    let copy_result = (|| {
        let scene = gpu_compositor.compose(
            surfaces,
            windows,
            display_width,
            display_height,
            cursor_x,
            cursor_y,
            cursor_visible,
            cursor_image,
            fps,
            if force_atlas_upload { None } else { damage },
        )?;
        let byte_len = scene.len();
        let destination = present_frame.bytes(byte_len).ok()?;
        destination[..byte_len].copy_from_slice(scene);
        Some(byte_len)
    })();
    present_frame.gpu_compositor = gpu_compositor;
    let Some(byte_len) = copy_result else {
        present_frame.gpu_contents_valid = false;
        return None;
    };
    let composition_millis = perf_counter().saturating_sub(composition_start);
    let timing = mochios_viewkit_gpu_protocol::compositor::FrameTiming {
        compose_ms: composition_millis.min(u32::MAX as u64) as u32,
        ipc_ms: present_frame.last_present_ms,
        control_ms: 0,
    };
    if present_frame
        .bytes(byte_len)
        .ok()
        .and_then(|bytes| {
            mochios_viewkit_gpu_protocol::compositor::set_frame_timing(bytes, timing).ok()
        })
        .is_none()
    {
        present_frame.gpu_contents_valid = false;
        return None;
    }
    let present_start = perf_counter();
    if present_frame.offer(display_tid).is_err() {
        present_frame.gpu_contents_valid = false;
        return None;
    }
    let status = display_present_gpu_scene(display_tid, byte_len);
    let present_millis = perf_counter().saturating_sub(present_start);
    present_frame.last_present_ms = present_millis.min(u32::MAX as u64) as u32;
    if status == 0 {
        present_frame.gpu_contents_valid = true;
        present_frame.cpu_contents_valid = false;
        present_frame.record_metrics(true, composition_millis, present_millis, byte_len);
        Some(0)
    } else {
        present_frame.gpu_contents_valid = false;
        Some(status)
    }
}

fn try_gpu_panel_present(
    surfaces: &[Surface],
    present_frame: &mut PresentFrame,
    display_tid: u64,
    display_width: u32,
    display_height: u32,
    damage: Option<Rect>,
) -> Option<u32> {
    if present_frame.gpu_panel_disabled {
        return None;
    }
    let mut candidate = None;
    for (index, surface) in surfaces.iter().enumerate() {
        if !surface.live || !surface.visible || !surface_has_current_pixels(surface) {
            continue;
        }
        let eligible = surface.role == crate::surface::SurfaceRole::Panel
            && surface.x == 0
            && surface.y == 0
            && surface.current_width == display_width
            && surface.current_height == display_height
            && surface.current_stride == display_width
            && surface.current_format == PIXEL_FORMAT_ARGB8888_PREMULTIPLIED;
        if !eligible || candidate.replace(index).is_some() {
            return None;
        }
    }
    let surface = &surfaces[candidate?];
    let pixel_count = (display_width as usize).checked_mul(display_height as usize)?;
    let byte_count = pixel_count.checked_mul(4)?;
    if surface.current.len() < pixel_count {
        return None;
    }
    let full = Rect::full(display_width, display_height);
    let present_rect = if present_frame.gpu_contents_valid {
        match clip_present_rect(damage, display_width as usize, display_height as usize) {
            Some(rect) => rect,
            None => return Some(0),
        }
    } else {
        full
    };
    {
        let frame = match present_frame.pixels(pixel_count, byte_count) {
            Ok(frame) => frame,
            Err(status) => return Some(status),
        };
        let left = present_rect.x.max(0) as usize;
        let top = present_rect.y.max(0) as usize;
        let right = left
            .saturating_add(present_rect.width as usize)
            .min(display_width as usize);
        let bottom = top
            .saturating_add(present_rect.height as usize)
            .min(display_height as usize);
        for y in top..bottom {
            let row = y.saturating_mul(display_width as usize);
            frame[row + left..row + right]
                .copy_from_slice(&surface.current[row + left..row + right]);
        }
    }
    if present_frame.offer(display_tid).is_err() {
        present_frame.gpu_panel_disabled = true;
        return None;
    }
    let status = display_present_gpu_panel(
        display_tid,
        display_width,
        display_height,
        present_rect,
        0xffc8_c8c8,
    );
    if status == 0 {
        present_frame.gpu_contents_valid = true;
        present_frame.cpu_contents_valid = false;
        Some(0)
    } else {
        present_frame.gpu_panel_disabled = true;
        present_frame.gpu_contents_valid = false;
        None
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
    keyboard_focus: Option<usize>,
    present_frame: &mut PresentFrame,
    display_tid: u64,
    display_width: u32,
    display_height: u32,
    _display_stride: u32,
    display_format: u32,
    renderer_caps: u32,
    cursor_x: i32,
    cursor_y: i32,
    cursor_visible: bool,
    cursor_image: &CursorImage,
    fps: Option<u32>,
    damage: Option<Rect>,
) -> u32 {
    if display_format != PIXEL_FORMAT_XRGB8888 {
        return errno_status(mochi_user_syscall::NativeError::Unsupported.into_raw());
    }
    if renderer_caps & crate::protocol::RENDERER_CAP_GPU_SCENE != 0 {
        return try_gpu_scene_present(
            surfaces,
            windows,
            present_frame,
            display_tid,
            display_width,
            display_height,
            cursor_x,
            cursor_y,
            cursor_visible,
            cursor_image,
            fps,
            damage,
        )
        .unwrap_or_else(|| errno_status(mochi_user_syscall::EIO));
    }
    if fps.is_none() {
        if let Some(status) = try_gpu_panel_present(
            surfaces,
            present_frame,
            display_tid,
            display_width,
            display_height,
            damage,
        ) {
            return status;
        }
    }
    let Some((frame_w, frame_h)) = choose_frame_size(display_width, display_height) else {
        return errno_status(crate::protocol::SIZE_LIMIT);
    };
    let Some(frame_pixels) = frame_w.checked_mul(frame_h) else {
        return errno_status(crate::protocol::SIZE_LIMIT);
    };
    let Some(frame_bytes) = frame_pixels.checked_mul(4) else {
        return errno_status(crate::protocol::SIZE_LIMIT);
    };
    // A newly allocated shared frame has no preserved pixels outside the damage
    // rectangle. Rebuild the complete image before its first transfer, and also
    // after a failed present marks the display mapping for re-establishment.
    let effective_damage = if present_frame.cpu_contents_valid {
        damage
    } else {
        None
    };
    let Some(present_rect) = clip_present_rect(effective_damage, frame_w, frame_h) else {
        return 0;
    };
    let rect_left = present_rect.x as usize;
    let rect_top = present_rect.y as usize;
    let rect_right = rect_left.saturating_add(present_rect.width as usize);
    let rect_bottom = rect_top.saturating_add(present_rect.height as usize);
    let composition_start = perf_counter();
    {
        let frame = match present_frame.pixels(frame_pixels, frame_bytes) {
            Ok(frame) => frame,
            Err(status) => return status,
        };
        for y in rect_top..rect_bottom {
            let Some(row) = y.checked_mul(frame_w) else {
                return errno_status(crate::protocol::SIZE_LIMIT);
            };
            for x in rect_left..rect_right {
                let shade = 0x00c8_c8c8u32;
                let Some(pixel) = frame.get_mut(row + x) else {
                    return errno_status(crate::protocol::SIZE_LIMIT);
                };
                *pixel = 0xff00_0000 | shade;
            }
        }
        let active_window = keyboard_focus
            .and_then(|index| surfaces.get(index))
            .filter(|surface| surface.live)
            .map(|surface| surface.window)
            .filter(|window| *window != WindowId(0));
        let mut drawn = [false; MAX_SURFACES];
        let mut shadow_drawn = [false; MAX_WINDOWS];
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
            let window_style =
                window_index_by_id(windows, surface.window).and_then(|window_index| {
                    let window = &windows[window_index];
                    let content_index = content_surface_index_for_window(surfaces, window)?;
                    (window.decoration.is_some() && surfaces[content_index].visible).then_some((
                        window_index,
                        window_frame_rect(&surfaces[content_index], window),
                        active_window == Some(window.id),
                        window.corner_radius(),
                    ))
                });
            if let Some((window_index, frame_rect, active, radius)) = window_style
                && radius != 0
                && !shadow_drawn[window_index]
            {
                draw_window_shadow(frame, frame_w, frame_h, present_rect, frame_rect, active);
                shadow_drawn[window_index] = true;
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
                        return errno_status(crate::protocol::SIZE_LIMIT);
                    };
                    let Some(pixel) = read_current_pixel(surface, sx, sy) else {
                        continue;
                    };
                    let coverage = window_style.map_or(255, |(_, frame, _, radius)| {
                        rounded_rect_coverage(frame, radius, dx as i32, dy as i32)
                    });
                    if coverage == 0 {
                        continue;
                    }
                    let Some(slot) = frame.get_mut(dst) else {
                        return errno_status(crate::protocol::SIZE_LIMIT);
                    };
                    *slot = blend_surface_pixel(*slot, pixel, surface.current_format, coverage);
                    if let Some((_, window_frame, true, radius)) = window_style {
                        let inner = inset_rect(window_frame, 1);
                        let inner_coverage = rounded_rect_coverage(
                            inner,
                            radius.saturating_sub(1),
                            dx as i32,
                            dy as i32,
                        );
                        let border_coverage = coverage.saturating_sub(inner_coverage);
                        if border_coverage != 0 {
                            let alpha = ((u32::from(ACTIVE_WINDOW_BORDER_ALPHA)
                                * u32::from(border_coverage)
                                + 127)
                                / 255) as u8;
                            *slot = blend_black_over_xrgb(*slot, alpha);
                        }
                    }
                }
            }
        }
        if let Some(fps) = fps {
            fps_overlay::draw(fps, |rect, color| {
                let left = rect.x.max(present_rect.x) as usize;
                let top = rect.y.max(present_rect.y) as usize;
                let right = (rect.x + rect.width as i32)
                    .min(present_rect.x + present_rect.width as i32)
                    as usize;
                let bottom = (rect.y + rect.height as i32)
                    .min(present_rect.y + present_rect.height as i32)
                    as usize;
                for y in top..bottom {
                    for x in left..right {
                        frame[y * frame_w + x] = color;
                    }
                }
            });
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
                        return errno_status(crate::protocol::SIZE_LIMIT);
                    };
                    let Some(slot) = frame.get_mut(dst) else {
                        return errno_status(crate::protocol::SIZE_LIMIT);
                    };
                    *slot = blend_premultiplied_argb_over_xrgb(*slot, pixel);
                }
            }
        }
    }
    let composition_millis = perf_counter().saturating_sub(composition_start);
    let present_start = perf_counter();
    if let Err(err) = present_frame.offer(display_tid) {
        return errno_from_platform(err);
    }
    let request = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(DISPLAY_PRESENT_REQ).cast::<u8>(),
            36,
        )
    };
    request.fill(0);
    let partial_present = effective_damage.is_some()
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
        if let Some(buffer) = present_frame.buffer.as_mut() {
            buffer.invalidate_offer();
        }
        present_frame.cpu_contents_valid = false;
        return status;
    }
    present_frame.cpu_contents_valid = true;
    present_frame.gpu_contents_valid = false;
    present_frame.record_metrics(
        false,
        composition_millis,
        perf_counter().saturating_sub(present_start),
        frame_bytes,
    );
    0
}

type WindowShadow = crate::window_elevation::Layer;
const INACTIVE_WINDOW_SHADOW: [WindowShadow; 1] = crate::window_elevation::INACTIVE;
const ACTIVE_WINDOW_SHADOW: [WindowShadow; 2] = crate::window_elevation::ACTIVE;

fn draw_window_shadow(
    frame: &mut [u32],
    frame_width: usize,
    frame_height: usize,
    damage: Rect,
    window_frame: Rect,
    active: bool,
) {
    let layers: &[WindowShadow] = if active {
        &ACTIVE_WINDOW_SHADOW
    } else {
        &INACTIVE_WINDOW_SHADOW
    };
    for shadow in layers.iter().rev() {
        draw_shadow(
            frame,
            frame_width,
            frame_height,
            damage,
            window_frame,
            *shadow,
        );
    }
}

fn draw_shadow(
    frame: &mut [u32],
    frame_width: usize,
    frame_height: usize,
    damage: Rect,
    window_frame: Rect,
    shadow: WindowShadow,
) {
    let layer_count = shadow.blur_radius.max(2).min(u32::from(shadow.alpha));
    let weight_sum = (1..=layer_count)
        .map(|layer| {
            layer_count
                .saturating_mul(4)
                .saturating_sub(layer.saturating_mul(3))
        })
        .sum::<u32>();
    let mut remaining_alpha = u32::from(shadow.alpha);
    for layer in (1..=layer_count).rev() {
        let expansion = shadow.spread.saturating_add(
            shadow
                .blur_radius
                .saturating_mul(layer)
                .saturating_add(layer_count - 1)
                / layer_count,
        );
        let weight = layer_count
            .saturating_mul(4)
            .saturating_sub(layer.saturating_mul(3));
        let mut alpha = u32::from(shadow.alpha)
            .saturating_mul(weight)
            .saturating_add(weight_sum / 2)
            / weight_sum;
        alpha = alpha.min(remaining_alpha);
        if layer == 1 {
            alpha = remaining_alpha;
        }
        remaining_alpha = remaining_alpha.saturating_sub(alpha);
        if alpha == 0 {
            continue;
        }
        let mut shadow_rect = window_frame.expanded(expansion);
        shadow_rect.y = shadow_rect.y.saturating_add(shadow.offset_y);
        fill_rounded_black(
            frame,
            frame_width,
            frame_height,
            damage,
            shadow_rect,
            WINDOW_CORNER_RADIUS.saturating_add(expansion),
            alpha as u8,
            window_frame,
            WINDOW_CORNER_RADIUS,
        );
    }
}

fn fill_rounded_black(
    frame: &mut [u32],
    frame_width: usize,
    frame_height: usize,
    damage: Rect,
    rect: Rect,
    radius: u32,
    alpha: u8,
    occluder: Rect,
    occluder_radius: u32,
) {
    let left = rect.x.max(damage.x).max(0) as usize;
    let top = rect.y.max(damage.y).max(0) as usize;
    let right = (i64::from(rect.x) + i64::from(rect.width))
        .min(i64::from(damage.x) + i64::from(damage.width))
        .min(frame_width as i64)
        .max(0) as usize;
    let bottom = (i64::from(rect.y) + i64::from(rect.height))
        .min(i64::from(damage.y) + i64::from(damage.height))
        .min(frame_height as i64)
        .max(0) as usize;
    let occluder_left = occluder.x.max(0) as usize;
    let occluder_top = occluder.y.max(0) as usize;
    let occluder_right = (i64::from(occluder.x) + i64::from(occluder.width))
        .min(frame_width as i64)
        .max(0) as usize;
    let occluder_bottom = (i64::from(occluder.y) + i64::from(occluder.height))
        .min(frame_height as i64)
        .max(0) as usize;
    let occluder_radius = occluder_radius
        .min(occluder.width / 2)
        .min(occluder.height / 2) as usize;
    for y in top..bottom {
        if y < occluder_top || y >= occluder_bottom {
            fill_shadow_range(frame, frame_width, rect, radius, alpha, y, left, right);
            continue;
        }
        let in_corner_row = y < occluder_top.saturating_add(occluder_radius)
            || y >= occluder_bottom.saturating_sub(occluder_radius);
        let left_end = if in_corner_row {
            occluder_left.saturating_add(occluder_radius)
        } else {
            occluder_left
        };
        let right_start = if in_corner_row {
            occluder_right.saturating_sub(occluder_radius)
        } else {
            occluder_right
        };
        fill_shadow_range(
            frame,
            frame_width,
            rect,
            radius,
            alpha,
            y,
            left,
            right.min(left_end),
        );
        fill_shadow_range(
            frame,
            frame_width,
            rect,
            radius,
            alpha,
            y,
            left.max(right_start),
            right,
        );
    }
}

fn fill_shadow_range(
    frame: &mut [u32],
    frame_width: usize,
    rect: Rect,
    radius: u32,
    alpha: u8,
    y: usize,
    left: usize,
    right: usize,
) {
    for x in left..right {
        let coverage = rounded_rect_coverage(rect, radius, x as i32, y as i32);
        if coverage == 0 {
            continue;
        }
        let effective_alpha = ((u32::from(alpha) * u32::from(coverage) + 127) / 255) as u8;
        if let Some(pixel) = frame.get_mut(y * frame_width + x) {
            *pixel = blend_black_over_xrgb(*pixel, effective_alpha);
        }
    }
}

fn inset_rect(rect: Rect, amount: u32) -> Rect {
    let offset = amount.min(i32::MAX as u32) as i32;
    Rect {
        x: rect.x.saturating_add(offset),
        y: rect.y.saturating_add(offset),
        width: rect.width.saturating_sub(amount.saturating_mul(2)),
        height: rect.height.saturating_sub(amount.saturating_mul(2)),
    }
}

fn rounded_rect_coverage(rect: Rect, radius: u32, x: i32, y: i32) -> u8 {
    if rect.width == 0 || rect.height == 0 {
        return 0;
    }
    let right = i64::from(rect.x) + i64::from(rect.width);
    let bottom = i64::from(rect.y) + i64::from(rect.height);
    if i64::from(x) < i64::from(rect.x)
        || i64::from(y) < i64::from(rect.y)
        || i64::from(x) >= right
        || i64::from(y) >= bottom
    {
        return 0;
    }
    let radius = (radius as f32).min(rect.width.min(rect.height) as f32 * 0.5);
    if radius == 0.0 {
        return 255;
    }
    if (x as f32 >= rect.x as f32 + radius && x as f32 + 1.0 <= right as f32 - radius)
        || (y as f32 >= rect.y as f32 + radius && y as f32 + 1.0 <= bottom as f32 - radius)
    {
        return 255;
    }
    let shape = mochios_viewkit_gpu_protocol::continuous_corner::RoundedRect::uniform(
        [
            rect.x as f32,
            rect.y as f32,
            rect.width as f32,
            rect.height as f32,
        ],
        radius,
    );
    let mut inside = 0u32;
    for sy in [0.125, 0.375, 0.625, 0.875] {
        for sx in [0.125, 0.375, 0.625, 0.875] {
            if shape.contains((x as f32 + sx, y as f32 + sy)) {
                inside += 1;
            }
        }
    }

    ((inside * 255 + 8) / 16) as u8
}

fn blend_surface_pixel(dst: u32, src: u32, format: u32, coverage: u8) -> u32 {
    if coverage == 255 {
        return if format == PIXEL_FORMAT_ARGB8888_PREMULTIPLIED {
            blend_premultiplied_argb_over_xrgb(dst, src)
        } else {
            0xff00_0000 | (src & 0x00ff_ffff)
        };
    }
    let coverage = u32::from(coverage);
    let premultiplied = if format == PIXEL_FORMAT_ARGB8888_PREMULTIPLIED {
        let alpha = ((src >> 24) & 0xff) * coverage / 255;
        let red = ((src >> 16) & 0xff) * coverage / 255;
        let green = ((src >> 8) & 0xff) * coverage / 255;
        let blue = (src & 0xff) * coverage / 255;
        (alpha << 24) | (red << 16) | (green << 8) | blue
    } else {
        let red = ((src >> 16) & 0xff) * coverage / 255;
        let green = ((src >> 8) & 0xff) * coverage / 255;
        let blue = (src & 0xff) * coverage / 255;
        (coverage << 24) | (red << 16) | (green << 8) | blue
    };
    blend_premultiplied_argb_over_xrgb(dst, premultiplied)
}

fn blend_black_over_xrgb(dst: u32, alpha: u8) -> u32 {
    if alpha == 0 {
        return dst;
    }
    let inverse = 255 - u32::from(alpha);
    let red = ((dst >> 16) & 0xff) * inverse / 255;
    let green = ((dst >> 8) & 0xff) * inverse / 255;
    let blue = (dst & 0xff) * inverse / 255;
    0xff00_0000 | (red << 16) | (green << 8) | blue
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

#[cfg(test)]
mod continuous_corner_tests {
    use super::*;

    #[test]
    fn shared_window_elevation_stays_within_existing_damage_bounds() {
        let margin=crate::window::WINDOW_SHADOW_MARGIN;
        for layer in ACTIVE_WINDOW_SHADOW.iter().chain(INACTIVE_WINDOW_SHADOW.iter()) {
            assert!(layer.blur_radius + layer.spread + layer.offset_y.unsigned_abs() <= margin);
        }
        assert!(ACTIVE_WINDOW_SHADOW.iter().map(|layer| u32::from(layer.alpha)).sum::<u32>()
            > INACTIVE_WINDOW_SHADOW.iter().map(|layer| u32::from(layer.alpha)).sum::<u32>());
    }
    #[test]
    fn maximized_cpu_surface_coverage_fills_the_corner_pixel() {
        let mut window = Window::empty();
        let rect = Rect {
            x: 0,
            y: 0,
            width: 640,
            height: 480,
        };
        assert_eq!(rounded_rect_coverage(rect, window.corner_radius(), 0, 0), 0);
        window.state = crate::protocol::WINDOW_STATE_MAXIMIZED;
        assert_eq!(
            rounded_rect_coverage(rect, window.corner_radius(), 0, 0),
            255
        );
        window.state = crate::protocol::WINDOW_STATE_NORMAL;
        assert_eq!(rounded_rect_coverage(rect, window.corner_radius(), 0, 0), 0);
    }
    #[test]
    fn shadow_and_surface_coverage_use_shared_reference() {
        for (w, h, r) in [
            (1, 1, 0),
            (1, 1, 999),
            (31, 21, 999),
            (17, 70, 999),
            (31, 20, 10),
            (100, 50, 1),
            (75, 40, 17),
        ] {
            let rect = Rect {
                x: 3,
                y: 5,
                width: w,
                height: h,
            };
            let shape = mochios_viewkit_gpu_protocol::continuous_corner::RoundedRect::uniform(
                [3.0, 5.0, w as f32, h as f32],
                r as f32,
            );
            for y in 4..(6 + h as i32) {
                for x in 2..(4 + w as i32) {
                    let mut count = 0;
                    for sy in [0.125, 0.375, 0.625, 0.875] {
                        for sx in [0.125, 0.375, 0.625, 0.875] {
                            if shape.contains((x as f32 + sx, y as f32 + sy)) {
                                count += 1;
                            }
                        }
                    }
                    assert_eq!(
                        rounded_rect_coverage(rect, r, x, y),
                        ((count * 255 + 8) / 16) as u8
                    );
                }
            }
        }
    }
}
