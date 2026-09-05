use mochi_user_platform as platform;

use crate::cursor::CursorImage;
use crate::display::display_present_gpu_scene;
use crate::geometry::Rect;
use crate::gpu_compositor::GpuCompositor;
use crate::protocol::{PIXEL_FORMAT_XRGB8888, errno_status};
use crate::state::{MAX_SHARED_PAGES, PAGE_SIZE};
use crate::surface::Surface;
use crate::window::Window;

#[derive(Default)]
pub(crate) struct PresentFrame {
    virt: u64,
    page_count: usize,
    byte_capacity: usize,
    sent_to_display: bool,
    gpu_contents_valid: bool,
    gpu_compositor: GpuCompositor,
    metrics: RendererMetrics,
}

#[derive(Default)]
struct RendererMetrics {
    next_report_tick: u64,
    frames: u64,
    composition_millis: u64,
    present_millis: u64,
    scene_bytes: u64,
}

impl PresentFrame {
    fn bytes(&mut self, byte_count: usize) -> Result<&mut [u8], u32> {
        let page_count = byte_count
            .checked_add(PAGE_SIZE - 1)
            .map(|bytes| bytes / PAGE_SIZE)
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
            self.byte_capacity = page_count
                .checked_mul(PAGE_SIZE)
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
            self.sent_to_display = false;
            self.gpu_contents_valid = false;
        }
        if self.byte_capacity < byte_count {
            return Err(errno_status(mochi_user_syscall::ERANGE));
        }
        Ok(unsafe { core::slice::from_raw_parts_mut(self.virt as *mut u8, byte_count) })
    }

    fn record_metrics(&mut self, composition_millis: u64, present_millis: u64, scene_bytes: usize) {
        self.metrics.frames = self.metrics.frames.saturating_add(1);
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

fn gpu_damage(contents_valid: bool, damage: Option<Rect>) -> Option<Rect> {
    contents_valid.then_some(damage).flatten()
}

#[allow(clippy::too_many_arguments)]
fn try_gpu_scene_present(
    surfaces: &[Surface],
    windows: &[Window],
    present_frame: &mut PresentFrame,
    display_tid: u64,
    display_width: u32,
    display_height: u32,
    damage: Option<Rect>,
    cursor_x: i32,
    cursor_y: i32,
    cursor_visible: bool,
    cursor_image: &CursorImage,
) -> Option<u32> {
    let contents_valid = present_frame.gpu_contents_valid;
    let force_atlas_upload = !contents_valid;
    let damage = gpu_damage(contents_valid, damage);
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
            damage,
            cursor_x,
            cursor_y,
            cursor_visible,
            cursor_image,
        )?;
        let byte_len = scene.len();
        let destination = present_frame.bytes(byte_len).ok()?;
        destination.copy_from_slice(scene);
        Some(byte_len)
    })();
    present_frame.gpu_compositor = gpu_compositor;
    let byte_len = copy_result?;
    let composition_millis = perf_counter().saturating_sub(composition_start);
    let present_start = perf_counter();
    if !present_frame.sent_to_display {
        if platform::ipc::send_page_count(display_tid, present_frame.page_count, present_frame.virt)
            .is_err()
        {
            present_frame.gpu_contents_valid = false;
            return None;
        }
        present_frame.sent_to_display = true;
    }
    let status = display_present_gpu_scene(display_tid, byte_len);
    let present_millis = perf_counter().saturating_sub(present_start);
    if status != 0 {
        present_frame.gpu_contents_valid = false;
        return None;
    }
    present_frame.gpu_contents_valid = true;
    present_frame.record_metrics(composition_millis, present_millis, byte_len);
    Some(0)
}

fn errno_from_platform(err: mochi_user_syscall::SysError) -> u32 {
    errno_status(err.errno().unwrap_or(mochi_user_syscall::EIO))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn composite_and_present(
    surfaces: &[Surface],
    windows: &[Window],
    _keyboard_focus: Option<usize>,
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
    damage: Option<Rect>,
) -> u32 {
    if display_format != PIXEL_FORMAT_XRGB8888
        || renderer_caps & crate::protocol::RENDERER_CAP_GPU_SCENE == 0
    {
        return errno_status(mochi_user_syscall::ENOTSUP);
    }
    try_gpu_scene_present(
        surfaces,
        windows,
        present_frame,
        display_tid,
        display_width,
        display_height,
        damage,
        cursor_x,
        cursor_y,
        cursor_visible,
        cursor_image,
    )
    .unwrap_or_else(|| errno_status(mochi_user_syscall::EIO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compositor_refuses_to_fall_back_when_gpu_scene_is_unavailable() {
        let mut present = PresentFrame::default();
        let cursor = CursorImage::default();
        assert_eq!(
            composite_and_present(
                &[],
                &[],
                None,
                &mut present,
                0,
                640,
                480,
                640,
                PIXEL_FORMAT_XRGB8888,
                0,
                0,
                0,
                false,
                &cursor,
                None,
            ),
            errno_status(mochi_user_syscall::ENOTSUP)
        );
    }

    #[test]
    fn invalid_gpu_contents_force_a_full_frame() {
        let damage = Rect::new(10, 20, 30, 40);
        assert_eq!(gpu_damage(false, Some(damage)), None);
        assert_eq!(gpu_damage(true, Some(damage)), Some(damage));
    }
}
