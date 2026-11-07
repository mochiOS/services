use bootui::{Image, LoadingScreen, PixelFormat, Surface as Canvas};

use crate::geometry::Rect;
use crate::protocol::{PIXEL_FORMAT_XRGB8888, errno_status};
use crate::surface::{Surface, SurfaceHandle, SurfaceRole};

include!(concat!(env!("OUT_DIR"), "/boot_logo.rs"));

/// Compositor-owned content until the first client has committed a frame.
/// It is never registered as a client surface or an input target.
pub(crate) struct BootScene {
    surface: Surface,
    phase: u8,
}

impl BootScene {
    pub(crate) fn new(width: u32, height: u32, now: u64) -> Result<Self, u32> {
        let count = (width as usize)
            .checked_mul(height as usize)
            .filter(|count| *count != 0 && *count <= crate::state::MAX_SHARED_PIXELS)
            .ok_or_else(|| errno_status(crate::protocol::SIZE_LIMIT))?;
        let mut surface = Surface::empty();
        surface
            .current
            .try_reserve_exact(count)
            .map_err(|_| errno_status(mochi_user_syscall::ENOMEM))?;
        surface.current.resize(count, 0);
        surface.live = true;
        surface.visible = true;
        surface.handle = SurfaceHandle(u64::MAX);
        surface.token = surface.handle.0;
        surface.role = SurfaceRole::Panel;
        surface.width = width;
        surface.height = height;
        surface.current_width = width;
        surface.current_height = height;
        surface.current_stride = width;
        surface.current_format = PIXEL_FORMAT_XRGB8888;
        surface.content_generation = 1;
        let mut scene = Self {
            surface,
            phase: LoadingScreen::phase_at(now),
        };
        let logo = Image::new(
            BOOT_LOGO_RGBA,
            BOOT_LOGO_WIDTH,
            BOOT_LOGO_HEIGHT,
            BOOT_LOGO_WIDTH as usize * 4,
        )
        .map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
        scene.paint(|canvas| LoadingScreen::new(logo).paint(canvas, now))?;
        Ok(scene)
    }

    pub(crate) fn surface(&self) -> &Surface {
        &self.surface
    }

    pub(crate) fn has_client_frame(surfaces: &[Surface]) -> bool {
        surfaces.iter().any(|surface| {
            surface.live
                && surface.visible
                && !surface.is_decoration
                && surface.content_generation != 0
        })
    }

    pub(crate) fn tick(&mut self, now: u64) -> Result<Option<Rect>, u32> {
        let phase = LoadingScreen::phase_at(now);
        if phase == self.phase {
            return Ok(None);
        }
        let mut damage = None;
        self.paint(|canvas| {
            LoadingScreen::paint_spinner(canvas, now);
            let rect = LoadingScreen::spinner_bounds(canvas);
            damage = Some(Rect {
                x: rect.origin.x,
                y: rect.origin.y,
                width: rect.size.width,
                height: rect.size.height,
            });
        })?;
        self.surface.content_generation = self.surface.content_generation.wrapping_add(1).max(1);
        self.phase = phase;
        Ok(damage)
    }

    fn paint(&mut self, paint: impl FnOnce(&mut Canvas<'_>)) -> Result<(), u32> {
        // SAFETY: current owns initialized u32 pixels exclusively; this byte
        // view has the same lifetime and covers exactly their allocated bytes.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                self.surface.current.as_mut_ptr().cast::<u8>(),
                self.surface.current.len() * 4,
            )
        };
        let mut canvas = Canvas::new(
            bytes,
            self.surface.width,
            self.surface.height,
            self.surface.current_stride,
            PixelFormat::Bgr,
        )
        .map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
        paint(&mut canvas);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polling_without_a_phase_change_does_not_upload_another_frame() {
        let mut scene = BootScene::new(128, 96, 0).unwrap();
        let generation = scene.surface().content_generation;
        assert!(scene.tick(0).unwrap().is_none());
        assert_eq!(scene.surface().content_generation, generation);
        assert!(scene.tick(250).unwrap().is_some());
        let generation = scene.surface().content_generation;
        assert!(scene.tick(250).unwrap().is_none());
        assert_eq!(scene.surface().content_generation, generation);
    }

    #[test]
    fn loading_finishes_only_after_visible_client_content_is_committed() {
        let mut surface = Surface::empty();
        surface.live = true;
        surface.visible = true;
        assert!(!BootScene::has_client_frame(core::slice::from_ref(
            &surface
        )));
        surface.content_generation = 1;
        surface.is_decoration = true;
        assert!(!BootScene::has_client_frame(core::slice::from_ref(
            &surface
        )));
        surface.is_decoration = false;
        assert!(BootScene::has_client_frame(core::slice::from_ref(&surface)));
        surface.visible = false;
        assert!(!BootScene::has_client_frame(core::slice::from_ref(
            &surface
        )));
    }
}
