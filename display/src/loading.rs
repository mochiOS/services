use alloc::vec::Vec;
use bootui::{Image, LoadingScreen, PixelFormat, Surface};

use crate::backend::DisplayBackend;
use crate::present::{DamageRect, DisplayGeometry, PresentFrame};

include!(concat!(env!("OUT_DIR"), "/boot_logo.rs"));

/// Temporary driver-owned scanout until a client takes presentation ownership.
pub(crate) struct LoadingFrame {
    pixels: Vec<u8>,
    geometry: DisplayGeometry,
    damage: DamageRect,
    phase: u8,
}

impl LoadingFrame {
    pub(crate) fn new(geometry: DisplayGeometry, now: u64) -> Result<Self, u64> {
        let mut pixels = Vec::new();
        let size = geometry.byte_len()?;
        pixels
            .try_reserve_exact(size)
            .map_err(|_| mochi_user_syscall::ENOMEM)?;
        pixels.resize(size, 0);
        let logo = Image::new(
            BOOT_LOGO_RGBA,
            BOOT_LOGO_WIDTH,
            BOOT_LOGO_HEIGHT,
            BOOT_LOGO_WIDTH as usize * 4,
        )
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        let mut canvas = Surface::new(
            &mut pixels,
            geometry.width,
            geometry.height,
            geometry.stride,
            PixelFormat::Bgr,
        )
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        LoadingScreen::new(logo).paint(&mut canvas, now);
        Ok(Self {
            pixels,
            geometry,
            damage: DamageRect::full(geometry),
            phase: LoadingScreen::phase_at(now),
        })
    }

    pub(crate) fn tick(&mut self, now: u64) -> Result<bool, u64> {
        let phase = LoadingScreen::phase_at(now);
        if phase == self.phase {
            return Ok(false);
        }
        let mut canvas = Surface::new(
            &mut self.pixels,
            self.geometry.width,
            self.geometry.height,
            self.geometry.stride,
            PixelFormat::Bgr,
        )
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        LoadingScreen::paint_spinner(&mut canvas, now);
        let area = LoadingScreen::spinner_bounds(&canvas);
        let left = area.origin.x.max(0) as u32;
        let top = area.origin.y.max(0) as u32;
        let right = (i64::from(area.origin.x) + i64::from(area.size.width))
            .max(0)
            .min(i64::from(self.geometry.width)) as u32;
        let bottom = (i64::from(area.origin.y) + i64::from(area.size.height))
            .max(0)
            .min(i64::from(self.geometry.height)) as u32;
        self.damage = DamageRect {
            x: left,
            y: top,
            width: right.saturating_sub(left),
            height: bottom.saturating_sub(top),
        };
        self.phase = phase;
        Ok(true)
    }

    pub(crate) fn present(&self, backend: &mut DisplayBackend) -> Result<(), u64> {
        let frame = PresentFrame {
            geometry: self.geometry,
            pixels: &self.pixels,
            damage: self.damage,
        };
        if let Some(pending) = backend.prepare_present(&frame)? {
            backend.finish_present(pending)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::present::PIXEL_FORMAT_XRGB8888;

    #[test]
    fn padded_frames_only_redraw_the_spinner_when_time_changes() {
        let geometry = DisplayGeometry {
            width: 128,
            height: 96,
            stride: 132,
            format: PIXEL_FORMAT_XRGB8888,
        };
        let mut frame = LoadingFrame::new(geometry, 0).unwrap();
        assert_eq!(frame.pixels.len(), geometry.byte_len().unwrap());
        assert!(!frame.tick(0).unwrap());
        assert!(frame.tick(250).unwrap());
        assert!(!frame.tick(250).unwrap());
        assert_eq!(frame.damage.width, 24);
        frame.damage.validate(geometry).unwrap();
    }
}
