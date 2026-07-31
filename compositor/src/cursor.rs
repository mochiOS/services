use alloc::vec::Vec;

use crate::geometry::{Rect, merge_damage};

const MAX_EXTENT: u32 = 64;

#[derive(Default)]
pub(crate) struct CursorImage {
    width: u32,
    height: u32,
    hotspot_x: i32,
    hotspot_y: i32,
    pixels: Vec<u32>,
    generation: u64,
}

impl CursorImage {
    pub(crate) fn set_premultiplied_rgba(
        &mut self,
        width: u32,
        height: u32,
        hotspot_x: i32,
        hotspot_y: i32,
        rgba: &[u8],
    ) -> bool {
        if width == 0
            || height == 0
            || width > MAX_EXTENT
            || height > MAX_EXTENT
            || hotspot_x < 0
            || hotspot_y < 0
            || hotspot_x >= width as i32
            || hotspot_y >= height as i32
        {
            return false;
        }
        let Some(pixel_count) = (width as usize).checked_mul(height as usize) else {
            return false;
        };
        if rgba.len() != pixel_count.saturating_mul(4) {
            return false;
        }
        self.pixels.clear();
        if self.pixels.try_reserve_exact(pixel_count).is_err() {
            return false;
        }
        for pixel in rgba.chunks_exact(4) {
            self.pixels.push(
                (u32::from(pixel[3]) << 24)
                    | (u32::from(pixel[0]) << 16)
                    | (u32::from(pixel[1]) << 8)
                    | u32::from(pixel[2]),
            );
        }
        self.width = width;
        self.height = height;
        self.hotspot_x = hotspot_x;
        self.hotspot_y = hotspot_y;
        self.generation = self.generation.wrapping_add(1).max(1);
        true
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pixels.is_empty()
    }

    pub(crate) fn texture(&self) -> Option<(u32, u32, &[u32], u64)> {
        (!self.pixels.is_empty()).then_some((
            self.width,
            self.height,
            self.pixels.as_slice(),
            self.generation,
        ))
    }

    pub(crate) fn bounds(&self, x: i32, y: i32) -> Rect {
        Rect {
            x: x.saturating_sub(self.hotspot_x),
            y: y.saturating_sub(self.hotspot_y),
            width: self.width,
            height: self.height,
        }
    }

    pub(crate) fn movement_damage(&self, old: Option<(i32, i32)>, new_x: i32, new_y: i32) -> Rect {
        old.map_or_else(
            || self.bounds(new_x, new_y),
            |(old_x, old_y)| {
                merge_damage(Some(self.bounds(old_x, old_y)), self.bounds(new_x, new_y))
                    .unwrap_or_else(|| self.bounds(new_x, new_y))
            },
        )
    }

    pub(crate) fn pixel(
        &self,
        screen_x: i32,
        screen_y: i32,
        pointer_x: i32,
        pointer_y: i32,
    ) -> Option<u32> {
        let x = screen_x.saturating_sub(pointer_x.saturating_sub(self.hotspot_x));
        let y = screen_y.saturating_sub(pointer_y.saturating_sub(self.hotspot_y));
        if x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return None;
        }
        let index = (y as usize)
            .checked_mul(self.width as usize)?
            .checked_add(x as usize)?;
        self.pixels
            .get(index)
            .copied()
            .filter(|pixel| pixel >> 24 != 0)
    }
}
