use crate::protocol::errno_status;
use crate::state::{MAX_DIMENSION, MAX_SHARED_PIXELS};

#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Rect {
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

impl Rect {
    pub(crate) const fn full(width: u32, height: u32) -> Self {
        Self {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    pub(crate) fn expanded(self, amount: u32) -> Self {
        let amount_i32 = amount.min(i32::MAX as u32) as i32;
        Self {
            x: self.x.saturating_sub(amount_i32),
            y: self.y.saturating_sub(amount_i32),
            width: self.width.saturating_add(amount.saturating_mul(2)),
            height: self.height.saturating_add(amount.saturating_mul(2)),
        }
    }
}

pub(crate) fn rounded_rect_contains(rect: Rect, radius: u32, x: i32, y: i32) -> bool {
    // Input coordinates identify a physical pixel; sample its center like rendering.
    if x < rect.x
        || y < rect.y
        || i64::from(x) >= i64::from(rect.x) + i64::from(rect.width)
        || i64::from(y) >= i64::from(rect.y) + i64::from(rect.height)
    {
        return false;
    }
    mochios_viewkit_gpu_protocol::continuous_corner::RoundedRect::uniform(
        [
            rect.x as f32,
            rect.y as f32,
            rect.width as f32,
            rect.height as f32,
        ],
        radius as f32,
    )
    .contains((x as f32 + 0.5, y as f32 + 0.5))
}

#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Point {
    pub(crate) x: i32,
    pub(crate) y: i32,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
pub(crate) struct PopupPlacement {
    pub(crate) anchor_rect: Rect,
    pub(crate) offset: Point,
}

pub(crate) fn validate_damage_rect(
    rect: Rect,
    surface_width: u32,
    surface_height: u32,
) -> Result<Rect, u32> {
    if rect.width == 0 || rect.height == 0 || rect.x < 0 || rect.y < 0 {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let x = u32::try_from(rect.x).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let y = u32::try_from(rect.y).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let right = x
        .checked_add(rect.width)
        .ok_or_else(|| errno_status(crate::protocol::SIZE_LIMIT))?;
    let bottom = y
        .checked_add(rect.height)
        .ok_or_else(|| errno_status(crate::protocol::SIZE_LIMIT))?;
    if right > surface_width || bottom > surface_height {
        return Err(errno_status(crate::protocol::SIZE_LIMIT));
    }
    Ok(rect)
}

pub(crate) fn merge_damage(first: Option<Rect>, second: Rect) -> Option<Rect> {
    match first {
        Some(first) => {
            let left = first.x.min(second.x);
            let top = first.y.min(second.y);
            let right = (first.x as i64)
                .saturating_add(first.width as i64)
                .max((second.x as i64).saturating_add(second.width as i64));
            let bottom = (first.y as i64)
                .saturating_add(first.height as i64)
                .max((second.y as i64).saturating_add(second.height as i64));
            Some(Rect {
                x: left,
                y: top,
                width: right.saturating_sub(left as i64) as u32,
                height: bottom.saturating_sub(top as i64) as u32,
            })
        }
        None => Some(second),
    }
}

pub(crate) fn choose_frame_size(display_width: u32, display_height: u32) -> Option<(usize, usize)> {
    if display_width == 0 || display_height == 0 {
        return None;
    }
    let width = display_width.min(MAX_DIMENSION) as usize;
    let height = display_height.min(MAX_DIMENSION) as usize;
    if width.checked_mul(height)? > MAX_SHARED_PIXELS {
        return None;
    }
    Some((width, height))
}

pub(crate) fn clip_present_rect(
    damage: Option<Rect>,
    frame_w: usize,
    frame_h: usize,
) -> Option<Rect> {
    if frame_w == 0 || frame_h == 0 {
        return None;
    }
    let Some(damage) = damage else {
        return Some(Rect {
            x: 0,
            y: 0,
            width: frame_w as u32,
            height: frame_h as u32,
        });
    };
    if damage.width == 0 || damage.height == 0 {
        return None;
    }
    let left = damage.x.max(0) as i64;
    let top = damage.y.max(0) as i64;
    let right = (damage.x as i64)
        .saturating_add(damage.width as i64)
        .min(frame_w as i64)
        .max(0);
    let bottom = (damage.y as i64)
        .saturating_add(damage.height as i64)
        .min(frame_h as i64)
        .max(0);
    if right <= left || bottom <= top {
        return None;
    }
    Some(Rect {
        x: left as i32,
        y: top as i32,
        width: right.saturating_sub(left) as u32,
        height: bottom.saturating_sub(top) as u32,
    })
}

#[cfg(test)]
mod continuous_corner_tests {
    use super::*;
    #[test]
    fn native_input_uses_reference_pixel_centers() {
        use mochios_viewkit_gpu_protocol::continuous_corner::RoundedRect;
        for (width, height, radius) in [(1, 1, 0), (100, 60, 20), (17, 70, 999), (90, 40, 1)] {
            let rect = Rect {
                x: 7,
                y: 13,
                width,
                height,
            };
            let shape =
                RoundedRect::uniform([7.0, 13.0, width as f32, height as f32], radius as f32);
            for y in 12..(14 + height as i32) {
                for x in 6..(8 + width as i32) {
                    assert_eq!(
                        rounded_rect_contains(rect, radius, x, y),
                        shape.contains((x as f32 + 0.5, y as f32 + 0.5))
                    );
                }
            }
        }
    }
}
