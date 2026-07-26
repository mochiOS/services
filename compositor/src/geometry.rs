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
    let right = (rect.x as i64).saturating_add(rect.width as i64);
    let bottom = (rect.y as i64).saturating_add(rect.height as i64);
    if i64::from(x) < i64::from(rect.x)
        || i64::from(y) < i64::from(rect.y)
        || i64::from(x) >= right
        || i64::from(y) >= bottom
    {
        return false;
    }
    let radius = radius.min(rect.width / 2).min(rect.height / 2) as i64;
    if radius == 0 {
        return true;
    }
    let x = i64::from(x);
    let y = i64::from(y);
    let left = i64::from(rect.x);
    let top = i64::from(rect.y);
    if x >= left + radius && x < right - radius {
        return true;
    }
    if y >= top + radius && y < bottom - radius {
        return true;
    }
    let center_x = if x < left + radius {
        left + radius
    } else {
        right - radius - 1
    };
    let center_y = if y < top + radius {
        top + radius
    } else {
        bottom - radius - 1
    };
    let dx = x - center_x;
    let dy = y - center_y;
    dx * dx + dy * dy <= radius * radius
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
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let bottom = y
        .checked_add(rect.height)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    if right > surface_width || bottom > surface_height {
        return Err(errno_status(mochi_user_syscall::ERANGE));
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
