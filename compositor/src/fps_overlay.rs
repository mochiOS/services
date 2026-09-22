use mochi_user_platform as platform;

use crate::geometry::Rect;

pub(crate) const BOUNDS: Rect = Rect { x: 12, y: 12, width: 86, height: 29 };

#[derive(Default)]
pub(crate) struct FpsOverlay {
    pub(crate) enabled: bool,
    keys: u8,
    latched: bool,
    window_start_ms: Option<u64>,
    frames: u32,
    fps: u32,
    drawn_value: Option<u32>,
}

impl FpsOverlay {
    /// Returns true only when the display mode changes.
    pub(crate) fn handle_key(&mut self, event: &platform::input::InputEvent) -> bool {
        if event.kind != platform::input::EVENT_KIND_KEY { return false; }
        let bit = match event.keycode {
            platform::input::KEY_F => 1,
            platform::input::KEY_P => 2,
            platform::input::KEY_S => 4,
            _ => 0,
        };
        if bit != 0 {
            if event.flags & platform::input::FLAG_PRESS != 0 { self.keys |= bit; }
            if event.flags & platform::input::FLAG_RELEASE != 0 { self.keys &= !bit; }
        }
        let modifiers = platform::input::MOD_CTRL | platform::input::MOD_SHIFT;
        let chord = self.keys == 7 && event.modifiers & modifiers == modifiers;
        if !chord { self.latched = false; return false; }
        if self.latched { return false; }
        self.latched = true;
        self.enabled = !self.enabled;
        self.window_start_ms = None;
        self.frames = 0;
        self.fps = 0;
        self.drawn_value = None;
        true
    }

    pub(crate) fn value(&self) -> Option<u32> {
        self.enabled.then_some(self.fps)
    }

    pub(crate) fn needs_damage(&self) -> bool {
        self.value() != self.drawn_value
    }

    pub(crate) fn mark_drawn(&mut self, value: Option<u32>) {
        self.drawn_value = value;
    }

    /// Count successful compositor presents, not application draw requests.
    pub(crate) fn presented(&mut self, now_ms: u64) {
        if !self.enabled { return; }
        let start = *self.window_start_ms.get_or_insert(now_ms);
        self.frames = self.frames.saturating_add(1);
        let elapsed = now_ms.saturating_sub(start);
        if elapsed >= 500 {
            self.fps = ((u64::from(self.frames) * 1_000 + elapsed / 2) / elapsed)
                .min(999) as u32;
            self.frames = 0;
            self.window_start_ms = Some(now_ms);
        }
    }
}

// 3x5 pixel font: digits and F/P/S. The solid rectangles work in both renderers.
fn glyph(c: u8) -> [u8; 5] {
    match c {
        b'0' => [7, 5, 5, 5, 7], b'1' => [2, 6, 2, 2, 7],
        b'2' => [7, 1, 7, 4, 7], b'3' => [7, 1, 7, 1, 7],
        b'4' => [5, 5, 7, 1, 1], b'5' => [7, 4, 7, 1, 7],
        b'6' => [7, 4, 7, 5, 7], b'7' => [7, 1, 1, 1, 1],
        b'8' => [7, 5, 7, 5, 7], b'9' => [7, 5, 7, 1, 7],
        b'F' => [7, 4, 6, 4, 4], b'P' => [7, 5, 7, 4, 4],
        b'S' => [7, 4, 7, 1, 7], _ => [0; 5],
    }
}

pub(crate) fn draw(fps: u32, mut rect: impl FnMut(Rect, u32)) {
    rect(BOUNDS, 0xff18_1c22);
    let value = fps.min(999);
    let text = [
        b'F', b'P', b'S', b' ',
        if value >= 100 { b'0' + (value / 100) as u8 } else { b' ' },
        if value >= 10 { b'0' + ((value / 10) % 10) as u8 } else { b' ' },
        b'0' + (value % 10) as u8,
    ];
    for (index, &character) in text.iter().enumerate() {
        for (row, bits) in glyph(character).iter().enumerate() {
            for column in 0..3 {
                if bits & (4 >> column) != 0 {
                    rect(Rect {
                        x: BOUNDS.x + 7 + (index * 10 + column * 2) as i32,
                        y: BOUNDS.y + 9 + (row * 2) as i32,
                        width: 2,
                        height: 2,
                    }, 0xff92_e6ac);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_rectangles_stay_inside_bounds() {
        draw(999, |rect, _| {
            assert!(rect.x >= BOUNDS.x && rect.y >= BOUNDS.y);
            assert!(rect.x + rect.width as i32 <= BOUNDS.x + BOUNDS.width as i32);
            assert!(rect.y + rect.height as i32 <= BOUNDS.y + BOUNDS.height as i32);
        });
    }
}
