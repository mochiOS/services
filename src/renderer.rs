use swiftlib::vga;

const BG_COLOR: u32 = 0x001E_1E2E;
const WINDOW_POS_X: i32 = 96;
const WINDOW_POS_Y: i32 = 96;

include!(concat!(env!("OUT_DIR"), "/cursor_pixels.rs"));

struct CursorSprite {
    width: usize,
    height: usize,
    pixels: Vec<u32>,
}

impl CursorSprite {
    fn from_generated() -> Self {
        Self {
            width: CURSOR_WIDTH,
            height: CURSOR_HEIGHT,
            pixels: CURSOR_PIXELS.to_vec(),
        }
    }
}

pub struct WindowSurface {
    pub id: u32,
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u32>,
}

pub struct Renderer {
    fb_ptr: *mut u32,
    width: i32,
    height: i32,
    stride: i32,
    cursor_x: i32,
    cursor_y: i32,
    cursor_sprite: CursorSprite,
    window: Option<WindowSurface>,
}

impl Renderer {
    pub fn new(fb_ptr: *mut u32, info: vga::FbInfo) -> Self {
        Self {
            fb_ptr,
            width: info.width as i32,
            height: info.height as i32,
            stride: info.stride as i32,
            cursor_x: (info.width / 2) as i32,
            cursor_y: (info.height / 2) as i32,
            cursor_sprite: CursorSprite::from_generated(),
            window: None,
        }
    }

    pub fn initialize(&mut self) {
        self.render_full();
    }

    pub fn set_window_surface(&mut self, surface: WindowSurface) {
        self.window = Some(surface);
        self.render_full();
    }

    pub fn move_cursor_by(&mut self, dx: i32, dy: i32) {
        let next_x = clamp_i32(self.cursor_x + dx, 0, self.width - 1);
        let next_y = clamp_i32(self.cursor_y - dy, 0, self.height - 1);
        if next_x == self.cursor_x && next_y == self.cursor_y {
            return;
        }
        self.cursor_x = next_x;
        self.cursor_y = next_y;
        self.render_full();
    }

    fn render_full(&mut self) {
        self.clear_screen(BG_COLOR);
        self.draw_window();
        self.draw_cursor(self.cursor_x, self.cursor_y);
    }

    fn clear_screen(&mut self, color: u32) {
        let total = (self.height * self.stride) as usize;
        let pixel = color | 0xFF00_0000;
        for i in 0..total {
            unsafe {
                self.fb_ptr.add(i).write_volatile(pixel);
            }
        }
    }

    fn draw_window(&mut self) {
        let Some(surface) = self.window.as_ref() else {
            return;
        };
        let _ = surface.id;
        for sy in 0..surface.height {
            for sx in 0..surface.width {
                let x = WINDOW_POS_X + sx as i32;
                let y = WINDOW_POS_Y + sy as i32;
                if x < 0 || y < 0 || x >= self.width || y >= self.height {
                    continue;
                }
                let fb_idx = (y * self.stride + x) as usize;
                let src = surface.pixels[sy * surface.width + sx];
                unsafe {
                    self.fb_ptr.add(fb_idx).write_volatile(src | 0xFF00_0000);
                }
            }
        }
    }

    fn draw_cursor(&mut self, cx: i32, cy: i32) {
        for sy in 0..self.cursor_sprite.height {
            for sx in 0..self.cursor_sprite.width {
                let sprite_idx = sy * self.cursor_sprite.width + sx;
                let x = cx + sx as i32;
                let y = cy + sy as i32;
                if x < 0 || y < 0 || x >= self.width || y >= self.height {
                    continue;
                }
                let fb_idx = (y * self.stride + x) as usize;
                let dst = unsafe { self.fb_ptr.add(fb_idx).read_volatile() };
                let src = self.cursor_sprite.pixels[sprite_idx];
                let blended = blend_argb(dst, src);
                unsafe {
                    self.fb_ptr.add(fb_idx).write_volatile(blended);
                }
            }
        }
    }
}

fn blend_argb(dst: u32, src: u32) -> u32 {
    let sa = (src >> 24) & 0xFF;
    if sa == 0 {
        return dst;
    }
    if sa == 0xFF {
        return src | 0xFF00_0000;
    }
    let inv = 255 - sa;
    let sr = (src >> 16) & 0xFF;
    let sg = (src >> 8) & 0xFF;
    let sb = src & 0xFF;
    let dr = (dst >> 16) & 0xFF;
    let dg = (dst >> 8) & 0xFF;
    let db = dst & 0xFF;
    let r = (sr * sa + dr * inv) / 255;
    let g = (sg * sa + dg * inv) / 255;
    let b = (sb * sa + db * inv) / 255;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

fn clamp_i32(v: i32, min: i32, max: i32) -> i32 {
    if v < min {
        min
    } else if v > max {
        max
    } else {
        v
    }
}
