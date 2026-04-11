use swiftlib::vga;

const BG_COLOR: u32 = 0x001E_1E2E;
const WINDOW_POS_X: i32 = 96;
const WINDOW_POS_Y: i32 = 96;
const WINDOW_STEP_X: i32 = 14;
const WINDOW_STEP_Y: i32 = 10;

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
    pub x: i32,
    pub y: i32,
    pub z: i32,
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u32>,
}

pub struct Renderer {
    fb_ptr: *mut u32,
    width: i32,
    height: i32,
    stride: i32,
    back_buffer: Vec<u32>,
    cursor_x: i32,
    cursor_y: i32,
    cursor_sprite: CursorSprite,
    windows: Vec<WindowSurface>,
}

impl Renderer {
    pub fn new(fb_ptr: *mut u32, info: vga::FbInfo) -> Self {
        Self {
            fb_ptr,
            width: info.width as i32,
            height: info.height as i32,
            stride: info.stride as i32,
            back_buffer: vec![0; (info.height * info.stride) as usize],
            cursor_x: (info.width / 2) as i32,
            cursor_y: (info.height / 2) as i32,
            cursor_sprite: CursorSprite::from_generated(),
            windows: Vec::new(),
        }
    }

    pub fn initialize(&mut self) {
        self.render_full();
    }

    pub fn create_window(&mut self, id: u32, width: usize, height: usize, pixels: Vec<u32>) {
        if self.windows.iter().any(|w| w.id == id) {
            self.update_window_pixels(id, width, height, pixels);
            return;
        }
        let z = self.next_z();
        let x = WINDOW_POS_X + ((id as i32 - 1) * WINDOW_STEP_X);
        let y = WINDOW_POS_Y + ((id as i32 - 1) * WINDOW_STEP_Y);
        self.windows.push(WindowSurface {
            id,
            x,
            y,
            z,
            width,
            height,
            pixels,
        });
        self.sort_windows_by_z();
        self.render_full();
    }

    pub fn update_window_pixels(&mut self, id: u32, width: usize, height: usize, pixels: Vec<u32>) {
        let new_z = self.next_z();
        if let Some(win) = self.windows.iter_mut().find(|w| w.id == id) {
            win.width = width;
            win.height = height;
            win.pixels = pixels;
            win.z = new_z;
            self.sort_windows_by_z();
            self.render_full();
            return;
        }
        self.create_window(id, width, height, pixels);
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
        self.clear_back_buffer(BG_COLOR);
        self.draw_windows_to_back_buffer();
        self.draw_cursor_to_back_buffer(self.cursor_x, self.cursor_y);
        self.present_back_buffer();
    }

    fn clear_back_buffer(&mut self, color: u32) {
        let pixel = color | 0xFF00_0000;
        for p in &mut self.back_buffer {
            *p = pixel;
        }
    }

    fn draw_windows_to_back_buffer(&mut self) {
        for surface in &self.windows {
            for sy in 0..surface.height {
                for sx in 0..surface.width {
                    let x = surface.x + sx as i32;
                    let y = surface.y + sy as i32;
                    if x < 0 || y < 0 || x >= self.width || y >= self.height {
                        continue;
                    }
                    let bb_idx = (y * self.stride + x) as usize;
                    let src = surface.pixels[sy * surface.width + sx];
                    self.back_buffer[bb_idx] = src | 0xFF00_0000;
                }
            }
        }
    }

    fn draw_cursor_to_back_buffer(&mut self, cx: i32, cy: i32) {
        for sy in 0..self.cursor_sprite.height {
            for sx in 0..self.cursor_sprite.width {
                let sprite_idx = sy * self.cursor_sprite.width + sx;
                let x = cx + sx as i32;
                let y = cy + sy as i32;
                if x < 0 || y < 0 || x >= self.width || y >= self.height {
                    continue;
                }
                let bb_idx = (y * self.stride + x) as usize;
                let dst = self.back_buffer[bb_idx];
                let src = self.cursor_sprite.pixels[sprite_idx];
                let blended = blend_argb(dst, src);
                self.back_buffer[bb_idx] = blended;
            }
        }
    }

    fn present_back_buffer(&mut self) {
        for (i, px) in self.back_buffer.iter().enumerate() {
            unsafe {
                self.fb_ptr.add(i).write_volatile(*px);
            }
        }
    }

    fn sort_windows_by_z(&mut self) {
        self.windows.sort_by_key(|w| w.z);
    }

    fn next_z(&self) -> i32 {
        self.windows
            .iter()
            .map(|w| w.z)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
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
