use swiftlib::{ipc, keyboard, process, mouse, task};

use crate::input::InputState;
use crate::ipc_proto::{
    IPC_BUF_SIZE, LAYER_APP, LAYER_STATUS, LAYER_SYSTEM, LAYER_WALLPAPER, OP_REQ_CREATE_WINDOW,
    OP_REQ_ATTACH_SHARED, OP_REQ_FLUSH, OP_REQ_FLUSH_CHUNK, OP_REQ_PRESENT_SHARED,
    OP_RES_WINDOW_CREATED,
};
use crate::renderer::{Renderer, WindowLayer};

const FLUSH_FULL_HEADER_SIZE: usize = 12;
const FLUSH_CHUNK_HEADER_SIZE: usize = 20;
const IPC_MAX_PIXELS_FULL: usize = (IPC_BUF_SIZE - FLUSH_FULL_HEADER_SIZE) / 4;
const IPC_MAX_PIXELS_CHUNK: usize = (IPC_BUF_SIZE - FLUSH_CHUNK_HEADER_SIZE) / 4;

#[derive(Clone, Copy)]
struct DragState {
    window_id: u32,
    grab_dx: i32,
    grab_dy: i32,
}

pub struct KagamiApp {
    renderer: Renderer,
    input: InputState,
    warned_mouse_err: bool,
    ipc_buf: [u8; IPC_BUF_SIZE],
    next_window_id: u32,
    demo_windows_created: bool,
    secure_input_mode: bool,
    prev_left_down: bool,
    drag_state: Option<DragState>,
    viewkit_key_down: bool,
}

impl KagamiApp {
    pub fn new(renderer: Renderer) -> Self {
        Self {
            renderer,
            input: InputState::new(),
            warned_mouse_err: false,
            ipc_buf: [0u8; IPC_BUF_SIZE],
            next_window_id: 1,
            demo_windows_created: false,
            secure_input_mode: false,
            prev_left_down: false,
            drag_state: None,
            viewkit_key_down: false,
        }
    }

    pub fn run(&mut self) {
        self.renderer.initialize();
        println!(
            "[KAGAMI] started (ESC to exit, D demo, V ViewKit) tid={}",
            task::gettid()
        );

        loop {
            let mut did_work = false;

            let sc_opt = match keyboard::read_scancode_tap() {
                Ok(Some(sc)) => Some(sc),
                Ok(None) => keyboard::read_scancode(),
                Err(_) => keyboard::read_scancode(),
            };

            if let Some(sc) = sc_opt {
                did_work = true;
                if self.input.should_exit(sc) {
                    println!("[KAGAMI] exit");
                    return;
                }
                if sc == 0x20 || sc == 0xA0 {
                    self.inject_demo_ipc();
                }
                if sc == 0x2F && !self.viewkit_key_down {
                    self.viewkit_key_down = true;
                    self.launch_viewkit_ui_test();
                }
                if sc == 0xAF {
                    self.viewkit_key_down = false;
                }
            }

            match mouse::read_packet_raw() {
                Ok(Some(packet)) => {
                    did_work = true;
                    if let Some((dx, dy)) = self.input.consume_mouse(packet) {
                        self.renderer.move_cursor_by(dx, dy);
                    }
                    self.handle_pointer_buttons(packet.left());
                }
                Ok(None) => {}
                Err(err) => {
                    if !self.warned_mouse_err {
                        eprintln!("[KAGAMI] mouse read error: {}", err as i64);
                        self.warned_mouse_err = true;
                    }
                }
            }

            if self.process_ipc_messages() {
                did_work = true;
            }

            self.update_secure_input_mode();

            if !did_work {
                task::yield_now();
            }
        }
    }

    fn process_ipc_messages(&mut self) -> bool {
        let mut handled = false;
        loop {
            let (sender, len) = ipc::ipc_recv(&mut self.ipc_buf);
            if sender == 0 || len == 0 {
                break;
            }
            let len = (len as usize).min(self.ipc_buf.len());
            self.handle_ipc_message(sender, len);
            handled = true;
        }
        handled
    }

    fn handle_ipc_message(&mut self, sender_tid: u64, len: usize) {
        if len < 4 {
            return;
        }
        let op = u32::from_le_bytes([
            self.ipc_buf[0],
            self.ipc_buf[1],
            self.ipc_buf[2],
            self.ipc_buf[3],
        ]);
        match op {
            OP_REQ_CREATE_WINDOW => {
                if len < 8 {
                    return;
                }
                let req_w = u16::from_le_bytes([self.ipc_buf[4], self.ipc_buf[5]]) as usize;
                let req_h = u16::from_le_bytes([self.ipc_buf[6], self.ipc_buf[7]]) as usize;
                let requested_layer = if len >= 9 { self.ipc_buf[8] } else { LAYER_APP };
                let width = req_w.clamp(8, 1024);
                let height = req_h.clamp(8, 1024);
                let privilege = task::get_thread_privilege(sender_tid);
                let layer = sanitize_layer_request(requested_layer, privilege);
                let window_id = self.next_window_id;
                self.next_window_id = self.next_window_id.saturating_add(1);
                self.renderer.create_window(
                    window_id,
                    layer,
                    width,
                    height,
                    vec![0x0030_3048; width * height],
                );
                let mut res = [0u8; 8];
                res[0..4].copy_from_slice(&OP_RES_WINDOW_CREATED.to_le_bytes());
                res[4..8].copy_from_slice(&window_id.to_le_bytes());
                let _ = ipc::ipc_send(sender_tid, &res);
            }
            OP_REQ_FLUSH => {
                if len < 12 {
                    return;
                }
                let window_id = u32::from_le_bytes([
                    self.ipc_buf[4],
                    self.ipc_buf[5],
                    self.ipc_buf[6],
                    self.ipc_buf[7],
                ]);
                let width = u16::from_le_bytes([self.ipc_buf[8], self.ipc_buf[9]]) as usize;
                let height = u16::from_le_bytes([self.ipc_buf[10], self.ipc_buf[11]]) as usize;
                let pixel_count = width.saturating_mul(height);
                let needed = 12usize.saturating_add(pixel_count.saturating_mul(4));
                if width == 0 || height == 0 || pixel_count > IPC_MAX_PIXELS_FULL || len < needed {
                    return;
                }
                let mut pixels = Vec::with_capacity(pixel_count);
                let mut off = 12usize;
                for _ in 0..pixel_count {
                    let px = u32::from_le_bytes([
                        self.ipc_buf[off],
                        self.ipc_buf[off + 1],
                        self.ipc_buf[off + 2],
                        self.ipc_buf[off + 3],
                    ]);
                    pixels.push(px | 0xFF00_0000);
                    off += 4;
                }
                self.renderer
                    .update_window_pixels(window_id, width, height, pixels);
            }
            OP_REQ_FLUSH_CHUNK => {
                if len < FLUSH_CHUNK_HEADER_SIZE {
                    return;
                }
                let window_id = u32::from_le_bytes([
                    self.ipc_buf[4],
                    self.ipc_buf[5],
                    self.ipc_buf[6],
                    self.ipc_buf[7],
                ]);
                let width = u16::from_le_bytes([self.ipc_buf[8], self.ipc_buf[9]]) as usize;
                let height = u16::from_le_bytes([self.ipc_buf[10], self.ipc_buf[11]]) as usize;
                let chunk_x = u16::from_le_bytes([self.ipc_buf[12], self.ipc_buf[13]]) as usize;
                let chunk_y = u16::from_le_bytes([self.ipc_buf[14], self.ipc_buf[15]]) as usize;
                let chunk_w = u16::from_le_bytes([self.ipc_buf[16], self.ipc_buf[17]]) as usize;
                let chunk_h = u16::from_le_bytes([self.ipc_buf[18], self.ipc_buf[19]]) as usize;
                let pixel_count = chunk_w.saturating_mul(chunk_h);
                let needed = FLUSH_CHUNK_HEADER_SIZE.saturating_add(pixel_count.saturating_mul(4));
                if width == 0
                    || height == 0
                    || chunk_w == 0
                    || chunk_h == 0
                    || pixel_count > IPC_MAX_PIXELS_CHUNK
                    || chunk_x.saturating_add(chunk_w) > width
                    || chunk_y.saturating_add(chunk_h) > height
                    || len < needed
                {
                    return;
                }
                let mut pixels = Vec::with_capacity(pixel_count);
                let mut off = FLUSH_CHUNK_HEADER_SIZE;
                for _ in 0..pixel_count {
                    let px = u32::from_le_bytes([
                        self.ipc_buf[off],
                        self.ipc_buf[off + 1],
                        self.ipc_buf[off + 2],
                        self.ipc_buf[off + 3],
                    ]);
                    pixels.push(px | 0xFF00_0000);
                    off += 4;
                }
                self.renderer.update_window_chunk_pixels(
                    window_id, width, height, chunk_x, chunk_y, chunk_w, chunk_h, &pixels,
                );
            }
            OP_REQ_ATTACH_SHARED => {
                if len < 16 {
                    return;
                }
                let window_id = u32::from_le_bytes([
                    self.ipc_buf[4],
                    self.ipc_buf[5],
                    self.ipc_buf[6],
                    self.ipc_buf[7],
                ]);
                let width = u16::from_le_bytes([self.ipc_buf[8], self.ipc_buf[9]]) as usize;
                let height = u16::from_le_bytes([self.ipc_buf[10], self.ipc_buf[11]]) as usize;
                let page_count = u16::from_le_bytes([self.ipc_buf[12], self.ipc_buf[13]]) as usize;
                if page_count == 0 || page_count > 128 {
                    return;
                }
                let needed = 16usize.saturating_add(page_count.saturating_mul(8));
                if len < needed {
                    return;
                }
                let mut phys_pages = Vec::with_capacity(page_count);
                let mut off = 16usize;
                for _ in 0..page_count {
                    let p = u64::from_le_bytes([
                        self.ipc_buf[off],
                        self.ipc_buf[off + 1],
                        self.ipc_buf[off + 2],
                        self.ipc_buf[off + 3],
                        self.ipc_buf[off + 4],
                        self.ipc_buf[off + 5],
                        self.ipc_buf[off + 6],
                        self.ipc_buf[off + 7],
                    ]);
                    phys_pages.push(p);
                    off += 8;
                }
                if !self
                    .renderer
                    .attach_shared_surface(window_id, width, height, &phys_pages)
                {
                    eprintln!("[KAGAMI] attach_shared_surface failed window={}", window_id);
                }
            }
            OP_REQ_PRESENT_SHARED => {
                if len < 8 {
                    return;
                }
                let window_id = u32::from_le_bytes([
                    self.ipc_buf[4],
                    self.ipc_buf[5],
                    self.ipc_buf[6],
                    self.ipc_buf[7],
                ]);
                self.renderer.present_shared_surface(window_id);
            }
            _ => {}
        }
    }

    fn update_secure_input_mode(&mut self) {
        let focused_layer = self.renderer.top_layer();
        let next_secure = matches!(focused_layer, Some(WindowLayer::System));
        if next_secure != self.secure_input_mode {
            self.secure_input_mode = next_secure;
            if self.secure_input_mode {
                println!("[KAGAMI] secure input mode: ON");
            } else {
                println!("[KAGAMI] secure input mode: OFF");
            }
        }
    }

    fn handle_pointer_buttons(&mut self, left_down: bool) {
        let (cx, cy) = self.renderer.cursor_pos();
        if !self.prev_left_down && left_down {
            if let Some(window_id) = self.renderer.hit_test_top_window(cx, cy) {
                self.renderer.bring_to_front(window_id);
                if self.renderer.is_title_bar_hit(window_id, cx, cy)
                    && let Some((wx, wy)) = self.renderer.window_pos(window_id)
                {
                    self.drag_state = Some(DragState {
                        window_id,
                        grab_dx: cx - wx,
                        grab_dy: cy - wy,
                    });
                }
            }
        } else if self.prev_left_down && !left_down {
            self.drag_state = None;
        } else if left_down && let Some(drag) = self.drag_state {
            self.renderer
                .move_window_to(drag.window_id, cx - drag.grab_dx, cy - drag.grab_dy);
        }
        self.prev_left_down = left_down;
    }

    fn inject_demo_ipc(&mut self) {
        let self_tid = task::gettid();
        let width_a: u16 = 120;
        let height_a: u16 = 80;
        let width_b: u16 = 104;
        let height_b: u16 = 72;

        if !self.demo_windows_created {
            let mut create_a = [0u8; 9];
            create_a[0..4].copy_from_slice(&OP_REQ_CREATE_WINDOW.to_le_bytes());
            create_a[4..6].copy_from_slice(&width_a.to_le_bytes());
            create_a[6..8].copy_from_slice(&height_a.to_le_bytes());
            create_a[8] = LAYER_APP;
            let _ = ipc::ipc_send(self_tid, &create_a);

            let mut create_b = [0u8; 9];
            create_b[0..4].copy_from_slice(&OP_REQ_CREATE_WINDOW.to_le_bytes());
            create_b[4..6].copy_from_slice(&width_b.to_le_bytes());
            create_b[6..8].copy_from_slice(&height_b.to_le_bytes());
            create_b[8] = LAYER_APP;
            let _ = ipc::ipc_send(self_tid, &create_b);
            self.demo_windows_created = true;
        }

        self.send_checkerboard_chunked(self_tid, 1, width_a as usize, height_a as usize, 0x0066_CCFF, 0x0022_3344);
        self.send_checkerboard_chunked(self_tid, 2, width_b as usize, height_b as usize, 0x00FF_8866, 0x0055_2233);
    }

    fn send_checkerboard_chunked(
        &self,
        target_tid: u64,
        window_id: u32,
        width: usize,
        height: usize,
        c0: u32,
        c1: u32,
    ) {
        let max_chunk_pixels = IPC_MAX_PIXELS_CHUNK.max(1);
        let chunk_w = width.min(64).max(1);
        let chunk_h = (max_chunk_pixels / chunk_w).max(1);
        let mut y0 = 0usize;
        while y0 < height {
            let h = (height - y0).min(chunk_h);
            let mut x0 = 0usize;
            while x0 < width {
                let w = (width - x0).min(chunk_w);
                let mut msg = vec![0u8; FLUSH_CHUNK_HEADER_SIZE + (w * h * 4)];
                msg[0..4].copy_from_slice(&OP_REQ_FLUSH_CHUNK.to_le_bytes());
                msg[4..8].copy_from_slice(&window_id.to_le_bytes());
                msg[8..10].copy_from_slice(&(width as u16).to_le_bytes());
                msg[10..12].copy_from_slice(&(height as u16).to_le_bytes());
                msg[12..14].copy_from_slice(&(x0 as u16).to_le_bytes());
                msg[14..16].copy_from_slice(&(y0 as u16).to_le_bytes());
                msg[16..18].copy_from_slice(&(w as u16).to_le_bytes());
                msg[18..20].copy_from_slice(&(h as u16).to_le_bytes());
                let mut off = FLUSH_CHUNK_HEADER_SIZE;
                for y in 0..h {
                    for x in 0..w {
                        let checker = (((x0 + x) / 2) + ((y0 + y) / 2)) & 1;
                        let c: u32 = if checker == 0 { c0 } else { c1 };
                        msg[off..off + 4].copy_from_slice(&(c | 0xFF00_0000).to_le_bytes());
                        off += 4;
                    }
                }
                let _ = ipc::ipc_send(target_tid, &msg);
                x0 += w;
            }
            y0 += h;
        }
    }

    fn launch_viewkit_ui_test(&self) {
        let kagami_tid = task::gettid();
        let arg_tid = format!("--kagami-tid={}", kagami_tid);
        let args = [arg_tid.as_str()];
        match process::exec_with_args("/Applications/ViewKit.app/entry.elf", &args) {
            Ok(pid) => println!("[KAGAMI] launched ViewKit ui_test pid={}", pid),
            Err(_) => eprintln!("[KAGAMI] failed to launch ViewKit ui_test"),
        }
    }
}

fn sanitize_layer_request(requested: u8, privilege: u64) -> WindowLayer {
    let requested_layer = match requested {
        LAYER_WALLPAPER => WindowLayer::Wallpaper,
        LAYER_STATUS => WindowLayer::Status,
        LAYER_SYSTEM => WindowLayer::System,
        _ => WindowLayer::App,
    };
    let is_privileged = privilege == 0 || privilege == 1;
    if !is_privileged {
        match requested_layer {
            WindowLayer::Status | WindowLayer::System => WindowLayer::App,
            other => other,
        }
    } else {
        requested_layer
    }
}
