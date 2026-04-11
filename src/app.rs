use swiftlib::{ipc, keyboard, mouse, task};

use crate::input::InputState;
use crate::ipc_proto::{IPC_BUF_SIZE, OP_REQ_CREATE_WINDOW, OP_REQ_FLUSH, OP_RES_WINDOW_CREATED};
use crate::renderer::Renderer;

pub struct KagamiApp {
    renderer: Renderer,
    input: InputState,
    warned_mouse_err: bool,
    ipc_buf: [u8; IPC_BUF_SIZE],
    next_window_id: u32,
    demo_windows_created: bool,
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
        }
    }

    pub fn run(&mut self) {
        self.renderer.initialize();
        println!(
            "[KAGAMI] started (ESC to exit, D to inject demo frame) tid={}",
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
            }

            match mouse::read_packet_raw() {
                Ok(Some(packet)) => {
                    did_work = true;
                    if let Some((dx, dy)) = self.input.consume_mouse(packet) {
                        self.renderer.move_cursor_by(dx, dy);
                    }
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
                let width = req_w.clamp(8, 96);
                let height = req_h.clamp(8, 96);
                let window_id = self.next_window_id;
                self.next_window_id = self.next_window_id.saturating_add(1);
                self.renderer
                    .create_window(window_id, width, height, vec![0x0030_3048; width * height]);
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
                if width == 0 || height == 0 || pixel_count > 1021 || len < needed {
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
            _ => {}
        }
    }

    fn inject_demo_ipc(&mut self) {
        let self_tid = task::gettid();
        let width_a: u16 = 40;
        let height_a: u16 = 24;
        let width_b: u16 = 38;
        let height_b: u16 = 22;

        if !self.demo_windows_created {
            let mut create_a = [0u8; 8];
            create_a[0..4].copy_from_slice(&OP_REQ_CREATE_WINDOW.to_le_bytes());
            create_a[4..6].copy_from_slice(&width_a.to_le_bytes());
            create_a[6..8].copy_from_slice(&height_a.to_le_bytes());
            let _ = ipc::ipc_send(self_tid, &create_a);

            let mut create_b = [0u8; 8];
            create_b[0..4].copy_from_slice(&OP_REQ_CREATE_WINDOW.to_le_bytes());
            create_b[4..6].copy_from_slice(&width_b.to_le_bytes());
            create_b[6..8].copy_from_slice(&height_b.to_le_bytes());
            let _ = ipc::ipc_send(self_tid, &create_b);
            self.demo_windows_created = true;
        }

        let mut flush_a = vec![0u8; 12 + (width_a as usize * height_a as usize * 4)];
        flush_a[0..4].copy_from_slice(&OP_REQ_FLUSH.to_le_bytes());
        flush_a[4..8].copy_from_slice(&1u32.to_le_bytes());
        flush_a[8..10].copy_from_slice(&width_a.to_le_bytes());
        flush_a[10..12].copy_from_slice(&height_a.to_le_bytes());
        let mut off_a = 12usize;
        for y in 0..height_a as usize {
            for x in 0..width_a as usize {
                let checker = ((x / 2) + (y / 2)) & 1;
                let c: u32 = if checker == 0 { 0x0066_CCFF } else { 0x0022_3344 };
                flush_a[off_a..off_a + 4].copy_from_slice(&(c | 0xFF00_0000).to_le_bytes());
                off_a += 4;
            }
        }
        let _ = ipc::ipc_send(self_tid, &flush_a);

        let mut flush_b = vec![0u8; 12 + (width_b as usize * height_b as usize * 4)];
        flush_b[0..4].copy_from_slice(&OP_REQ_FLUSH.to_le_bytes());
        flush_b[4..8].copy_from_slice(&2u32.to_le_bytes());
        flush_b[8..10].copy_from_slice(&width_b.to_le_bytes());
        flush_b[10..12].copy_from_slice(&height_b.to_le_bytes());
        let mut off_b = 12usize;
        for y in 0..height_b as usize {
            for x in 0..width_b as usize {
                let checker = ((x / 2) + (y / 2)) & 1;
                let c: u32 = if checker == 0 { 0x00FF_8866 } else { 0x0055_2233 };
                flush_b[off_b..off_b + 4].copy_from_slice(&(c | 0xFF00_0000).to_le_bytes());
                off_b += 4;
            }
        }
        let _ = ipc::ipc_send(self_tid, &flush_b);
    }
}
