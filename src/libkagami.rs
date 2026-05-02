// Host-side shim for Kagami minimal APIs.

#[cfg(all(unix, target_os = "linux", target_env = "gnu"))]
mod unix_impl {
    use memmap2::MmapMut;
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    use tempfile::tempfile;
    use wayland_client::protocol::wl_shm_pool::WlShmPool;
    use std::os::unix::io::BorrowedFd;
    use wayland_client::protocol::{
        wl_buffer, wl_compositor, wl_shm, wl_shm::Format, wl_registry, wl_shm_pool,
        wl_surface, wl_pointer, wl_keyboard, wl_seat, wl_callback, wl_shell, wl_shell_surface,
    };
    use wayland_protocols::xdg::shell::client::xdg_wm_base;
    use wayland_protocols::xdg::shell::client::xdg_surface;
    use wayland_protocols::xdg::shell::client::xdg_toplevel;
    use wayland_client::{Connection, EventQueue, QueueHandle, Dispatch};
    use wayland_client::globals::{registry_queue_init, GlobalList, GlobalListContents};
    use wayland_client::protocol::wl_surface::WlSurface;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Registry state used only for initial global collection
    struct RegistryState;
    impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_registry::WlRegistry,
            _event: wl_registry::Event,
            _data: &GlobalListContents,
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {
            // no-op: global list helper maintains globals
        }
    }

    // Implement empty Dispatch handlers for objects we will create with the same QueueHandle
    // no-op handlers for various protocol objects using () userdata
    impl Dispatch<WlShmPool, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &WlShmPool,
            _event: wl_shm_pool::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {}
    }
    impl Dispatch<wl_buffer::WlBuffer, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_buffer::WlBuffer,
            _event: wl_buffer::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {}
    }
    impl Dispatch<WlSurface, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &WlSurface,
            _event: wl_surface::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {}
    }
    impl Dispatch<wl_compositor::WlCompositor, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_compositor::WlCompositor,
            _event: wl_compositor::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {}
    }
    impl Dispatch<wl_shm::WlShm, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_shm::WlShm,
            _event: wl_shm::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {}
    }

    // Pointer/Keyboard callbacks userdata
    struct PointerHandler(Arc<dyn Fn(f64, f64) + Send + Sync>);
    struct KeyboardHandler(Arc<dyn Fn(u32, wayland_client::WEnum<wl_keyboard::KeyState>) + Send + Sync>);

    impl Dispatch<wl_pointer::WlPointer, Arc<PointerHandler>> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_pointer::WlPointer,
            event: wl_pointer::Event,
            data: &Arc<PointerHandler>,
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {
            match event {
                wl_pointer::Event::Motion { surface_x, surface_y, .. } => {
                    data.0(surface_x, surface_y);
                }
                _ => {}
            }
        }
    }

    impl Dispatch<wl_keyboard::WlKeyboard, Arc<KeyboardHandler>> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_keyboard::WlKeyboard,
            event: wl_keyboard::Event,
            data: &Arc<KeyboardHandler>,
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {
            match event {
                wl_keyboard::Event::Key { key, state, .. } => {
                    data.0(key, state);
                }
                _ => {}
            }
        }
    }

    impl Dispatch<wl_callback::WlCallback, Arc<AtomicBool>> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_callback::WlCallback,
            event: wl_callback::Event,
            data: &Arc<AtomicBool>,
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {
            if let wl_callback::Event::Done { .. } = event {
                data.store(true, Ordering::SeqCst);
            }
        }
    }

    // minimal no-op handlers for shell related objects
    impl Dispatch<wl_seat::WlSeat, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_seat::WlSeat,
            _event: wl_seat::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {}
    }
    impl Dispatch<wl_shell::WlShell, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_shell::WlShell,
            _event: wl_shell::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {}
    }
    impl Dispatch<wl_shell_surface::WlShellSurface, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &wl_shell_surface::WlShellSurface,
            _event: wl_shell_surface::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {}
    }

    // xdg toplevel handlers: respond to ping, no-op for surface/toplevel events
    impl Dispatch<xdg_wm_base::XdgWmBase, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            proxy: &xdg_wm_base::XdgWmBase,
            event: xdg_wm_base::Event,
            _data: &(),
            conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {
            if let xdg_wm_base::Event::Ping { serial } = event {
                // reply pong
                let _ = proxy.pong(serial);
                // flush to ensure delivery
                let _ = conn.flush();
            }
        }
    }
    impl Dispatch<xdg_surface::XdgSurface, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            proxy: &xdg_surface::XdgSurface,
            event: xdg_surface::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {
            if let xdg_surface::Event::Configure { serial } = event {
                // Acknowledge configure so the compositor can map the surface
                let _ = proxy.ack_configure(serial);
                let _ = _conn.flush();
                println!("libkagami: xdg_surface configure acked (serial={})", serial);
            }
        }
    }
    impl Dispatch<xdg_toplevel::XdgToplevel, ()> for RegistryState {
        fn event(
            _state: &mut RegistryState,
            _proxy: &xdg_toplevel::XdgToplevel,
            _event: xdg_toplevel::Event,
            _data: &(),
            _conn: &Connection,
            _qh: &QueueHandle<RegistryState>,
        ) {}
    }

    fn connect_wayland() -> Result<(Connection, EventQueue<RegistryState>, GlobalList), String> {
        let conn = Connection::connect_to_env().map_err(|e| format!("Wayland connect failed: {}", e))?;
        let (globals, event_queue) = registry_queue_init::<RegistryState>(&conn)
            .map_err(|e| format!("registry init failed: {:?}", e))?;
        Ok((conn, event_queue, globals))
    }

    /// wl_shm を使って匿名ファイル + mmap を作り、Pool と Buffer を返す。
    /// 返り値: (tempfile, mmap, pool, buffer)
    fn create_shm_buffer(
        shm: &wl_shm::WlShm,
        qh: &QueueHandle<RegistryState>,
        width: i32,
        height: i32,
    ) -> Result<(File, MmapMut, WlShmPool, wl_buffer::WlBuffer), String> {
        let stride = (width * 4) as usize;
        let size = stride.checked_mul(height as usize).ok_or("size overflow")?;

        // 匿名テンポラリファイルを作る
        let tmp = tempfile().map_err(|e| format!("tempfile failed: {}", e))?;
        tmp.set_len(size as u64)
            .map_err(|e| format!("set_len failed: {}", e))?;

        // mmap
        let mmap = unsafe { MmapMut::map_mut(&tmp).map_err(|e| format!("mmap failed: {}", e))? };

        // pool と buffer
        let fd = tmp.as_raw_fd();
        // create BorrowedFd from raw fd
        let bfd = unsafe { BorrowedFd::borrow_raw(fd) };
        // Attempt to create pool/buffer using current API (requires QueueHandle)
        let pool = shm.create_pool(bfd, size as i32, qh, ());
        // Use XRGB8888 to avoid alpha blending issues on compositors that ignore alpha
        let buffer = pool.create_buffer(0, width, height, stride as i32, Format::Xrgb8888, qh, ());

        Ok((tmp, mmap, pool, buffer))
    }


    /// 高レベル表示管理: compositor/shm および EventQueue を保持する
    pub struct HostDisplay {
        conn: Connection,
        event_queue: EventQueue<RegistryState>,
        globals: GlobalList,
        compositor: wl_compositor::WlCompositor,
        shm: wl_shm::WlShm,
    }

    // Helper to register input handlers
    #[allow(dead_code)]
    pub fn register_pointer_and_keyboard(
        host: &mut HostDisplay,
        pointer_cb: Option<Arc<dyn Fn(f64,f64) + Send + Sync>>,
        keyboard_cb: Option<Arc<dyn Fn(u32, wayland_client::WEnum<wl_keyboard::KeyState>) + Send + Sync>>,
    ) -> Result<(), String> {
        let qh = host.event_queue.handle();
        // bind seat
        let seat = host.globals.bind::<wl_seat::WlSeat, RegistryState, ()>(&qh, 1..=1, ())
            .map_err(|_| "seat not available".to_string())?;
        if let Some(pcb) = pointer_cb {
            let ud = Arc::new(PointerHandler(pcb));
            let _pointer = seat.get_pointer(&qh, ud.clone());
        }
        if let Some(kcb) = keyboard_cb {
            let ud = Arc::new(KeyboardHandler(kcb));
            let _kb = seat.get_keyboard(&qh, ud.clone());
        }
        Ok(())
    }

    impl HostDisplay {
        /// Wayland 接続して必要なグローバル（compositor, shm）まで取得する
        pub fn new() -> Result<Self, String> {
            let (conn, event_queue, globals) = connect_wayland()?;
            // obtain a queue handle for binding
            let qh = event_queue.handle();
            // 主要なグローバルを取得
            let compositor = globals
                .bind::<wl_compositor::WlCompositor, RegistryState, ()>(&qh, 1..=4, ())
                .map_err(|_| "Compositor not available".to_string())?;
            let shm = globals
                .bind::<wl_shm::WlShm, RegistryState, ()>(&qh, 1..=1, ())
                .map_err(|_| "wl_shm not available".to_string())?;
            println!("libkagami: connected to compositor and wl_shm");
            Ok(HostDisplay { conn, event_queue, globals, compositor, shm })
        }

        /// イベントのディスパッチを行う（呼び出し側でループする）
        pub fn dispatch(&mut self) -> Result<(), String> {
            let mut st = RegistryState;
            self.event_queue
                .dispatch_pending(&mut st)
                .map(|_| ())
                .map_err(|e| format!("dispatch failed: {}", e))
        }

        /// 新しい surface と double-buffer を作る
        pub fn create_surface(&mut self, width: i32, height: i32) -> Result<HostSurface, String> {
            let qh = self.event_queue.handle();
            let surface = self.compositor.create_surface(&qh, ());
            // create buffers
            let (tmp0, mmap0, _pool0, buffer0) = create_shm_buffer(&self.shm, &qh, width, height)?;
            let (tmp1, mmap1, _pool1, buffer1) = create_shm_buffer(&self.shm, &qh, width, height)?;
            let hs = HostSurface {
                surface,
                conn: self.conn.clone(),
                qh,
                width,
                height,
                stride: (width * 4) as usize,
                mmap0,
                mmap1,
                _tmp0: tmp0,
                _tmp1: tmp1,
                buffer0,
                buffer1,
                front: 0,
            };
            // Do not attach a buffer yet when creating the surface. When using xdg,
            // attaching a buffer before the xdg_surface configure is an error on some compositors.
            println!("libkagami: created surface ({}x{}), buffers allocated", width, height);
            Ok(hs)
        }

        /// Try to make a surface a toplevel using wl_shell (best-effort)
        pub fn set_toplevel(&mut self, hs: &mut HostSurface) -> Result<(), String> {
            let qh = self.event_queue.handle();
            // Prefer xdg_wm_base (modern) if available
            if let Ok(xdg) = self.globals.bind::<xdg_wm_base::XdgWmBase, RegistryState, ()>(&qh, 1..=1, ()) {
                let xsurf = xdg.get_xdg_surface(&hs.surface, &qh, ());
                let toplevel = xsurf.get_toplevel(&qh, ());
                // set title and app_id for compositor policies
                let _ = toplevel.set_title("ViewKit".to_string());
                let _ = toplevel.set_app_id("ViewKit".to_string());
                // hint min size to avoid some compositors refusing to map
                let _ = toplevel.set_min_size(hs.width, hs.height);
                // Commit role assignment; do not attach a buffer until we receive and ack the
                // xdg_surface.configure event, otherwise some compositors will error.
                hs.surface.commit();
                self.conn.flush().map_err(|e| format!("conn flush failed: {}", e))?;
                // Wait for compositor to send configure and our Dispatch will ack it.
                let mut st = RegistryState;
                let _ = self.event_queue.roundtrip(&mut st).map_err(|e| format!("roundtrip failed: {}", e))?;
                // After configure/ack, ensure the buffer we rendered into becomes the
                // front buffer and is attached. Use swap_and_commit which flips the
                // back buffer into front and commits it.
                hs.swap_and_commit().map_err(|e| format!("initial buffer attach failed: {}", e))?;
                println!("libkagami: requested xdg_wm_base xdg_surface/xdg_toplevel and attached buffer (via swap)");
                return Ok(());
            }
            // fallback to wl_shell
            match self.globals.bind::<wl_shell::WlShell, RegistryState, ()>(&qh, 1..=1, ()) {
                Ok(wl_shell) => {
                    let shell_surface = wl_shell.get_shell_surface(&hs.surface, &qh, ());
                    shell_surface.set_toplevel();
                    self.conn.flush().map_err(|e| format!("conn flush failed: {}", e))?;
                    println!("libkagami: requested wl_shell.set_toplevel");
                    Ok(())
                }
                Err(_) => {
                    println!("libkagami: no toplevel protocol available; surface may not be mapped as window");
                    Ok(())
                }
            }
        }
    }

    /// Surface と double-buffer の小さなラッパ
    pub struct HostSurface {
        surface: WlSurface,
        conn: Connection,
        qh: QueueHandle<RegistryState>,
        width: i32,
        height: i32,
        stride: usize,
        mmap0: MmapMut,
        mmap1: MmapMut,
        _tmp0: File,
        _tmp1: File,
        buffer0: wl_buffer::WlBuffer,
        buffer1: wl_buffer::WlBuffer,
        front: usize,
    }

    impl HostSurface {
        /// Width accessor
        pub fn width(&self) -> i32 { self.width }
        /// Height accessor
        pub fn height(&self) -> i32 { self.height }
        /// Stride accessor
        pub fn stride(&self) -> usize { self.stride }

        /// 書き込み可能バッファスライスを取得
        pub fn back_buffer_mut(&mut self) -> &mut [u8] {
            if self.front == 0 { &mut self.mmap1[..] } else { &mut self.mmap0[..] }
        }

        /// 現在のフロントを attach + commit する
        pub fn commit_front(&mut self) -> Result<(), String> {
            if self.front == 0 {
                self.surface.attach(Some(&self.buffer0), 0, 0);
                self.front = 0;
            } else {
                self.surface.attach(Some(&self.buffer1), 0, 0);
                self.front = 1;
            }
            self.surface.damage_buffer(0, 0, self.width, self.height);
            self.surface.commit();
            let res = self.conn.flush().map_err(|e| format!("conn flush failed: {}", e));
            match self.front {
                0 => println!("libkagami: commit_front -> front=0 attached buffer0"),
                1 => println!("libkagami: commit_front -> front=1 attached buffer1"),
                _ => println!("libkagami: commit_front -> front={} (unknown)", self.front),
            }
            res
        }

        /// バッファをスワップして commit（back を front にする）
        pub fn swap_and_commit(&mut self) -> Result<(), String> {
            if self.front == 0 {
                // front 0 -> use buffer1 as new front
                self.mmap1.flush().map_err(|e| format!("mmap flush failed: {}", e))?;
                self.surface.attach(Some(&self.buffer1), 0, 0);
                self.front = 1;
            } else {
                self.mmap0.flush().map_err(|e| format!("mmap flush failed: {}", e))?;
                self.surface.attach(Some(&self.buffer0), 0, 0);
                self.front = 0;
            }
            self.surface.damage_buffer(0, 0, self.width, self.height);
            self.surface.commit();
            let res = self.conn.flush().map_err(|e| format!("conn flush failed: {}", e));
            match self.front {
                0 => println!("libkagami: swap_and_commit -> front=0 attached buffer0"),
                1 => println!("libkagami: swap_and_commit -> front=1 attached buffer1"),
                _ => println!("libkagami: swap_and_commit -> front={} (unknown)", self.front),
            }
            res
        }

        /// request a frame callback; provided AtomicBool is set true when done
        pub fn request_frame(&mut self, flag: Arc<AtomicBool>) -> Result<(), String> {
            // create frame callback with AtomicBool userdata so RegistryState::Dispatch handles Done
            let cb = self.surface.frame(&self.qh, flag.clone());
            let _ = cb;
            Ok(())
        }
    }

    // エクスポート
    pub use HostDisplay as host_HostDisplay;
    pub use HostSurface as host_HostSurface;
}

#[cfg(all(unix, target_os = "linux", target_env = "musl"))]
mod mochi_impl {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use swiftlib::ipc::{ipc_recv, ipc_send};
    use swiftlib::privileged;
    use swiftlib::task::{find_process_by_name, yield_now};
    use wayland_client::WEnum;
    use wayland_client::protocol::wl_keyboard;

    const IPC_BUF_SIZE: usize = 4128;
    const KAGAMI_PROCESS_CANDIDATES: [&str; 3] =
        ["/Applications/Kagami.app/entry.elf", "Kagami.app", "entry.elf"];

    const OP_REQ_CREATE_WINDOW: u32 = 1;
    const OP_RES_WINDOW_CREATED: u32 = 2;
    const OP_REQ_ATTACH_SHARED: u32 = 5;
    const OP_REQ_PRESENT_SHARED: u32 = 6;
    const OP_RES_SHARED_ATTACHED: u32 = 7;
    const LAYER_APP: u8 = 1;

    struct SharedSurface {
        virt_addr: u64,
        page_count: u64,
        total_pixels: usize,
    }

    pub struct HostDisplay {
        kagami_tid: u64,
        ipc_buf: [u8; IPC_BUF_SIZE],
    }

    pub struct HostSurface {
        kagami_tid: u64,
        window_id: u32,
        width: i32,
        height: i32,
        stride: usize,
        front: usize,
        back0: Vec<u8>,
        back1: Vec<u8>,
        shared: SharedSurface,
    }

    pub fn register_pointer_and_keyboard(
        _host: &mut HostDisplay,
        _pointer_cb: Option<Arc<dyn Fn(f64, f64) + Send + Sync>>,
        _keyboard_cb: Option<Arc<dyn Fn(u32, WEnum<wl_keyboard::KeyState>) + Send + Sync>>,
    ) -> Result<(), String> {
        Ok(())
    }

    impl HostDisplay {
        pub fn new() -> Result<Self, String> {
            let kagami_tid = parse_kagami_tid_from_args()
                .or_else(find_kagami_tid)
                .ok_or("Kagami not found; pass --kagami-tid=<tid> or launch from Kagami".to_string())?;
            Ok(Self {
                kagami_tid,
                ipc_buf: [0u8; IPC_BUF_SIZE],
            })
        }

        pub fn dispatch(&mut self) -> Result<(), String> {
            let _ = ipc_recv(&mut self.ipc_buf);
            yield_now();
            Ok(())
        }

        pub fn create_surface(&mut self, width: i32, height: i32) -> Result<HostSurface, String> {
            if width <= 0 || height <= 0 {
                return Err("invalid surface size".into());
            }
            let window_id = create_window(self.kagami_tid, width as u16, height as u16)?;
            let shared = request_shared_surface(
                self.kagami_tid,
                &mut self.ipc_buf,
                window_id,
                width as u16,
                height as u16,
            )?;
            let size = (width as usize)
                .checked_mul(height as usize)
                .and_then(|v| v.checked_mul(4))
                .ok_or("surface size overflow")?;
            Ok(HostSurface {
                kagami_tid: self.kagami_tid,
                window_id,
                width,
                height,
                stride: width as usize * 4,
                front: 0,
                back0: vec![0; size],
                back1: vec![0; size],
                shared,
            })
        }

        pub fn set_toplevel(&mut self, hs: &mut HostSurface) -> Result<(), String> {
            hs.present().map_err(|e| format!("present failed: {}", e))
        }
    }

    impl HostSurface {
        pub fn width(&self) -> i32 { self.width }
        pub fn height(&self) -> i32 { self.height }
        pub fn stride(&self) -> usize { self.stride }

        pub fn back_buffer_mut(&mut self) -> &mut [u8] {
            if self.front == 0 {
                &mut self.back1
            } else {
                &mut self.back0
            }
        }

        pub fn commit_front(&mut self) -> Result<(), String> {
            self.present()
                .map_err(|e| format!("present(front={}) failed: {}", self.front, e))
        }

        pub fn swap_and_commit(&mut self) -> Result<(), String> {
            self.front = if self.front == 0 { 1 } else { 0 };
            self.present()
                .map_err(|e| format!("present(swap front={}) failed: {}", self.front, e))
        }

        pub fn request_frame(&mut self, flag: Arc<AtomicBool>) -> Result<(), String> {
            flag.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn present(&self) -> Result<(), &'static str> {
            let src = if self.front == 0 {
                &self.back0
            } else {
                &self.back1
            };
            blit_shared_surface(&self.shared, src);
            present_shared(self.kagami_tid, self.window_id)?;
            Ok(())
        }
    }

    fn create_window(kagami_tid: u64, width: u16, height: u16) -> Result<u32, String> {
        let mut req = [0u8; 9];
        req[0..4].copy_from_slice(&OP_REQ_CREATE_WINDOW.to_le_bytes());
        req[4..6].copy_from_slice(&width.to_le_bytes());
        req[6..8].copy_from_slice(&height.to_le_bytes());
        req[8] = LAYER_APP;
        if (ipc_send(kagami_tid, &req) as i64) < 0 {
            return Err("send create window failed".into());
        }

        let mut recv = [0u8; IPC_BUF_SIZE];
        for _ in 0..512 {
            let (sender, len) = ipc_recv(&mut recv);
            if sender != kagami_tid || len < 8 {
                yield_now();
                continue;
            }
            let op = u32::from_le_bytes([recv[0], recv[1], recv[2], recv[3]]);
            if op != OP_RES_WINDOW_CREATED {
                continue;
            }
            let window_id = u32::from_le_bytes([recv[4], recv[5], recv[6], recv[7]]);
            return Ok(window_id);
        }
        Err("window create timeout".into())
    }

    fn request_shared_surface(
        kagami_tid: u64,
        ipc_buf: &mut [u8; IPC_BUF_SIZE],
        window_id: u32,
        width: u16,
        height: u16,
    ) -> Result<SharedSurface, String> {
        let total = (width as usize)
            .checked_mul(height as usize)
            .ok_or("size overflow")?;
        let total_bytes = total.checked_mul(4).ok_or("size overflow")?;
        let page_count = total_bytes.div_ceil(4096);
        if page_count == 0 {
            return Err("page_count was zero".into());
        }

        let mut phys_pages = vec![0u64; page_count];
        let virt_addr = unsafe {
            privileged::alloc_shared_pages(page_count as u64, Some(phys_pages.as_mut_slice()), 0)
        };
        if (virt_addr as i64) < 0 || virt_addr == 0 {
            return Err("alloc_shared_pages failed".into());
        }

        let mut attach = [0u8; 12];
        attach[0..4].copy_from_slice(&OP_REQ_ATTACH_SHARED.to_le_bytes());
        attach[4..8].copy_from_slice(&window_id.to_le_bytes());
        attach[8..10].copy_from_slice(&width.to_le_bytes());
        attach[10..12].copy_from_slice(&height.to_le_bytes());
        if (ipc_send(kagami_tid, &attach) as i64) < 0 {
            return Err("send attach request failed".into());
        }
        let send_pages_ret = unsafe { privileged::ipc_send_pages(kagami_tid, phys_pages.as_slice(), 0) };
        if (send_pages_ret as i64) < 0 {
            return Err("ipc_send_pages failed".into());
        }

        for _ in 0..512 {
            let (sender, len) = ipc_recv(ipc_buf);
            if sender != kagami_tid || len < 8 {
                yield_now();
                continue;
            }
            let op = u32::from_le_bytes([ipc_buf[0], ipc_buf[1], ipc_buf[2], ipc_buf[3]]);
            if op != OP_RES_SHARED_ATTACHED {
                continue;
            }
            let ack_window = u32::from_le_bytes([ipc_buf[4], ipc_buf[5], ipc_buf[6], ipc_buf[7]]);
            if ack_window == window_id {
                return Ok(SharedSurface {
                    virt_addr,
                    page_count: page_count as u64,
                    total_pixels: total,
                });
            }
        }

        Err("shared attach ack timeout".into())
    }

    fn blit_shared_surface(surface: &SharedSurface, src_rgba_bytes: &[u8]) {
        let src_pixels = src_rgba_bytes.len() / 4;
        let mapped_pixels = (surface.page_count as usize).saturating_mul(4096) / 4;
        let count = surface.total_pixels.min(src_pixels).min(mapped_pixels);
        unsafe {
            let dst = core::slice::from_raw_parts_mut(surface.virt_addr as *mut u32, count);
            for (i, d) in dst.iter_mut().enumerate() {
                let base = i * 4;
                let b = src_rgba_bytes[base] as u32;
                let g = src_rgba_bytes[base + 1] as u32;
                let r = src_rgba_bytes[base + 2] as u32;
                *d = 0xFF00_0000 | (r << 16) | (g << 8) | b;
            }
        }
    }

    fn present_shared(kagami_tid: u64, window_id: u32) -> Result<(), &'static str> {
        let mut present = [0u8; 8];
        present[0..4].copy_from_slice(&OP_REQ_PRESENT_SHARED.to_le_bytes());
        present[4..8].copy_from_slice(&window_id.to_le_bytes());
        if (ipc_send(kagami_tid, &present) as i64) < 0 {
            return Err("send present failed");
        }
        Ok(())
    }

    fn find_kagami_tid() -> Option<u64> {
        for name in KAGAMI_PROCESS_CANDIDATES {
            if let Some(tid) = find_process_by_name(name) {
                return Some(tid);
            }
        }
        None
    }

    fn parse_kagami_tid_from_args() -> Option<u64> {
        for arg in std::env::args().skip(1) {
            if let Some(rest) = arg.strip_prefix("--kagami-tid=")
                && let Ok(tid) = rest.parse::<u64>()
                && tid != 0
            {
                return Some(tid);
            }
        }
        None
    }

    pub use HostDisplay as host_HostDisplay;
    pub use HostSurface as host_HostSurface;
}

#[cfg(not(any(
    all(unix, target_os = "linux", target_env = "gnu"),
    all(unix, target_os = "linux", target_env = "musl")
)))]
mod stub_impl {
    // mochiOS向けスタブ
    pub fn host_connect_wayland() -> Result<(), String> {
        Err("libkagami host shim is only available on unix hosts".into())
    }
    pub fn host_create_shm_buffer(_: &(), _: i32, _: i32) -> Result<(), String> {
        Err("libkagami host shim is only available on unix hosts".into())
    }
}

#[cfg(not(any(
    all(unix, target_os = "linux", target_env = "gnu"),
    all(unix, target_os = "linux", target_env = "musl")
)))]
pub use stub_impl::*;
// 公開インターフェース
#[cfg(all(unix, target_os = "linux", target_env = "gnu"))]
pub use unix_impl::{host_HostDisplay, host_HostSurface, register_pointer_and_keyboard};
#[cfg(all(unix, target_os = "linux", target_env = "musl"))]
pub use mochi_impl::{host_HostDisplay, host_HostSurface, register_pointer_and_keyboard};
