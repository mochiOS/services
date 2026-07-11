#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::arch::global_asm;
use mochi_user_platform as platform;

global_asm!(
    r#"
    .global _start
_start:
    xor rbp, rbp
    mov rdi, rsp
    and rsp, -16
    call service_main
1:
    hlt
    jmp 1b
"#
);

const DISPLAY_SERVICE_NAME: &str = "display.driver";
const INPUT_SERVICE_NAME: &str = "input.service";
const OP_CREATE_SURFACE: u32 = 1;
const OP_ATTACH_BUFFER: u32 = 2;
const OP_DAMAGE: u32 = 3;
const OP_COMMIT: u32 = 4;
const OP_SET_POSITION: u32 = 5;
const OP_DESTROY_SURFACE: u32 = 6;
const OP_DECOR_SUBSCRIBE: u32 = 100;
const OP_DECOR_CREATE_SURFACE: u32 = 101;
const OP_DECOR_ATTACH: u32 = 102;
const OP_DECOR_DETACH: u32 = 103;
const OP_DECOR_UPDATE_INSETS: u32 = 104;
const OP_DECOR_BEGIN_MOVE: u32 = 105;
const OP_DECOR_BEGIN_RESIZE: u32 = 106;
const OP_DECOR_MINIMIZE: u32 = 107;
const OP_DECOR_TOGGLE_MAXIMIZE: u32 = 108;
const OP_DECOR_CLOSE_REQUEST: u32 = 109;
const OP_DISPLAY_GET_INFO: u32 = 1;
const OP_DISPLAY_PRESENT: u32 = 2;
const DECOR_EVENT_WINDOW: u32 = 0x5749_4e44;
const EVENT_POINTER_ENTER: u32 = 2;
const EVENT_POINTER_LEAVE: u32 = 3;
const EVENT_POINTER_MOTION: u32 = 4;
const EVENT_POINTER_BUTTON: u32 = 5;
const EVENT_KEY: u32 = 6;
const EVENT_FOCUS_GAINED: u32 = 8;
const EVENT_FOCUS_LOST: u32 = 9;
const EVENT_FRAME_DONE: u32 = 10;
const ROLE_TOPLEVEL: u32 = 1;
const ROLE_POPUP: u32 = 2;
const ROLE_BACKGROUND: u32 = 3;
const ROLE_PANEL: u32 = 4;
const ROLE_SECURE_OVERLAY: u32 = 5;
const PIXEL_FORMAT_XRGB8888: u32 = 1;
const MAX_SURFACES: usize = 16;
const MAX_WINDOWS: usize = 8;
const MAX_CLIENTS: usize = 16;
const PAGE_SIZE: usize = 4096;
const MAX_SHARED_PAGES: usize = 262_144;
const MAX_SHARED_BYTES: usize = MAX_SHARED_PAGES * PAGE_SIZE;
const MAX_SHARED_PIXELS: usize = MAX_SHARED_BYTES / 4;
const MAX_DIMENSION: u32 = 16_384;
const IDLE_CLEANUP_YIELDS: u32 = 64;
const DECORATE_CAPABILITY: &str = "window.decorate";
const DECORATE_COMPAT_CAPABILITY: &str = "window.overlay";
const CURSOR_ICON_PATH: &str = "/system/icons/cursor.svg";
const DEFAULT_CURSOR_WIDTH: u32 = 24;
const DEFAULT_CURSOR_HEIGHT: u32 = 24;
const WINDOW_STATE_NORMAL: u32 = 0;
const WINDOW_STATE_MINIMIZED: u32 = 1;
const WINDOW_STATE_MAXIMIZED: u32 = 2;
const DECOR_TITLE_BAR_HEIGHT: u32 = 28;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct ClientId(u64);

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct SurfaceHandle(u64);

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct WindowId(u64);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SurfaceRole {
    Toplevel,
    Popup,
    Background,
    Panel,
    SecureOverlay,
}

impl SurfaceRole {
    fn from_wire(value: u32) -> Result<Self, u32> {
        match value {
            ROLE_TOPLEVEL => Ok(Self::Toplevel),
            ROLE_POPUP => Ok(Self::Popup),
            ROLE_BACKGROUND => Ok(Self::Background),
            ROLE_PANEL => Ok(Self::Panel),
            ROLE_SECURE_OVERLAY => Ok(Self::SecureOverlay),
            _ => Err(errno_status(mochi_user_syscall::EINVAL)),
        }
    }

    fn general_client_rights(self) -> Result<SurfaceRights, u32> {
        match self {
            Self::Toplevel | Self::Popup => Ok(SurfaceRights::GENERAL_CLIENT),
            Self::Background | Self::Panel | Self::SecureOverlay => {
                Err(errno_status(mochi_user_syscall::EACCES))
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct SurfaceRights {
    bits: u32,
}

impl SurfaceRights {
    const ATTACH_BUFFER: Self = Self { bits: 1 << 0 };
    const DAMAGE: Self = Self { bits: 1 << 1 };
    const COMMIT: Self = Self { bits: 1 << 2 };
    const DESTROY: Self = Self { bits: 1 << 3 };
    #[allow(dead_code)]
    const SET_POSITION: Self = Self { bits: 1 << 4 };
    #[allow(dead_code)]
    const SET_Z_ORDER: Self = Self { bits: 1 << 5 };
    #[allow(dead_code)]
    const FOCUS_CONTROL: Self = Self { bits: 1 << 6 };
    const GENERAL_CLIENT: Self = Self {
        bits: Self::ATTACH_BUFFER.bits | Self::DAMAGE.bits | Self::COMMIT.bits | Self::DESTROY.bits,
    };

    const fn contains(self, required: Self) -> bool {
        (self.bits & required.bits) == required.bits
    }
}

#[derive(Clone, Copy, Default)]
struct Client {
    live: bool,
    sender: u64,
    id: ClientId,
    decoration_endpoint: u64,
}

#[derive(Clone, Copy, Default)]
struct Insets {
    left: u32,
    top: u32,
    right: u32,
    bottom: u32,
}

#[derive(Clone, Copy, Default)]
struct Window {
    live: bool,
    id: WindowId,
    token: u64,
    content: SurfaceHandle,
    decoration: Option<SurfaceHandle>,
    decorator: ClientId,
    decorator_endpoint: u64,
    insets: Insets,
    state: u32,
    resizable: bool,
    close_requested: bool,
    metadata_sent: bool,
}

impl Window {
    const fn empty() -> Self {
        Self {
            live: false,
            id: WindowId(0),
            token: 0,
            content: SurfaceHandle(0),
            decoration: None,
            decorator: ClientId(0),
            decorator_endpoint: 0,
            insets: Insets {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            state: WINDOW_STATE_NORMAL,
            resizable: true,
            close_requested: false,
            metadata_sent: false,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct PointerSerial {
    serial: u64,
    window: WindowId,
    decoration: SurfaceHandle,
    used: bool,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
struct Rect {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

impl Rect {
    const fn full(width: u32, height: u32) -> Self {
        Self {
            x: 0,
            y: 0,
            width,
            height,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
struct Point {
    x: i32,
    y: i32,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
struct PopupPlacement {
    anchor_rect: Rect,
    offset: Point,
}

#[derive(Clone)]
struct SurfaceBuffer {
    mapped_addr: u64,
    byte_len: usize,
    width: u32,
    height: u32,
    stride: u32,
    pixels: usize,
}

#[derive(Clone)]
struct Surface {
    live: bool,
    owner: ClientId,
    event_endpoint: u64,
    handle: SurfaceHandle,
    token: u64,
    role: SurfaceRole,
    rights: SurfaceRights,
    parent: Option<SurfaceHandle>,
    window: WindowId,
    is_decoration: bool,
    visible: bool,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    pending_width: u32,
    pending_height: u32,
    pending_stride: u32,
    pending_len: usize,
    pending_bytes_received: usize,
    awaiting_buffer: bool,
    pending_damage: Option<Rect>,
    pending_buffer: Option<SurfaceBuffer>,
    pending: Vec<u32>,
    current_width: u32,
    current_height: u32,
    current_stride: u32,
    current_buffer: Option<SurfaceBuffer>,
    current: Vec<u32>,
    z: u32,
}

struct CursorImage {
    width: u32,
    height: u32,
    hotspot_x: i32,
    hotspot_y: i32,
    pixels: Vec<u32>,
}

impl Surface {
    fn empty() -> Self {
        Self {
            live: false,
            owner: ClientId(0),
            event_endpoint: 0,
            handle: SurfaceHandle(0),
            token: 0,
            role: SurfaceRole::Toplevel,
            rights: SurfaceRights::default(),
            parent: None,
            window: WindowId(0),
            is_decoration: false,
            visible: true,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            pending_width: 0,
            pending_height: 0,
            pending_stride: 0,
            pending_len: 0,
            pending_bytes_received: 0,
            awaiting_buffer: false,
            pending_damage: None,
            pending_buffer: None,
            pending: Vec::new(),
            current_width: 0,
            current_height: 0,
            current_stride: 0,
            current_buffer: None,
            current: Vec::new(),
            z: 0,
        }
    }

    fn reset(&mut self) {
        self.live = false;
        self.owner = ClientId(0);
        self.event_endpoint = 0;
        self.handle = SurfaceHandle(0);
        self.token = 0;
        self.role = SurfaceRole::Toplevel;
        self.rights = SurfaceRights::default();
        self.parent = None;
        self.window = WindowId(0);
        self.is_decoration = false;
        self.visible = true;
        self.x = 0;
        self.y = 0;
        self.width = 0;
        self.height = 0;
        self.pending_width = 0;
        self.pending_height = 0;
        self.pending_stride = 0;
        self.pending_len = 0;
        self.pending_bytes_received = 0;
        self.awaiting_buffer = false;
        self.pending_damage = None;
        self.pending_buffer = None;
        self.pending.clear();
        self.current_width = 0;
        self.current_height = 0;
        self.current_stride = 0;
        self.current_buffer = None;
        self.current.clear();
        self.z = 0;
    }
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_pixel(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

static mut DISPLAY_REQ_BUF: [u8; 20] = [0; 20];
static mut DISPLAY_REP_BUF: [u8; 32] = [0; 32];
static mut DISPLAY_PRESENT_REQ: [u8; 20] = [0; 20];
static mut INPUT_SUBSCRIBE_REQ: [u8; 16] = [0; 16];
static mut INPUT_SUBSCRIBE_REP: [u8; 8] = [0; 8];
static mut TOKEN_RANDOM_BUF: [u8; 8] = [0; 8];
static mut IPC_BUF: [u8; 4128] = [0; 4128];

fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let bytes = buf.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn getrandom_u64() -> Option<u64> {
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(TOKEN_RANDOM_BUF).cast::<u8>(), 8)
    };
    let len = match mochi_user_syscall::call3(
        mochi_user_syscall::SyscallNumber::Getrandom,
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
        0,
    ) {
        Ok(len) => len,
        Err(err) => {
            platform::println!(
                "compositor.service: getrandom failed errno={}",
                err.errno().unwrap_or(0)
            );
            return None;
        }
    };
    if len == bytes.len() as u64 {
        Some(u64::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    } else {
        platform::println!("compositor.service: getrandom short read len={}", len);
        None
    }
}

fn sleep_one_tick() {
    let _ = mochi_user_syscall::call1(mochi_user_syscall::SyscallNumber::Sleep, 1);
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn errno_status(errno: u64) -> u32 {
    let signed = errno as i64;
    if signed < 0 {
        signed.wrapping_neg() as u32
    } else {
        errno as u32
    }
}

fn put_i32(out: &mut [u8], offset: usize, value: i32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn sender_has_decorate_capability(sender: u64) -> bool {
    matches!(
        platform::capability::check_thread(sender, DECORATE_CAPABILITY),
        Ok(1)
    ) || matches!(
        platform::capability::check_thread(sender, DECORATE_COMPAT_CAPABILITY),
        Ok(1)
    )
}

fn decode_display_info(reply: &[u8]) -> Option<(u32, u32, u32, u32)> {
    if reply.len() < 20 {
        return None;
    }
    let status = read_u32(reply, 0)?;
    if status != 0 {
        return None;
    }
    Some((
        read_u32(reply, 4)?,
        read_u32(reply, 8)?,
        read_u32(reply, 12)?,
        read_u32(reply, 16)?,
    ))
}

fn display_request_info(display_tid: u64) -> (u32, u32, u32, u32) {
    let req = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REQ_BUF).cast::<u8>(), 20)
    };
    req.fill(0);
    put_u32(req, 0, OP_DISPLAY_GET_INFO);
    let reply = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REP_BUF).cast::<u8>(), 32)
    };
    reply.fill(0);
    if let Ok(msg) = platform::ipc::call(display_tid, req, reply) {
        let len = (msg & 0xffff_ffff) as usize;
        if let Some(info) = decode_display_info(&reply[..len.min(reply.len())]) {
            return info;
        }
    }
    (640, 480, 640, PIXEL_FORMAT_XRGB8888)
}

fn ascii_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
}

fn find_byte(bytes: &[u8], needle: u8) -> Option<usize> {
    bytes.iter().position(|&byte| byte == needle)
}

fn attr_value<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0usize;
    while pos < tag.len() {
        while pos < tag.len() && !ascii_ws(tag[pos]) {
            pos += 1;
        }
        while pos < tag.len() && ascii_ws(tag[pos]) {
            pos += 1;
        }
        if pos >= tag.len() {
            break;
        }
        let key_start = pos;
        while pos < tag.len() && tag[pos] != b'=' && !ascii_ws(tag[pos]) && tag[pos] != b'/' {
            pos += 1;
        }
        let key_end = pos;
        while pos < tag.len() && ascii_ws(tag[pos]) {
            pos += 1;
        }
        if pos >= tag.len() || tag[pos] != b'=' {
            continue;
        }
        pos += 1;
        while pos < tag.len() && ascii_ws(tag[pos]) {
            pos += 1;
        }
        if pos >= tag.len() || (tag[pos] != b'"' && tag[pos] != b'\'') {
            continue;
        }
        let quote = tag[pos];
        pos += 1;
        let value_start = pos;
        while pos < tag.len() && tag[pos] != quote {
            pos += 1;
        }
        let value_end = pos;
        if pos < tag.len() {
            pos += 1;
        }
        if &tag[key_start..key_end] == name {
            return Some(&tag[value_start..value_end]);
        }
    }
    None
}

fn parse_u32_attr(tag: &[u8], name: &[u8]) -> Option<u32> {
    let value = attr_value(tag, name)?;
    let mut out = 0u32;
    let mut saw_digit = false;
    for &byte in value {
        if byte == b'.' {
            break;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        saw_digit = true;
        out = out.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    saw_digit.then_some(out)
}

fn parse_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_fill(tag: &[u8]) -> Option<u32> {
    let value = attr_value(tag, b"fill")?;
    if value.len() != 7 || value[0] != b'#' {
        return None;
    }
    let r = parse_hex_digit(value[1])? << 4 | parse_hex_digit(value[2])?;
    let g = parse_hex_digit(value[3])? << 4 | parse_hex_digit(value[4])?;
    let b = parse_hex_digit(value[5])? << 4 | parse_hex_digit(value[6])?;
    Some(u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b))
}

fn parse_opacity_permille(value: &[u8]) -> Option<u32> {
    if value == b"1" || value == b"1.0" || value == b"1.00" {
        return Some(1000);
    }
    if value == b"0" {
        return Some(0);
    }
    if !value.starts_with(b"0.") {
        return None;
    }
    let mut out = 0u32;
    let mut scale = 100u32;
    for &byte in &value[2..] {
        if !byte.is_ascii_digit() || scale == 0 {
            break;
        }
        out = out.checked_add(u32::from(byte - b'0').checked_mul(scale)?)?;
        scale /= 10;
    }
    Some(out.min(1000))
}

fn parse_alpha(tag: &[u8]) -> u32 {
    let opacity = attr_value(tag, b"fill-opacity")
        .or_else(|| attr_value(tag, b"opacity"))
        .and_then(parse_opacity_permille)
        .unwrap_or(1000);
    ((opacity * 255) / 1000).min(255)
}

fn rasterize_svg_rects(svg: &[u8]) -> Option<CursorImage> {
    let width = parse_u32_attr(svg, b"width").unwrap_or(DEFAULT_CURSOR_WIDTH);
    let height = parse_u32_attr(svg, b"height").unwrap_or(DEFAULT_CURSOR_HEIGHT);
    if width == 0 || height == 0 || width > 128 || height > 128 {
        return None;
    }
    let pixels_len = (width as usize).checked_mul(height as usize)?;
    let mut pixels = Vec::new();
    pixels.try_reserve_exact(pixels_len).ok()?;
    pixels.resize(pixels_len, 0);

    let mut pos = 0usize;
    while let Some(rel_start) = svg[pos..].windows(5).position(|window| window == b"<rect") {
        let start = pos.checked_add(rel_start)?;
        let end = start.checked_add(find_byte(&svg[start..], b'>')?)?;
        let tag = &svg[start..=end];
        let x = parse_u32_attr(tag, b"x").unwrap_or(0);
        let y = parse_u32_attr(tag, b"y").unwrap_or(0);
        let rect_w = parse_u32_attr(tag, b"width").unwrap_or(0);
        let rect_h = parse_u32_attr(tag, b"height").unwrap_or(0);
        let Some(rgb) = parse_fill(tag) else {
            pos = end.saturating_add(1);
            continue;
        };
        let alpha = parse_alpha(tag);
        if rect_w == 0 || rect_h == 0 || alpha == 0 {
            pos = end.saturating_add(1);
            continue;
        }
        let max_y = y.saturating_add(rect_h).min(height);
        let max_x = x.saturating_add(rect_w).min(width);
        for py in y..max_y {
            let row = (py as usize).checked_mul(width as usize)?;
            for px in x..max_x {
                let index = row.checked_add(px as usize)?;
                if let Some(slot) = pixels.get_mut(index) {
                    *slot = (alpha << 24) | rgb;
                }
            }
        }
        pos = end.saturating_add(1);
    }

    if pixels.iter().all(|&pixel| pixel == 0) {
        return None;
    }

    Some(CursorImage {
        width,
        height,
        hotspot_x: parse_u32_attr(svg, b"data-hotspot-x").unwrap_or(1) as i32,
        hotspot_y: parse_u32_attr(svg, b"data-hotspot-y").unwrap_or(1) as i32,
        pixels,
    })
}

fn fallback_cursor_image() -> CursorImage {
    let width = DEFAULT_CURSOR_WIDTH;
    let height = DEFAULT_CURSOR_HEIGHT;
    let mut pixels = Vec::new();
    let len = (width as usize)
        .checked_mul(height as usize)
        .unwrap_or(DEFAULT_CURSOR_WIDTH as usize * DEFAULT_CURSOR_HEIGHT as usize);
    pixels.resize(len, 0);
    for y in 0..height {
        for x in 0..width {
            let inside = x <= y / 2 && y < 20 || (x >= 7 && x <= 10 && y >= 14 && y <= 22);
            if !inside {
                continue;
            }
            let edge =
                x == 0 || x == y / 2 || y == 19 || (x == 7 && y >= 14) || (x == 10 && y >= 14);
            let color = if edge { 0xff00_0000 } else { 0xffff_ffff };
            let index = (y as usize)
                .checked_mul(width as usize)
                .and_then(|row| row.checked_add(x as usize))
                .unwrap_or(0);
            if let Some(slot) = pixels.get_mut(index) {
                *slot = color;
            }
        }
    }
    CursorImage {
        width,
        height,
        hotspot_x: 1,
        hotspot_y: 1,
        pixels,
    }
}

fn load_cursor_image() -> CursorImage {
    platform::file::read_to_end_path(CURSOR_ICON_PATH)
        .ok()
        .and_then(|bytes| rasterize_svg_rects(&bytes))
        .unwrap_or_else(fallback_cursor_image)
}

fn find_service(name: &str) -> Option<u64> {
    for _ in 0..64 {
        if let Ok(tid) = platform::process::find_by_name(name)
            && tid != 0
        {
            return Some(tid);
        }
        platform::thread::yield_now();
    }
    None
}

fn client_id_for_sender(clients: &mut [Client], sender: u64, next_client_id: &mut u64) -> ClientId {
    if let Some(client) = clients
        .iter()
        .find(|client| client.live && client.sender == sender)
    {
        return client.id;
    }
    if let Some(client) = clients.iter_mut().find(|client| !client.live) {
        *next_client_id = next_client_id.wrapping_add(1).max(1);
        let id = ClientId(*next_client_id);
        *client = Client {
            live: true,
            sender,
            id,
            decoration_endpoint: 0,
        };
        return id;
    }
    ClientId(0)
}

fn surface_index_for(
    surfaces: &[Surface],
    client: ClientId,
    handle: SurfaceHandle,
    required: SurfaceRights,
) -> Option<usize> {
    surfaces.iter().position(|surface| {
        surface.live
            && surface.owner == client
            && surface.handle == handle
            && surface.token == handle.0
            && surface.rights.contains(required)
    })
}

fn surface_index_for_child(surfaces: &[Surface], parent: SurfaceHandle) -> Option<usize> {
    surfaces
        .iter()
        .position(|surface| surface.live && surface.parent == Some(parent))
}

fn clear_focus_for_surface(
    surfaces: &[Surface],
    index: usize,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) {
    if pointer_focus.is_some_and(|focus| focus == index) {
        if let Some(surface) = surfaces.get(index)
            && surface.live
        {
            send_event(surface.event_endpoint, EVENT_POINTER_LEAVE, 0, 0, 0);
        }
        *pointer_focus = None;
    }
    if keyboard_focus.is_some_and(|focus| focus == index) {
        update_keyboard_focus(surfaces, keyboard_focus, None);
    }
}

fn destroy_surface_tree(
    surfaces: &mut [Surface],
    windows: &mut [Window],
    index: usize,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) {
    let Some(handle) = surfaces
        .get(index)
        .filter(|surface| surface.live)
        .map(|s| s.handle)
    else {
        return;
    };
    while let Some(child) = surface_index_for_child(surfaces, handle) {
        destroy_surface_tree(surfaces, windows, child, pointer_focus, keyboard_focus);
    }
    let window_id = surfaces[index].window;
    if surfaces[index].is_decoration {
        if let Some(window_index) = window_index_by_id(windows, window_id) {
            windows[window_index].decoration = None;
            windows[window_index].decorator = ClientId(0);
            windows[window_index].decorator_endpoint = 0;
        }
    } else if let Some(window_index) = window_index_by_id(windows, window_id) {
        if let Some(decoration) = windows[window_index].decoration
            && let Some(decoration_index) = surface_index_by_handle(surfaces, decoration)
        {
            clear_focus_for_surface(surfaces, decoration_index, pointer_focus, keyboard_focus);
            surfaces[decoration_index].reset();
        }
        windows[window_index] = Window::empty();
    }
    clear_focus_for_surface(surfaces, index, pointer_focus, keyboard_focus);
    surfaces[index].reset();
}

fn cleanup_client(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    client: ClientId,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) {
    if client == ClientId(0) {
        return;
    }
    while let Some(index) = surfaces
        .iter()
        .position(|surface| surface.live && surface.owner == client && !surface.is_decoration)
    {
        destroy_surface_tree(surfaces, windows, index, pointer_focus, keyboard_focus);
    }
    while let Some(index) = surfaces
        .iter()
        .position(|surface| surface.live && surface.owner == client && surface.is_decoration)
    {
        destroy_surface_tree(surfaces, windows, index, pointer_focus, keyboard_focus);
    }
    for window in windows
        .iter_mut()
        .filter(|window| window.live && window.decorator == client)
    {
        window.decorator = ClientId(0);
        window.decorator_endpoint = 0;
    }
    if let Some(record) = clients
        .iter_mut()
        .find(|record| record.live && record.id == client)
    {
        *record = Client::default();
    }
}

fn cleanup_dead_clients(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) -> bool {
    let mut changed = false;
    for index in 0..clients.len() {
        let client = clients[index];
        if client.live && !platform::ipc::endpoint_alive(client.sender) {
            cleanup_client(
                clients,
                surfaces,
                windows,
                client.id,
                pointer_focus,
                keyboard_focus,
            );
            changed = true;
        }
    }
    changed
}

fn generate_surface_token(surfaces: &[Surface]) -> Result<u64, u32> {
    for _ in 0..16 {
        let Some(token) = getrandom_u64() else {
            return Err(errno_status(mochi_user_syscall::EIO));
        };
        if token != 0
            && surfaces
                .iter()
                .all(|surface| !surface.live || surface.token != token)
        {
            return Ok(token);
        }
    }
    Err(errno_status(mochi_user_syscall::EAGAIN))
}

fn generate_window_token(windows: &[Window]) -> Result<u64, u32> {
    for _ in 0..16 {
        let Some(token) = getrandom_u64() else {
            return Err(errno_status(mochi_user_syscall::EIO));
        };
        if token != 0
            && windows
                .iter()
                .all(|window| !window.live || window.token != token)
        {
            return Ok(token);
        }
    }
    Err(errno_status(mochi_user_syscall::EAGAIN))
}

fn window_index_by_token(windows: &[Window], token: u64) -> Option<usize> {
    windows
        .iter()
        .position(|window| window.live && window.token == token)
}

fn window_index_by_id(windows: &[Window], id: WindowId) -> Option<usize> {
    windows
        .iter()
        .position(|window| window.live && window.id == id)
}

fn surface_index_by_handle(surfaces: &[Surface], handle: SurfaceHandle) -> Option<usize> {
    surfaces
        .iter()
        .position(|surface| surface.live && surface.handle == handle && surface.token == handle.0)
}

fn content_surface_index_for_window(surfaces: &[Surface], window: &Window) -> Option<usize> {
    surface_index_by_handle(surfaces, window.content)
}

fn decoration_surface_index_for_window(surfaces: &[Surface], window: &Window) -> Option<usize> {
    surface_index_by_handle(surfaces, window.decoration?)
}

fn send_window_metadata(window: &Window, surfaces: &[Surface], endpoint: u64) {
    if endpoint == 0 || !window.live {
        return;
    }
    let Some(content_index) = content_surface_index_for_window(surfaces, window) else {
        return;
    };
    let content = &surfaces[content_index];
    let (content_width, content_height) = surface_extent(content);
    if content_width == 0 || content_height == 0 {
        return;
    }
    let mut event = [0u8; 80];
    put_u32(&mut event, 0, DECOR_EVENT_WINDOW);
    put_u64(&mut event, 4, window.token);
    put_u32(&mut event, 12, content_width);
    put_u32(&mut event, 16, content_height);
    put_u32(&mut event, 20, u32::from(window.resizable));
    put_u32(&mut event, 24, window.state);
    put_u32(&mut event, 28, window.insets.left);
    put_u32(&mut event, 32, window.insets.top);
    put_u32(&mut event, 36, window.insets.right);
    put_u32(&mut event, 40, window.insets.bottom);
    let title = b"mochiOS window";
    put_u32(&mut event, 44, title.len() as u32);
    event[48..48 + title.len()].copy_from_slice(title);
    let _ = platform::ipc::send(endpoint, &event);
}

fn notify_decorators(
    clients: &[Client],
    windows: &[Window],
    surfaces: &[Surface],
    window_index: usize,
) {
    let Some(window) = windows.get(window_index) else {
        return;
    };
    for client in clients
        .iter()
        .filter(|client| client.live && client.decoration_endpoint != 0)
    {
        send_window_metadata(window, surfaces, client.decoration_endpoint);
    }
}

fn reposition_window_surfaces(surfaces: &mut [Surface], window: &Window) {
    let Some(content_index) = content_surface_index_for_window(surfaces, window) else {
        return;
    };
    let content_x = surfaces[content_index].x;
    let content_y = surfaces[content_index].y;
    if let Some(decor_index) = decoration_surface_index_for_window(surfaces, window) {
        surfaces[decor_index].x = content_x.saturating_sub(window.insets.left as i32);
        surfaces[decor_index].y = content_y.saturating_sub(window.insets.top as i32);
    }
}

fn surface_extent(surface: &Surface) -> (u32, u32) {
    let width = if surface.current_width == 0 {
        surface.width
    } else {
        surface.current_width
    };
    let height = if surface.current_height == 0 {
        surface.height
    } else {
        surface.current_height
    };
    (width, height)
}

fn resize_buffer(buffer: &mut Vec<u32>, width: u32, height: u32) -> bool {
    let Some(len) = (width as usize).checked_mul(height as usize) else {
        return false;
    };
    buffer.clear();
    if buffer.capacity() < len && buffer.try_reserve_exact(len - buffer.capacity()).is_err() {
        return false;
    }
    buffer.resize(len, 0);
    true
}

fn surface_has_current_pixels(surface: &Surface) -> bool {
    if let Some(buffer) = &surface.current_buffer {
        return buffer.width == surface.current_width
            && buffer.height == surface.current_height
            && buffer.stride >= buffer.width
            && buffer.byte_len >= buffer.pixels.saturating_mul(4);
    }
    let Some(surface_len) =
        (surface.current_width as usize).checked_mul(surface.current_height as usize)
    else {
        return false;
    };
    surface.current.len() >= surface_len
}

fn read_current_pixel(surface: &Surface, sx: usize, sy: usize) -> Option<u32> {
    if let Some(buffer) = &surface.current_buffer {
        let stride = usize::try_from(buffer.stride).ok()?;
        let src = sy.checked_mul(stride)?.checked_add(sx)?;
        let byte_offset = src.checked_mul(4)?;
        if byte_offset.checked_add(4)? > buffer.byte_len {
            return None;
        }
        let ptr = (buffer.mapped_addr as *const u8).wrapping_add(byte_offset);
        let bytes = unsafe { core::slice::from_raw_parts(ptr, 4) };
        return Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }
    let src = sy
        .checked_mul(surface.current_stride as usize)?
        .checked_add(sx)?;
    surface.current.get(src).copied()
}

fn shared_page_count(byte_len: usize) -> Option<usize> {
    byte_len
        .checked_add(PAGE_SIZE - 1)
        .map(|len| len / PAGE_SIZE)
}

fn validate_buffer_layout(
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
    expected_width: u32,
    expected_height: u32,
) -> Result<(usize, usize, usize), u32> {
    if format != PIXEL_FORMAT_XRGB8888
        || width == 0
        || height == 0
        || stride < width
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
        || width != expected_width
        || height != expected_height
    {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let row_pixels =
        usize::try_from(stride).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let row_bytes = row_pixels
        .checked_mul(4)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let height_usize =
        usize::try_from(height).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let needed_bytes = row_bytes
        .checked_mul(height_usize)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let width_usize =
        usize::try_from(width).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let pixels = width_usize
        .checked_mul(height_usize)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    Ok((row_bytes, needed_bytes, pixels))
}

fn validate_damage_rect(rect: Rect, surface_width: u32, surface_height: u32) -> Result<Rect, u32> {
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

fn choose_frame_size(display_width: u32, display_height: u32) -> Option<(usize, usize)> {
    if display_width == 0 || display_height == 0 {
        return None;
    }
    let width = display_width.min(MAX_DIMENSION) as usize;
    let height = display_height.min(MAX_DIMENSION) as usize;
    if width.checked_mul(height)? <= MAX_SHARED_PIXELS {
        return Some((width, height));
    }
    let width = width.min(512);
    let height = height.min(MAX_SHARED_PIXELS / width).max(1);
    Some((width, height))
}

fn errno_from_platform(err: mochi_user_syscall::SysError) -> u32 {
    errno_status(err.errno().unwrap_or(mochi_user_syscall::EIO))
}

fn send_frame_done(surface: &Surface) {
    if surface.event_endpoint == 0 || surface.is_decoration {
        return;
    }
    let mut event = [0u8; 20];
    put_u32(&mut event, 0, EVENT_FRAME_DONE);
    let _ = platform::ipc::send(surface.event_endpoint, &event);
}

fn handle_shared_buffer(
    surfaces: &mut [Surface],
    client: ClientId,
    mapped_addr: u64,
    total: u64,
) -> bool {
    let Some(index) = surfaces
        .iter()
        .position(|surface| surface.live && surface.owner == client && surface.awaiting_buffer)
    else {
        return false;
    };
    let surface = &mut surfaces[index];
    let width = surface.pending_width;
    let height = surface.pending_height;
    let stride = surface.pending_stride;
    if width == 0 || height == 0 || stride < width {
        surface.awaiting_buffer = false;
        return true;
    }
    let Ok((_row_bytes, needed_bytes, pixels)) = validate_buffer_layout(
        width,
        height,
        stride,
        PIXEL_FORMAT_XRGB8888,
        surface.width,
        surface.height,
    ) else {
        surface.awaiting_buffer = false;
        return true;
    };
    let Ok(total) = usize::try_from(total) else {
        surface.awaiting_buffer = false;
        return true;
    };
    if total == 0 || total > MAX_SHARED_BYTES || total < needed_bytes {
        surface.awaiting_buffer = false;
        return true;
    }
    if mapped_addr == 0 {
        surface.awaiting_buffer = false;
        return true;
    }
    surface.pending.clear();
    surface.pending_buffer = Some(SurfaceBuffer {
        mapped_addr,
        byte_len: needed_bytes,
        width,
        height,
        stride,
        pixels,
    });
    surface.pending_bytes_received = needed_bytes;
    surface.pending_len = pixels;
    surface.pending_damage = Some(Rect::full(width, height));
    surface.awaiting_buffer = false;
    true
}

fn hit_test(surfaces: &[Surface], x: i32, y: i32) -> Option<usize> {
    let mut hit = None;
    let mut best_z = 0u32;
    for (index, surface) in surfaces.iter().enumerate() {
        if !surface.live || !surface.visible {
            continue;
        }
        let (width, height) = surface_extent(surface);
        let right = surface.x.saturating_add(width as i32);
        let bottom = surface.y.saturating_add(height as i32);
        if x >= surface.x && x < right && y >= surface.y && y < bottom && surface.z >= best_z {
            hit = Some(index);
            best_z = surface.z;
        }
    }
    hit
}

fn send_event(endpoint: u64, kind: u32, a: i32, b: i32, c: u32) {
    if endpoint == 0 {
        return;
    }
    let mut event = [0u8; 20];
    put_u32(&mut event, 0, kind);
    put_i32(&mut event, 4, a);
    put_i32(&mut event, 8, b);
    put_u32(&mut event, 12, c);
    let _ = platform::ipc::send(endpoint, &event);
}

fn update_keyboard_focus(
    surfaces: &[Surface],
    keyboard_focus: &mut Option<usize>,
    next: Option<usize>,
) {
    if *keyboard_focus == next {
        return;
    }
    if let Some(index) = *keyboard_focus {
        if let Some(surface) = surfaces.get(index)
            && surface.live
        {
            send_event(surface.event_endpoint, EVENT_FOCUS_LOST, 0, 0, 0);
        }
    }
    *keyboard_focus = next;
    if let Some(index) = *keyboard_focus {
        if let Some(surface) = surfaces.get(index)
            && surface.live
        {
            send_event(surface.event_endpoint, EVENT_FOCUS_GAINED, 0, 0, 0);
        }
    }
}

fn handle_input_event(
    surfaces: &[Surface],
    windows: &[Window],
    next_pointer_serial: &mut u64,
    pointer_serials: &mut [PointerSerial],
    pointer_x: &mut i32,
    pointer_y: &mut i32,
    display_width: u32,
    display_height: u32,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    event: &platform::input::InputEvent,
) -> bool {
    match event.kind {
        platform::input::EVENT_KIND_POINTER_MOVE => {
            *pointer_x = pointer_x.saturating_add(event.value_x);
            *pointer_y = pointer_y.saturating_add(event.value_y);
            if *pointer_x < 0 {
                *pointer_x = 0;
            }
            if *pointer_y < 0 {
                *pointer_y = 0;
            }
            let max_x = display_width.saturating_sub(1).min(MAX_DIMENSION) as i32;
            let max_y = display_height.saturating_sub(1).min(MAX_DIMENSION) as i32;
            if *pointer_x > max_x {
                *pointer_x = max_x;
            }
            if *pointer_y > max_y {
                *pointer_y = max_y;
            }
            let next = hit_test(surfaces, *pointer_x, *pointer_y);
            if *pointer_focus != next {
                if let Some(index) = *pointer_focus {
                    if let Some(surface) = surfaces.get(index)
                        && surface.live
                    {
                        send_event(surface.event_endpoint, EVENT_POINTER_LEAVE, 0, 0, 0);
                    }
                }
                *pointer_focus = next;
                if let Some(index) = next {
                    let surface = &surfaces[index];
                    send_event(
                        surface.event_endpoint,
                        EVENT_POINTER_ENTER,
                        *pointer_x - surface.x,
                        *pointer_y - surface.y,
                        0,
                    );
                }
            }
            if let Some(index) = *pointer_focus {
                if let Some(surface) = surfaces.get(index)
                    && surface.live
                {
                    send_event(
                        surface.event_endpoint,
                        EVENT_POINTER_MOTION,
                        *pointer_x - surface.x,
                        *pointer_y - surface.y,
                        0,
                    );
                }
            }
            true
        }
        platform::input::EVENT_KIND_POINTER_BUTTON => {
            let target = hit_test(surfaces, *pointer_x, *pointer_y);
            if event.flags & platform::input::FLAG_PRESS != 0 {
                let focus = target.and_then(|index| {
                    let surface = &surfaces[index];
                    if surface.is_decoration {
                        let window_index = window_index_by_id(windows, surface.window)?;
                        content_surface_index_for_window(surfaces, &windows[window_index])
                    } else {
                        Some(index)
                    }
                });
                update_keyboard_focus(surfaces, keyboard_focus, focus);
            }
            if let Some(index) = target {
                let surface = &surfaces[index];
                let mut detail = if surface.is_decoration {
                    u32::from(event.detail)
                } else {
                    (u32::from(event.flags) << 16) | u32::from(event.detail)
                };
                if event.flags & platform::input::FLAG_PRESS != 0 && surface.is_decoration {
                    *next_pointer_serial = next_pointer_serial.wrapping_add(1).max(1);
                    detail = (*next_pointer_serial & 0xffff_ffff) as u32;
                    if let Some(slot) = pointer_serials
                        .iter_mut()
                        .find(|record| record.used || record.serial == 0)
                    {
                        *slot = PointerSerial {
                            serial: *next_pointer_serial,
                            window: surface.window,
                            decoration: surface.handle,
                            used: false,
                        };
                    }
                }
                send_event(
                    surface.event_endpoint,
                    EVENT_POINTER_BUTTON,
                    *pointer_x - surface.x,
                    *pointer_y - surface.y,
                    detail,
                );
            }
            false
        }
        platform::input::EVENT_KIND_KEY => {
            if let Some(index) = *keyboard_focus {
                if let Some(surface) = surfaces.get(index)
                    && surface.live
                {
                    send_event(
                        surface.event_endpoint,
                        EVENT_KEY,
                        i32::from(event.keycode),
                        event.codepoint as i32,
                        u32::from(event.flags),
                    );
                }
            }
            false
        }
        _ => false,
    }
}

fn blend_argb_over_xrgb(dst: u32, src: u32) -> u32 {
    let alpha = (src >> 24) & 0xff;
    if alpha == 0 {
        return dst;
    }
    if alpha == 0xff {
        return 0xff00_0000 | (src & 0x00ff_ffff);
    }
    let inv = 255 - alpha;
    let sr = (src >> 16) & 0xff;
    let sg = (src >> 8) & 0xff;
    let sb = src & 0xff;
    let dr = (dst >> 16) & 0xff;
    let dg = (dst >> 8) & 0xff;
    let db = dst & 0xff;
    let r = (sr * alpha + dr * inv + 127) / 255;
    let g = (sg * alpha + dg * inv + 127) / 255;
    let b = (sb * alpha + db * inv + 127) / 255;
    0xff00_0000 | (r << 16) | (g << 8) | b
}

fn composite_cursor(
    frame: &mut [u32],
    frame_w: usize,
    frame_h: usize,
    cursor: &CursorImage,
    pointer_x: i32,
    pointer_y: i32,
) -> Result<(), u32> {
    let origin_x = pointer_x.saturating_sub(cursor.hotspot_x);
    let origin_y = pointer_y.saturating_sub(cursor.hotspot_y);
    for cy in 0..cursor.height as usize {
        let dy = origin_y.saturating_add(cy as i32);
        if dy < 0 || dy >= frame_h as i32 {
            continue;
        }
        let Some(src_row) = cy.checked_mul(cursor.width as usize) else {
            return Err(errno_status(mochi_user_syscall::ERANGE));
        };
        let Some(dst_row) = (dy as usize).checked_mul(frame_w) else {
            return Err(errno_status(mochi_user_syscall::ERANGE));
        };
        for cx in 0..cursor.width as usize {
            let dx = origin_x.saturating_add(cx as i32);
            if dx < 0 || dx >= frame_w as i32 {
                continue;
            }
            let Some(src_index) = src_row.checked_add(cx) else {
                return Err(errno_status(mochi_user_syscall::ERANGE));
            };
            let Some(src) = cursor.pixels.get(src_index).copied() else {
                return Err(errno_status(mochi_user_syscall::ERANGE));
            };
            if (src >> 24) == 0 {
                continue;
            }
            let Some(dst_index) = dst_row.checked_add(dx as usize) else {
                return Err(errno_status(mochi_user_syscall::ERANGE));
            };
            let Some(slot) = frame.get_mut(dst_index) else {
                return Err(errno_status(mochi_user_syscall::ERANGE));
            };
            *slot = blend_argb_over_xrgb(*slot, src);
        }
    }
    Ok(())
}

fn composite_and_present(
    surfaces: &[Surface],
    cursor: &CursorImage,
    pointer_x: i32,
    pointer_y: i32,
    display_tid: u64,
    display_width: u32,
    display_height: u32,
    _display_stride: u32,
    display_format: u32,
) -> u32 {
    if display_format != PIXEL_FORMAT_XRGB8888 {
        return errno_status(mochi_user_syscall::ENOTSUP);
    }
    let Some((frame_w, frame_h)) = choose_frame_size(display_width, display_height) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let Some(frame_pixels) = frame_w.checked_mul(frame_h) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let Some(frame_bytes) = frame_pixels.checked_mul(4) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let Some(page_count) = shared_page_count(frame_bytes) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    if page_count == 0 || page_count > MAX_SHARED_PAGES {
        return errno_status(mochi_user_syscall::ERANGE);
    }
    let virt = match platform::memory::alloc_shared_page_count(page_count) {
        Ok(virt) => virt,
        Err(err) => return errno_from_platform(err),
    };
    if virt == 0 || (virt as usize) & (PAGE_SIZE - 1) != 0 {
        return errno_status(mochi_user_syscall::EIO);
    }
    let frame = unsafe { core::slice::from_raw_parts_mut(virt as *mut u32, frame_pixels) };
    for y in 0..frame_h {
        let Some(row) = y.checked_mul(frame_w) else {
            return errno_status(mochi_user_syscall::ERANGE);
        };
        for x in 0..frame_w {
            let shade = 0x0020_2630u32 + (((x as u32) ^ (y as u32)) & 0x7);
            let Some(pixel) = frame.get_mut(row + x) else {
                return errno_status(mochi_user_syscall::ERANGE);
            };
            *pixel = 0xff00_0000 | shade;
        }
    }
    for surface in surfaces.iter().filter(|s| s.live && s.visible) {
        if !surface_has_current_pixels(surface) {
            continue;
        }
        for sy in 0..surface.current_height as usize {
            let dy = surface.y + sy as i32;
            if dy < 0 || dy >= frame_h as i32 {
                continue;
            }
            for sx in 0..surface.current_width as usize {
                let dx = surface.x + sx as i32;
                if dx < 0 || dx >= frame_w as i32 {
                    continue;
                }
                let Some(dst) = (dy as usize)
                    .checked_mul(frame_w)
                    .and_then(|row| row.checked_add(dx as usize))
                else {
                    return errno_status(mochi_user_syscall::ERANGE);
                };
                let Some(pixel) = read_current_pixel(surface, sx, sy) else {
                    continue;
                };
                let Some(slot) = frame.get_mut(dst) else {
                    return errno_status(mochi_user_syscall::ERANGE);
                };
                *slot = pixel;
            }
        }
    }
    if let Err(status) = composite_cursor(frame, frame_w, frame_h, cursor, pointer_x, pointer_y) {
        return status;
    }
    if let Err(err) = platform::ipc::send_page_count(display_tid, page_count, virt) {
        return errno_from_platform(err);
    }
    let request = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(DISPLAY_PRESENT_REQ).cast::<u8>(),
            20,
        )
    };
    request.fill(0);
    put_u32(request, 0, OP_DISPLAY_PRESENT);
    put_u32(request, 4, frame_w as u32);
    put_u32(request, 8, frame_h as u32);
    put_u32(request, 12, frame_w as u32);
    put_u32(request, 16, PIXEL_FORMAT_XRGB8888);
    let reply = &mut [];
    let Ok(_msg) = platform::ipc::call(display_tid, request, reply) else {
        return errno_status(mochi_user_syscall::EIO);
    };
    0
}

fn handle_request(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    next_z: &mut u32,
    next_window_index: &mut u32,
    next_window_id: &mut u64,
    _next_pointer_serial: &mut u64,
    pointer_serials: &mut [PointerSerial],
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    client: ClientId,
    sender: u64,
    request: &[u8],
    needs_present: &mut bool,
    _display_tid: u64,
    _display_width: u32,
    _display_height: u32,
    _display_stride: u32,
    _display_format: u32,
) -> [u8; 16] {
    let mut reply = [0u8; 16];
    let Some(opcode) = read_u32(request, 0) else {
        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
        return reply;
    };
    match opcode {
        OP_CREATE_SURFACE => {
            let role_raw = read_u32(request, 4).unwrap_or(0);
            let role = match SurfaceRole::from_wire(role_raw) {
                Ok(role) => role,
                Err(status) => {
                    put_u32(&mut reply, 0, status);
                    return reply;
                }
            };
            let rights = match role.general_client_rights() {
                Ok(rights) => rights,
                Err(status) => {
                    put_u32(&mut reply, 0, status);
                    return reply;
                }
            };
            let width = read_u32(request, 8).unwrap_or(0);
            let height = read_u32(request, 12).unwrap_or(0);
            let event_endpoint = read_u64(request, 16).unwrap_or(0);
            if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let (parent, placement) = if role == SurfaceRole::Popup {
                let Some(parent_token) = read_u64(request, 24) else {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                    return reply;
                };
                let parent_handle = SurfaceHandle(parent_token);
                let Some(parent_index) =
                    surface_index_for(surfaces, client, parent_handle, SurfaceRights::COMMIT)
                else {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                    return reply;
                };
                let parent_role = surfaces[parent_index].role;
                if !matches!(parent_role, SurfaceRole::Toplevel | SurfaceRole::Popup) {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                    return reply;
                }
                let placement = PopupPlacement {
                    anchor_rect: Rect {
                        x: read_u32(request, 32).unwrap_or(0) as i32,
                        y: read_u32(request, 36).unwrap_or(0) as i32,
                        width: read_u32(request, 40).unwrap_or(1),
                        height: read_u32(request, 44).unwrap_or(1),
                    },
                    offset: Point {
                        x: read_u32(request, 48).unwrap_or(0) as i32,
                        y: read_u32(request, 52).unwrap_or(0) as i32,
                    },
                };
                if validate_damage_rect(
                    placement.anchor_rect,
                    surfaces[parent_index].width,
                    surfaces[parent_index].height,
                )
                .is_err()
                {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                    return reply;
                }
                (Some(parent_handle), placement)
            } else {
                (None, PopupPlacement::default())
            };
            let Some(index) = surfaces.iter().position(|s| !s.live) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOSPC));
                return reply;
            };
            *next_z = next_z.wrapping_add(1);
            let token = match generate_surface_token(surfaces) {
                Ok(token) => token,
                Err(status) => {
                    put_u32(&mut reply, 0, status);
                    return reply;
                }
            };
            let handle = SurfaceHandle(token);
            let (window_id, window_token, window_slot) = if role == SurfaceRole::Toplevel {
                let Some(slot) = windows.iter().position(|window| !window.live) else {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOSPC));
                    return reply;
                };
                *next_window_id = next_window_id.wrapping_add(1).max(1);
                let window_token = match generate_window_token(windows) {
                    Ok(token) => token,
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
                };
                (WindowId(*next_window_id), window_token, Some(slot))
            } else {
                (WindowId(0), 0, None)
            };
            let (x, y) = if let Some(parent_handle) = parent {
                let Some(parent_index) = surfaces
                    .iter()
                    .position(|surface| surface.live && surface.handle == parent_handle)
                else {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                    return reply;
                };
                (
                    surfaces[parent_index]
                        .x
                        .saturating_add(placement.anchor_rect.x)
                        .saturating_add(placement.offset.x),
                    surfaces[parent_index]
                        .y
                        .saturating_add(placement.anchor_rect.y)
                        .saturating_add(placement.offset.y),
                )
            } else {
                let cascade = *next_window_index % 8;
                *next_window_index = next_window_index.wrapping_add(1);
                (
                    32i32.saturating_add((cascade as i32).saturating_mul(24)),
                    48i32.saturating_add((cascade as i32).saturating_mul(24)),
                )
            };
            surfaces[index].reset();
            surfaces[index].live = true;
            surfaces[index].owner = client;
            surfaces[index].event_endpoint = event_endpoint;
            surfaces[index].handle = handle;
            surfaces[index].token = token;
            surfaces[index].role = role;
            surfaces[index].rights = rights;
            surfaces[index].parent = parent;
            surfaces[index].window = window_id;
            surfaces[index].is_decoration = false;
            surfaces[index].visible = true;
            surfaces[index].x = x;
            surfaces[index].y = y;
            surfaces[index].width = width;
            surfaces[index].height = height;
            surfaces[index].z = *next_z;
            if let Some(slot) = window_slot {
                windows[slot] = Window::empty();
                windows[slot].live = true;
                windows[slot].id = window_id;
                windows[slot].token = window_token;
                windows[slot].content = handle;
                windows[slot].resizable = true;
            }
            put_u32(&mut reply, 0, 0);
            reply[4..12].copy_from_slice(&token.to_le_bytes());
        }
        OP_ATTACH_BUFFER => {
            let token = read_u64(request, 4).unwrap_or(0);
            let width = read_u32(request, 12).unwrap_or(0);
            let height = read_u32(request, 16).unwrap_or(0);
            let stride = read_u32(request, 20).unwrap_or(0);
            let format = read_u32(request, 24).unwrap_or(0);
            let handle = SurfaceHandle(token);
            let Some(index) =
                surface_index_for(surfaces, client, handle, SurfaceRights::ATTACH_BUFFER)
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let Some(index_width) = surfaces.get(index).map(|surface| surface.width) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            };
            let Some(index_height) = surfaces.get(index).map(|surface| surface.height) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            };
            let (row_bytes, needed, pixels) = match validate_buffer_layout(
                width,
                height,
                stride,
                format,
                index_width,
                index_height,
            ) {
                Ok(layout) => layout,
                Err(status) => {
                    put_u32(&mut reply, 0, status);
                    return reply;
                }
            };
            if request.len() == 28 {
                let surface = &mut surfaces[index];
                surface.pending_width = width;
                surface.pending_height = height;
                surface.pending_stride = stride;
                surface.pending_len = pixels;
                surface.pending_bytes_received = 0;
                surface.pending.clear();
                surface.pending_buffer = None;
                surface.pending_damage = Some(Rect::full(width, height));
                surface.awaiting_buffer = true;
            } else {
                if needed > MAX_SHARED_BYTES {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                    return reply;
                }
                if request.len() < 28 + needed {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                    return reply;
                }
                let mut pending = Vec::new();
                if !resize_buffer(&mut pending, width, height) {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOMEM));
                    return reply;
                }
                for y in 0..height as usize {
                    let Some(src_row) = y.checked_mul(row_bytes) else {
                        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                        return reply;
                    };
                    let Some(dst_row) = y.checked_mul(width as usize) else {
                        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                        return reply;
                    };
                    for x in 0..width as usize {
                        let Some(src) = src_row
                            .checked_add(x.saturating_mul(4))
                            .and_then(|offset| offset.checked_add(28))
                        else {
                            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                            return reply;
                        };
                        let Some(pixel) = read_pixel(request, src) else {
                            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                            return reply;
                        };
                        let Some(dst) = dst_row.checked_add(x) else {
                            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                            return reply;
                        };
                        let Some(slot) = pending.get_mut(dst) else {
                            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                            return reply;
                        };
                        *slot = pixel;
                    }
                }
                let surface = &mut surfaces[index];
                surface.pending = pending;
                surface.pending_width = width;
                surface.pending_height = height;
                surface.pending_stride = stride;
                surface.pending_len = pixels;
                surface.pending_bytes_received = needed;
                surface.pending_buffer = None;
                surface.pending_damage = Some(Rect::full(width, height));
                surface.awaiting_buffer = false;
            }
            put_u32(&mut reply, 0, 0);
        }
        OP_DAMAGE => {
            let token = read_u64(request, 4).unwrap_or(0);
            let handle = SurfaceHandle(token);
            let Some(index) = surface_index_for(surfaces, client, handle, SurfaceRights::DAMAGE)
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let damage = if request.len() >= 28 {
                let rect = Rect {
                    x: read_u32(request, 12).unwrap_or(0) as i32,
                    y: read_u32(request, 16).unwrap_or(0) as i32,
                    width: read_u32(request, 20).unwrap_or(0),
                    height: read_u32(request, 24).unwrap_or(0),
                };
                match validate_damage_rect(rect, surfaces[index].width, surfaces[index].height) {
                    Ok(rect) => Some(rect),
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
                }
            } else {
                Some(Rect::full(surfaces[index].width, surfaces[index].height))
            };
            surfaces[index].pending_damage = damage;
            put_u32(&mut reply, 0, 0);
        }
        OP_COMMIT => {
            let token = read_u64(request, 4).unwrap_or(0);
            let handle = SurfaceHandle(token);
            let Some(index) = surface_index_for(surfaces, client, handle, SurfaceRights::COMMIT)
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let (pending_width, pending_height, pending_len, pending_stride, awaiting_buffer) = {
                let surface = &surfaces[index];
                (
                    surface.pending_width,
                    surface.pending_height,
                    surface.pending_len,
                    surface.pending_stride,
                    surface.awaiting_buffer,
                )
            };
            if awaiting_buffer || pending_width == 0 || pending_len == 0 {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let Some(needed) = (pending_width as usize).checked_mul(pending_height as usize) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            };
            if pending_stride < pending_width {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            if surfaces[index].pending_buffer.is_none() && surfaces[index].pending.len() < needed {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            {
                let surface = &mut surfaces[index];
                surface.current_buffer = surface.pending_buffer.take();
                if surface.current_buffer.is_some() {
                    surface.current.clear();
                } else {
                    core::mem::swap(&mut surface.current, &mut surface.pending);
                }
                surface.current_width = pending_width;
                surface.current_height = pending_height;
                surface.current_stride = pending_stride;
                surface.pending_width = 0;
                surface.pending_height = 0;
                surface.pending_stride = 0;
                surface.pending_len = 0;
                surface.pending_bytes_received = 0;
                surface.pending_damage = None;
                surface.pending_buffer = None;
                surface.awaiting_buffer = false;
            }
            *needs_present = !surfaces[index].is_decoration;
            if !surfaces[index].is_decoration {
                let window_id = surfaces[index].window;
                if let Some(window_index) = window_index_by_id(windows, window_id) {
                    if !windows[window_index].metadata_sent {
                        windows[window_index].metadata_sent = true;
                        notify_decorators(clients, windows, surfaces, window_index);
                    }
                }
            }
            put_u32(&mut reply, 0, 0);
        }
        OP_SET_POSITION => {
            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
        }
        OP_DESTROY_SURFACE => {
            let token = read_u64(request, 4).unwrap_or(0);
            let handle = SurfaceHandle(token);
            if let Some(index) = surface_index_for(surfaces, client, handle, SurfaceRights::DESTROY)
            {
                destroy_surface_tree(surfaces, windows, index, pointer_focus, keyboard_focus);
                *needs_present = true;
                put_u32(&mut reply, 0, 0);
            } else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
            }
        }
        OP_DECOR_SUBSCRIBE => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let endpoint = read_u64(request, 4).unwrap_or(0);
            if endpoint == 0 {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            if let Some(record) = clients
                .iter_mut()
                .find(|record| record.live && record.id == client)
            {
                record.decoration_endpoint = endpoint;
            }
            for window in windows
                .iter()
                .filter(|window| window.live && window.metadata_sent)
            {
                send_window_metadata(window, surfaces, endpoint);
            }
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_CREATE_SURFACE => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let width = read_u32(request, 12).unwrap_or(0);
            let height = read_u32(request, 16).unwrap_or(0);
            let event_endpoint = read_u64(request, 20).unwrap_or(0);
            if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let Some(content_index) =
                content_surface_index_for_window(surfaces, &windows[window_index])
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let Some(index) = surfaces.iter().position(|surface| !surface.live) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOSPC));
                return reply;
            };
            let token = match generate_surface_token(surfaces) {
                Ok(token) => token,
                Err(status) => {
                    put_u32(&mut reply, 0, status);
                    return reply;
                }
            };
            *next_z = next_z.wrapping_add(1);
            let handle = SurfaceHandle(token);
            surfaces[index].reset();
            surfaces[index].live = true;
            surfaces[index].owner = client;
            surfaces[index].event_endpoint = event_endpoint;
            surfaces[index].handle = handle;
            surfaces[index].token = token;
            surfaces[index].role = SurfaceRole::Popup;
            surfaces[index].rights = SurfaceRights::GENERAL_CLIENT;
            surfaces[index].window = windows[window_index].id;
            surfaces[index].is_decoration = true;
            surfaces[index].visible = true;
            surfaces[index].x = surfaces[content_index].x;
            surfaces[index].y = surfaces[content_index]
                .y
                .saturating_sub(DECOR_TITLE_BAR_HEIGHT as i32);
            surfaces[index].width = width;
            surfaces[index].height = height;
            surfaces[index].z = *next_z;
            put_u32(&mut reply, 0, 0);
            reply[4..12].copy_from_slice(&token.to_le_bytes());
        }
        OP_DECOR_ATTACH => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let decoration_token = read_u64(request, 12).unwrap_or(0);
            let insets = Insets {
                left: read_u32(request, 20).unwrap_or(0),
                top: read_u32(request, 24).unwrap_or(0),
                right: read_u32(request, 28).unwrap_or(0),
                bottom: read_u32(request, 32).unwrap_or(0),
            };
            if insets.left > MAX_DIMENSION
                || insets.top > MAX_DIMENSION
                || insets.right > MAX_DIMENSION
                || insets.bottom > MAX_DIMENSION
            {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let handle = SurfaceHandle(decoration_token);
            let Some(decoration_index) =
                surface_index_for(surfaces, client, handle, SurfaceRights::COMMIT)
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if !surfaces[decoration_index].is_decoration
                || surfaces[decoration_index].window != windows[window_index].id
            {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            if surfaces[decoration_index].current_buffer.is_none()
                && surfaces[decoration_index].current.is_empty()
                && (surfaces[decoration_index].pending_buffer.is_some()
                    || !surfaces[decoration_index].pending.is_empty())
                && surfaces[decoration_index].pending_width != 0
                && surfaces[decoration_index].pending_height != 0
            {
                let surface = &mut surfaces[decoration_index];
                let pending_width = surface.pending_width;
                let pending_height = surface.pending_height;
                let pending_stride = surface.pending_stride;
                surface.current_buffer = surface.pending_buffer.take();
                if surface.current_buffer.is_some() {
                    surface.current.clear();
                } else {
                    core::mem::swap(&mut surface.current, &mut surface.pending);
                }
                surface.current_width = pending_width;
                surface.current_height = pending_height;
                surface.current_stride = pending_stride;
                surface.pending_width = 0;
                surface.pending_height = 0;
                surface.pending_stride = 0;
                surface.pending_len = 0;
                surface.pending_damage = None;
                surface.pending_buffer = None;
                surface.awaiting_buffer = false;
            }
            windows[window_index].decoration = Some(handle);
            windows[window_index].decorator = client;
            *needs_present = true;
            windows[window_index].decorator_endpoint = surfaces[decoration_index].event_endpoint;
            windows[window_index].insets = insets;
            reposition_window_surfaces(surfaces, &windows[window_index]);
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_DETACH => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            windows[window_index].decoration = None;
            windows[window_index].decorator = ClientId(0);
            windows[window_index].decorator_endpoint = 0;
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_UPDATE_INSETS => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            windows[window_index].insets = Insets {
                left: read_u32(request, 12).unwrap_or(0).min(MAX_DIMENSION),
                top: read_u32(request, 16).unwrap_or(0).min(MAX_DIMENSION),
                right: read_u32(request, 20).unwrap_or(0).min(MAX_DIMENSION),
                bottom: read_u32(request, 24).unwrap_or(0).min(MAX_DIMENSION),
            };
            reposition_window_surfaces(surfaces, &windows[window_index]);
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_BEGIN_MOVE | OP_DECOR_BEGIN_RESIZE => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let serial = read_u64(request, 12).unwrap_or(0);
            let dx = read_u32(request, 20).unwrap_or(0) as i32;
            let dy = read_u32(request, 24).unwrap_or(0) as i32;
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let Some(serial_index) = pointer_serials.iter().position(|record| {
                record.serial == serial
                    && record.window == windows[window_index].id
                    && !record.used
                    && Some(record.decoration) == windows[window_index].decoration
            }) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            pointer_serials[serial_index].used = true;
            if opcode == OP_DECOR_BEGIN_MOVE {
                if let Some(content_index) =
                    content_surface_index_for_window(surfaces, &windows[window_index])
                {
                    surfaces[content_index].x = surfaces[content_index].x.saturating_add(dx);
                    surfaces[content_index].y = surfaces[content_index].y.saturating_add(dy);
                }
                reposition_window_surfaces(surfaces, &windows[window_index]);
                *needs_present = true;
                put_u32(&mut reply, 0, 0);
            } else {
                put_u32(&mut reply, 0, 0);
            }
        }
        OP_DECOR_MINIMIZE | OP_DECOR_TOGGLE_MAXIMIZE => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            if opcode == OP_DECOR_MINIMIZE {
                windows[window_index].state = WINDOW_STATE_MINIMIZED;
            } else {
                windows[window_index].state =
                    if windows[window_index].state == WINDOW_STATE_MAXIMIZED {
                        WINDOW_STATE_NORMAL
                    } else {
                        WINDOW_STATE_MAXIMIZED
                    };
            }
            let visible = windows[window_index].state != WINDOW_STATE_MINIMIZED;
            if let Some(content_index) =
                content_surface_index_for_window(surfaces, &windows[window_index])
            {
                surfaces[content_index].visible = visible;
            }
            if let Some(decoration_index) =
                decoration_surface_index_for_window(surfaces, &windows[window_index])
            {
                surfaces[decoration_index].visible = visible;
            }
            *needs_present = true;
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_CLOSE_REQUEST => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            windows[window_index].close_requested = true;
            if let Some(content_index) =
                content_surface_index_for_window(surfaces, &windows[window_index])
            {
                destroy_surface_tree(
                    surfaces,
                    windows,
                    content_index,
                    pointer_focus,
                    keyboard_focus,
                );
            }
            *needs_present = true;
            put_u32(&mut reply, 0, 0);
        }
        _ => put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL)),
    }
    reply
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    platform::println!("compositor.service: start");
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => platform::process::exit(1),
    };
    let Some(display_tid) = find_service(DISPLAY_SERVICE_NAME) else {
        platform::println!("compositor.service: display.driver not found");
        platform::process::exit(1);
    };
    if let Some(input_tid) = find_service(INPUT_SERVICE_NAME) {
        let subscribe = unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::addr_of_mut!(INPUT_SUBSCRIBE_REQ).cast::<u8>(),
                16,
            )
        };
        subscribe.fill(0);
        put_u32(subscribe, 0, platform::input::SUBSCRIBE_OPCODE);
        subscribe[8..16].copy_from_slice(&endpoint.to_le_bytes());
        let reply = unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::addr_of_mut!(INPUT_SUBSCRIBE_REP).cast::<u8>(),
                8,
            )
        };
        reply.fill(0);
        let _ = platform::ipc::call(input_tid, subscribe, reply);
    }
    let (display_width, display_height, display_stride, display_format) =
        display_request_info(display_tid);

    let mut clients = [Client::default(); MAX_CLIENTS];
    let mut next_client_id = 0u64;
    let mut surfaces: Vec<Surface> = vec![Surface::empty(); MAX_SURFACES];
    let mut windows = [Window::empty(); MAX_WINDOWS];
    let mut next_z = 0u32;
    let mut next_window_index = 0u32;
    let mut next_window_id = 0u64;
    let mut next_pointer_serial = 0u64;
    let mut pointer_serials = [PointerSerial::default(); 32];
    let mut pointer_x = 0i32;
    let mut pointer_y = 0i32;
    let mut pointer_focus = None;
    let mut keyboard_focus = None;
    let mut idle_cleanup_ticks = 0u32;
    let cursor = load_cursor_image();
    loop {
        let buf = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(IPC_BUF).cast::<u8>(), 4128)
        };
        let msg = match platform::ipc::try_wait(buf) {
            Ok(msg) => {
                idle_cleanup_ticks = 0;
                msg
            }
            Err(_) => {
                idle_cleanup_ticks = idle_cleanup_ticks.wrapping_add(1);
                if idle_cleanup_ticks >= IDLE_CLEANUP_YIELDS {
                    idle_cleanup_ticks = 0;
                    if cleanup_dead_clients(
                        &mut clients,
                        &mut surfaces,
                        &mut windows,
                        &mut pointer_focus,
                        &mut keyboard_focus,
                    ) {
                        let _ = composite_and_present(
                            &surfaces,
                            &cursor,
                            pointer_x,
                            pointer_y,
                            display_tid,
                            display_width,
                            display_height,
                            display_stride,
                            display_format,
                        );
                    }
                }
                sleep_one_tick();
                continue;
            }
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        if len == 16 {
            let client = client_id_for_sender(&mut clients, sender, &mut next_client_id);
            if client == ClientId(0) {
                continue;
            }
            let mapped_addr = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            let total = u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            if handle_shared_buffer(&mut surfaces, client, mapped_addr, total) {
                continue;
            }
        }
        if len == core::mem::size_of::<platform::input::InputEvent>() {
            let event = unsafe {
                core::ptr::read_unaligned(buf.as_ptr().cast::<platform::input::InputEvent>())
            };
            let needs_present = handle_input_event(
                &surfaces,
                &windows,
                &mut next_pointer_serial,
                &mut pointer_serials,
                &mut pointer_x,
                &mut pointer_y,
                display_width,
                display_height,
                &mut pointer_focus,
                &mut keyboard_focus,
                &event,
            );
            if needs_present {
                let _ = composite_and_present(
                    &surfaces,
                    &cursor,
                    pointer_x,
                    pointer_y,
                    display_tid,
                    display_width,
                    display_height,
                    display_stride,
                    display_format,
                );
            }
            continue;
        }
        if len == 0 || len > buf.len() {
            let mut reply = [0u8; 16];
            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
            let _ = platform::ipc::reply(sender, &reply);
            continue;
        }
        let client = client_id_for_sender(&mut clients, sender, &mut next_client_id);
        if client == ClientId(0) {
            let mut reply = [0u8; 16];
            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOSPC));
            let _ = platform::ipc::reply(sender, &reply);
            continue;
        }
        let mut needs_present = false;
        let reply = handle_request(
            &mut clients,
            &mut surfaces,
            &mut windows,
            &mut next_z,
            &mut next_window_index,
            &mut next_window_id,
            &mut next_pointer_serial,
            &mut pointer_serials,
            &mut pointer_focus,
            &mut keyboard_focus,
            client,
            sender,
            &buf[..len],
            &mut needs_present,
            display_tid,
            display_width,
            display_height,
            display_stride,
            display_format,
        );
        if platform::ipc::reply(sender, &reply).is_err() {
            cleanup_client(
                &mut clients,
                &mut surfaces,
                &mut windows,
                client,
                &mut pointer_focus,
                &mut keyboard_focus,
            );
        } else {
            if needs_present {
                let status = composite_and_present(
                    &surfaces,
                    &cursor,
                    pointer_x,
                    pointer_y,
                    display_tid,
                    display_width,
                    display_height,
                    display_stride,
                    display_format,
                );
                if status == 0 {
                    for surface in surfaces.iter().filter(|surface| surface.live) {
                        send_frame_done(surface);
                    }
                } else {
                    platform::println!("compositor.service: present deferred status={}", status);
                }
            }
        }
    }
}
