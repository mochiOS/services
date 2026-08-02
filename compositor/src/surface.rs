use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::client::{Client, ClientId};
use crate::decoration::{
    sender_has_overlay_compat_capability, sender_has_secure_overlay_capability,
};
use crate::geometry::{Point, PopupPlacement, Rect, merge_damage, validate_damage_rect};
use crate::input::clear_focus_for_surface;
use crate::protocol::*;
use crate::state::{MAX_DIMENSION, MAX_SHARED_BYTES, PAGE_SIZE, getrandom_u64};
use crate::window::{
    Window, WindowId, generate_window_token, notify_decorators, window_index_by_id,
};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SurfaceHandle(pub(crate) u64);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SurfaceRole {
    Toplevel,
    Popup,
    Background,
    Panel,
    SecureOverlay,
}

impl SurfaceRole {
    pub(crate) fn from_wire(value: u32) -> Result<Self, u32> {
        match value {
            ROLE_TOPLEVEL => Ok(Self::Toplevel),
            ROLE_POPUP => Ok(Self::Popup),
            ROLE_BACKGROUND => Ok(Self::Background),
            ROLE_PANEL => Ok(Self::Panel),
            ROLE_SECURE_OVERLAY => Ok(Self::SecureOverlay),
            _ => Err(errno_status(mochi_user_syscall::EINVAL)),
        }
    }

    pub(crate) fn general_client_rights(self) -> Result<SurfaceRights, u32> {
        match self {
            Self::Toplevel | Self::Popup => Ok(SurfaceRights::GENERAL_CLIENT),
            Self::Background | Self::Panel | Self::SecureOverlay => {
                Err(errno_status(mochi_user_syscall::EACCES))
            }
        }
    }

    pub(crate) fn privileged_overlay_rights(self) -> Result<SurfaceRights, u32> {
        match self {
            Self::Background | Self::Panel | Self::Toplevel | Self::Popup => {
                Ok(SurfaceRights::GENERAL_CLIENT)
            }
            Self::SecureOverlay => Err(errno_status(mochi_user_syscall::EACCES)),
        }
    }

    pub(crate) const fn stack_layer(self) -> u8 {
        match self {
            Self::Background => 0,
            Self::Toplevel | Self::Popup => 1,
            Self::Panel => 2,
            Self::SecureOverlay => 3,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct SurfaceRights {
    bits: u32,
}

impl SurfaceRights {
    pub(crate) const ATTACH_BUFFER: Self = Self { bits: 1 << 0 };
    pub(crate) const DAMAGE: Self = Self { bits: 1 << 1 };
    pub(crate) const COMMIT: Self = Self { bits: 1 << 2 };
    pub(crate) const DESTROY: Self = Self { bits: 1 << 3 };
    #[allow(dead_code)]
    pub(crate) const SET_POSITION: Self = Self { bits: 1 << 4 };
    #[allow(dead_code)]
    pub(crate) const SET_Z_ORDER: Self = Self { bits: 1 << 5 };
    #[allow(dead_code)]
    pub(crate) const FOCUS_CONTROL: Self = Self { bits: 1 << 6 };
    pub(crate) const GENERAL_CLIENT: Self = Self {
        bits: Self::ATTACH_BUFFER.bits | Self::DAMAGE.bits | Self::COMMIT.bits | Self::DESTROY.bits,
    };

    pub(crate) const fn contains(self, required: Self) -> bool {
        (self.bits & required.bits) == required.bits
    }
}

#[derive(Clone)]
pub(crate) struct SurfaceBuffer {
    pub(crate) mapped_addr: u64,
    pub(crate) byte_len: usize,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) stride: u32,
    pub(crate) pixels: usize,
    pub(crate) format: u32,
}

#[derive(Clone, Default)]
pub(crate) struct GpuSurfaceState {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) atlas_width: u32,
    pub(crate) atlas_height: u32,
    pub(crate) vertices: Vec<u8>,
    pub(crate) atlas: Vec<u8>,
    pub(crate) generation: u64,
    pub(crate) atlas_generation: u64,
}

#[derive(Clone)]
pub(crate) struct Surface {
    pub(crate) live: bool,
    pub(crate) owner: ClientId,
    pub(crate) event_endpoint: u64,
    pub(crate) handle: SurfaceHandle,
    pub(crate) token: u64,
    pub(crate) role: SurfaceRole,
    pub(crate) rights: SurfaceRights,
    pub(crate) parent: Option<SurfaceHandle>,
    pub(crate) window: WindowId,
    pub(crate) is_decoration: bool,
    pub(crate) visible: bool,
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) pending_width: u32,
    pub(crate) pending_height: u32,
    pub(crate) pending_stride: u32,
    pub(crate) pending_format: u32,
    pub(crate) pending_len: usize,
    pub(crate) pending_bytes_received: usize,
    pub(crate) awaiting_buffer: bool,
    pub(crate) pending_damage: Option<Rect>,
    pub(crate) pending_buffer: Option<SurfaceBuffer>,
    pub(crate) pending: Vec<u32>,
    pub(crate) current_width: u32,
    pub(crate) current_height: u32,
    pub(crate) current_stride: u32,
    pub(crate) current_format: u32,
    pub(crate) current_buffer: Option<SurfaceBuffer>,
    pub(crate) current: Vec<u32>,
    pub(crate) gpu: Option<GpuSurfaceState>,
    pub(crate) content_generation: u64,
    pub(crate) z: u32,
}

impl Surface {
    pub(crate) fn empty() -> Self {
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
            pending_format: PIXEL_FORMAT_XRGB8888,
            pending_len: 0,
            pending_bytes_received: 0,
            awaiting_buffer: false,
            pending_damage: None,
            pending_buffer: None,
            pending: Vec::new(),
            current_width: 0,
            current_height: 0,
            current_stride: 0,
            current_format: PIXEL_FORMAT_XRGB8888,
            current_buffer: None,
            current: Vec::new(),
            gpu: None,
            content_generation: 0,
            z: 0,
        }
    }

    pub(crate) fn reset(&mut self) {
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
        self.pending_format = PIXEL_FORMAT_XRGB8888;
        self.pending_len = 0;
        self.pending_bytes_received = 0;
        self.awaiting_buffer = false;
        self.pending_damage = None;
        self.pending_buffer = None;
        self.pending.clear();
        self.current_width = 0;
        self.current_height = 0;
        self.current_stride = 0;
        self.current_format = PIXEL_FORMAT_XRGB8888;
        self.current_buffer = None;
        self.current.clear();
        self.gpu = None;
        self.content_generation = 0;
        self.z = 0;
    }
}

pub(crate) fn surface_index_for(
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

pub(crate) fn destroy_surface_tree(
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

pub(crate) fn generate_surface_token(surfaces: &[Surface]) -> Result<u64, u32> {
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

pub(crate) fn surface_index_by_handle(
    surfaces: &[Surface],
    handle: SurfaceHandle,
) -> Option<usize> {
    surfaces
        .iter()
        .position(|surface| surface.live && surface.handle == handle && surface.token == handle.0)
}

pub(crate) fn surface_extent(surface: &Surface) -> (u32, u32) {
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

pub(crate) fn surface_has_current_pixels(surface: &Surface) -> bool {
    if surface.current_format == PIXEL_FORMAT_GPU_SCENE {
        return surface.gpu.as_ref().is_some_and(|gpu| {
            gpu.width == surface.current_width
                && gpu.height == surface.current_height
                && !gpu.vertices.is_empty()
                && !gpu.atlas.is_empty()
        });
    }
    if matches!(surface.role, SurfaceRole::Background | SurfaceRole::Panel) {
        let Some(surface_len) =
            (surface.current_width as usize).checked_mul(surface.current_height as usize)
        else {
            return false;
        };
        return surface.current.len() >= surface_len;
    }
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

fn update_gpu_surface_state(
    current: Option<GpuSurfaceState>,
    buffer: &SurfaceBuffer,
    damage: Rect,
) -> Result<GpuSurfaceState, u32> {
    let source =
        unsafe { core::slice::from_raw_parts(buffer.mapped_addr as *const u8, buffer.byte_len) };
    let (scene, _) = mochios_viewkit_gpu_protocol::decode_prefix(source)
        .map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    if scene.width != buffer.width || scene.height != buffer.height {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let atlas_len = usize::try_from(scene.atlas_width)
        .ok()
        .and_then(|width| {
            usize::try_from(scene.atlas_height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let mut gpu = current.unwrap_or_default();
    let atlas_reallocated = gpu.atlas_width != scene.atlas_width
        || gpu.atlas_height != scene.atlas_height
        || gpu.atlas.len() != atlas_len;
    if atlas_reallocated {
        gpu.atlas.clear();
        gpu.atlas
            .try_reserve_exact(atlas_len)
            .map_err(|_| errno_status(mochi_user_syscall::ENOMEM))?;
        gpu.atlas.resize(atlas_len, 0);
    }
    let row_bytes = usize::try_from(scene.atlas_width)
        .ok()
        .and_then(|width| width.checked_mul(4))
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let atlas_offset = usize::try_from(scene.atlas_data_y)
        .ok()
        .and_then(|y| y.checked_mul(row_bytes))
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let atlas_end = atlas_offset
        .checked_add(scene.atlas.len())
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let Some(destination) = gpu.atlas.get_mut(atlas_offset..atlas_end) else {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    };
    destination.copy_from_slice(scene.atlas);
    let mut vertices = Vec::new();
    if gpu.width == scene.width && gpu.height == scene.height {
        crate::gpu_compositor::merge_surface_vertices(
            &gpu.vertices,
            scene.vertices,
            scene.width,
            scene.height,
            damage,
            &mut vertices,
        )
        .ok_or_else(|| errno_status(mochi_user_syscall::ENOMEM))?;
    } else {
        vertices
            .try_reserve_exact(scene.vertices.len())
            .map_err(|_| errno_status(mochi_user_syscall::ENOMEM))?;
        vertices.extend_from_slice(scene.vertices);
    }
    gpu.vertices = vertices;
    gpu.width = scene.width;
    gpu.height = scene.height;
    gpu.atlas_width = scene.atlas_width;
    gpu.atlas_height = scene.atlas_height;
    gpu.generation = gpu.generation.wrapping_add(1).max(1);
    if atlas_reallocated || !scene.atlas.is_empty() {
        gpu.atlas_generation = gpu.atlas_generation.wrapping_add(1).max(1);
    }
    Ok(gpu)
}

pub(crate) fn read_current_pixel(surface: &Surface, sx: usize, sy: usize) -> Option<u32> {
    if matches!(surface.role, SurfaceRole::Background | SurfaceRole::Panel) {
        let width = usize::try_from(surface.current_width).ok()?;
        let index = sy.checked_mul(width)?.checked_add(sx)?;
        return surface.current.get(index).copied();
    }
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

fn copy_surface_buffer(buffer: &SurfaceBuffer) -> Result<Vec<u32>, u32> {
    let mut pixels = Vec::new();
    if !resize_buffer(&mut pixels, buffer.width, buffer.height) {
        return Err(errno_status(mochi_user_syscall::ENOMEM));
    }
    let stride =
        usize::try_from(buffer.stride).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let width =
        usize::try_from(buffer.width).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let height =
        usize::try_from(buffer.height).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let row_bytes = stride
        .checked_mul(4)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let needed = row_bytes
        .checked_mul(height)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    if buffer.byte_len < needed {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let source =
        unsafe { core::slice::from_raw_parts(buffer.mapped_addr as *const u8, buffer.byte_len) };
    for y in 0..height {
        let src_row = y
            .checked_mul(stride)
            .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        let dst_row = y
            .checked_mul(width)
            .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        for x in 0..width {
            let src = src_row
                .checked_add(x)
                .and_then(|offset| offset.checked_mul(4))
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
            let Some(pixel) = read_pixel(source, src) else {
                return Err(errno_status(mochi_user_syscall::EINVAL));
            };
            let dst = dst_row
                .checked_add(x)
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
            let Some(slot) = pixels.get_mut(dst) else {
                return Err(errno_status(mochi_user_syscall::EINVAL));
            };
            *slot = pixel;
        }
    }
    Ok(pixels)
}

fn copy_surface_buffer_rect(
    buffer: &SurfaceBuffer,
    rect: Rect,
    destination: &mut [u32],
    destination_width: u32,
    destination_height: u32,
) -> Result<(), u32> {
    let rect = validate_damage_rect(rect, destination_width, destination_height)?;
    if buffer.width != destination_width || buffer.height != destination_height {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let stride =
        usize::try_from(buffer.stride).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let width =
        usize::try_from(destination_width).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let height = usize::try_from(destination_height)
        .map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let row_bytes = stride
        .checked_mul(4)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let needed = row_bytes
        .checked_mul(height)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    if buffer.byte_len < needed || destination.len() < width.saturating_mul(height) {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let source =
        unsafe { core::slice::from_raw_parts(buffer.mapped_addr as *const u8, buffer.byte_len) };
    let left = rect.x as usize;
    let top = rect.y as usize;
    let right = left.saturating_add(rect.width as usize);
    let bottom = top.saturating_add(rect.height as usize);
    for y in top..bottom {
        let src_row = y
            .checked_mul(stride)
            .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        let dst_row = y
            .checked_mul(width)
            .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        for x in left..right {
            let src = src_row
                .checked_add(x)
                .and_then(|offset| offset.checked_mul(4))
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
            let Some(pixel) = read_pixel(source, src) else {
                return Err(errno_status(mochi_user_syscall::EINVAL));
            };
            let dst = dst_row
                .checked_add(x)
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
            let Some(slot) = destination.get_mut(dst) else {
                return Err(errno_status(mochi_user_syscall::EINVAL));
            };
            *slot = pixel;
        }
    }
    Ok(())
}

pub(crate) fn shared_page_count(byte_len: usize) -> Option<usize> {
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
    if !matches!(
        format,
        PIXEL_FORMAT_XRGB8888 | PIXEL_FORMAT_ARGB8888_PREMULTIPLIED | PIXEL_FORMAT_GPU_SCENE
    ) || width == 0
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

pub(crate) fn send_frame_done(surface: &Surface) {
    if surface.event_endpoint == 0 || surface.is_decoration {
        return;
    }
    let mut event = [0u8; 20];
    put_u32(&mut event, 0, EVENT_FRAME_DONE);
    let _ = platform::ipc::send(surface.event_endpoint, &event);
}

pub(crate) fn handle_shared_buffer(
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
        surface.pending_format,
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
        format: surface.pending_format,
    });
    surface.pending_bytes_received = needed_bytes;
    surface.pending_len = pixels;
    surface.pending_damage = Some(Rect::full(width, height));
    surface.awaiting_buffer = false;
    true
}

pub(crate) fn handle_request(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    next_z: &mut u32,
    next_window_index: &mut u32,
    next_window_id: &mut u64,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    client: ClientId,
    sender: u64,
    request: &[u8],
    needs_present: &mut bool,
    present_damage: &mut Option<Rect>,
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
            let rights = if role == SurfaceRole::SecureOverlay {
                if sender_has_secure_overlay_capability(sender) {
                    SurfaceRights::GENERAL_CLIENT
                } else {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                    return reply;
                }
            } else if sender_has_overlay_compat_capability(sender) {
                match role.privileged_overlay_rights() {
                    Ok(rights) => rights,
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
                }
            } else {
                match role.general_client_rights() {
                    Ok(rights) => rights,
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
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
            let z = if role == SurfaceRole::Background {
                0
            } else {
                *next_z = next_z.wrapping_add(1);
                *next_z
            };
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
            } else if matches!(
                role,
                SurfaceRole::Background | SurfaceRole::Panel | SurfaceRole::SecureOverlay
            ) {
                (0, 0)
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
            surfaces[index].z = z;
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
            let attach_reject_reason = if !matches!(
                format,
                PIXEL_FORMAT_XRGB8888
                    | PIXEL_FORMAT_ARGB8888_PREMULTIPLIED
                    | PIXEL_FORMAT_GPU_SCENE
            ) {
                Some(1)
            } else if matches!(
                format,
                PIXEL_FORMAT_ARGB8888_PREMULTIPLIED | PIXEL_FORMAT_GPU_SCENE
            ) && surfaces[index].role != SurfaceRole::Panel
            {
                Some(1)
            } else if width == 0 {
                Some(2)
            } else if height == 0 {
                Some(3)
            } else if stride < width {
                Some(4)
            } else if width > MAX_DIMENSION || height > MAX_DIMENSION {
                Some(5)
            } else {
                None
            };
            if let Some(reason) = attach_reject_reason {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                put_u32(&mut reply, 4, reason);
                put_u32(&mut reply, 8, height);
                put_u32(&mut reply, 12, height);
                return reply;
            }
            let (row_bytes, needed, pixels) =
                match validate_buffer_layout(width, height, stride, format, width, height) {
                    Ok(layout) => layout,
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
                };
            if request.len() == 28 {
                let surface = &mut surfaces[index];
                surface.width = width;
                surface.height = height;
                surface.pending_width = width;
                surface.pending_height = height;
                surface.pending_stride = stride;
                surface.pending_format = format;
                surface.pending_len = pixels;
                surface.pending_bytes_received = 0;
                surface.pending.clear();
                surface.pending_buffer = None;
                surface.pending_damage = Some(Rect::full(width, height));
                if let Some(buffer) = surface.current_buffer.as_ref() {
                    if buffer.width == width
                        && buffer.height == height
                        && buffer.stride == stride
                        && buffer.pixels == pixels
                        && buffer.format == format
                    {
                        surface.pending_buffer = Some(buffer.clone());
                        surface.pending_bytes_received = buffer.byte_len;
                        surface.awaiting_buffer = false;
                    } else {
                        surface.awaiting_buffer = true;
                    }
                } else {
                    surface.awaiting_buffer = true;
                }
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
                surface.width = width;
                surface.height = height;
                surface.pending = pending;
                surface.pending_width = width;
                surface.pending_height = height;
                surface.pending_stride = stride;
                surface.pending_format = format;
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
            if surfaces[index].pending_width == 0 {
                if let Some(buffer) = surfaces[index].current_buffer.clone() {
                    let surface = &mut surfaces[index];
                    surface.pending_width = buffer.width;
                    surface.pending_height = buffer.height;
                    surface.pending_stride = buffer.stride;
                    surface.pending_format = buffer.format;
                    surface.pending_len = buffer.pixels;
                    surface.pending_bytes_received = buffer.byte_len;
                    surface.pending_buffer = Some(buffer);
                    surface.awaiting_buffer = false;
                }
            }
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
            let (
                pending_width,
                pending_height,
                pending_len,
                pending_stride,
                pending_format,
                awaiting_buffer,
            ) = {
                let surface = &surfaces[index];
                (
                    surface.pending_width,
                    surface.pending_height,
                    surface.pending_len,
                    surface.pending_stride,
                    surface.pending_format,
                    surface.awaiting_buffer,
                )
            };
            let pending_damage = surfaces[index]
                .pending_damage
                .unwrap_or(Rect::full(pending_width, pending_height));
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
                if pending_format == PIXEL_FORMAT_GPU_SCENE {
                    let Some(buffer) = surface.pending_buffer.as_ref().cloned() else {
                        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                        return reply;
                    };
                    let gpu =
                        match update_gpu_surface_state(surface.gpu.take(), &buffer, pending_damage)
                        {
                            Ok(gpu) => gpu,
                            Err(status) => {
                                put_u32(&mut reply, 0, status);
                                return reply;
                            }
                        };
                    surface.gpu = Some(gpu);
                    surface.current_buffer = surface.pending_buffer.take();
                    surface.current.clear();
                    surface.current_stride = pending_stride;
                } else if matches!(surface.role, SurfaceRole::Background | SurfaceRole::Panel) {
                    if let Some(buffer) = surface.pending_buffer.take() {
                        let can_patch_current = surface.current_width == pending_width
                            && surface.current_height == pending_height
                            && surface.current_stride == pending_width
                            && surface.current.len() >= needed;
                        if can_patch_current {
                            if let Err(status) = copy_surface_buffer_rect(
                                &buffer,
                                pending_damage,
                                &mut surface.current,
                                pending_width,
                                pending_height,
                            ) {
                                put_u32(&mut reply, 0, status);
                                return reply;
                            }
                            surface.current_buffer = Some(buffer);
                        } else {
                            match copy_surface_buffer(&buffer) {
                                Ok(pixels) => {
                                    surface.current = pixels;
                                    surface.current_buffer = Some(buffer);
                                }
                                Err(status) => {
                                    put_u32(&mut reply, 0, status);
                                    return reply;
                                }
                            }
                        }
                    } else {
                        surface.current_buffer = None;
                        core::mem::swap(&mut surface.current, &mut surface.pending);
                    }
                    surface.current_stride = pending_width;
                } else {
                    surface.current_buffer = surface.pending_buffer.take();
                    if surface.current_buffer.is_some() {
                        surface.current.clear();
                    } else {
                        core::mem::swap(&mut surface.current, &mut surface.pending);
                    }
                    surface.current_stride = pending_stride;
                }
                surface.current_width = pending_width;
                surface.current_height = pending_height;
                surface.current_format = pending_format;
                if pending_format != PIXEL_FORMAT_GPU_SCENE {
                    surface.gpu = None;
                }
                surface.content_generation = surface.content_generation.wrapping_add(1).max(1);
                surface.pending_width = 0;
                surface.pending_height = 0;
                surface.pending_stride = 0;
                surface.pending_format = PIXEL_FORMAT_XRGB8888;
                surface.pending_len = 0;
                surface.pending_bytes_received = 0;
                surface.pending_damage = None;
                surface.pending_buffer = None;
                surface.awaiting_buffer = false;
            }
            *needs_present = true;
            let screen_damage = Rect {
                x: surfaces[index].x.saturating_add(pending_damage.x),
                y: surfaces[index].y.saturating_add(pending_damage.y),
                width: pending_damage.width,
                height: pending_damage.height,
            };
            *present_damage = merge_damage(*present_damage, screen_damage);
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
        _ => put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL)),
    }
    reply
}
