use alloc::vec::Vec;

use crate::WindowId;
use crate::client::ClientId;
use crate::geometry::Rect;
use crate::protocol::{
    ROLE_BACKGROUND, ROLE_PANEL, ROLE_POPUP, ROLE_SECURE_OVERLAY, ROLE_TOPLEVEL, errno_status,
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
    pub(crate) pending_len: usize,
    pub(crate) pending_bytes_received: usize,
    pub(crate) awaiting_buffer: bool,
    pub(crate) pending_damage: Option<Rect>,
    pub(crate) pending_buffer: Option<SurfaceBuffer>,
    pub(crate) pending: Vec<u32>,
    pub(crate) current_width: u32,
    pub(crate) current_height: u32,
    pub(crate) current_stride: u32,
    pub(crate) current_buffer: Option<SurfaceBuffer>,
    pub(crate) current: Vec<u32>,
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
