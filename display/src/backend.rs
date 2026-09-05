use crate::framebuffer_backend::FramebufferBackend;
use crate::present::{DisplayGeometry, PanelFrame, PresentFrame};
use crate::virtio_gpu_backend::{GpuError, VirtioGpuBackend};

pub(crate) enum DisplayBackend {
    VirtioGpu(VirtioGpuBackend),
    Framebuffer(FramebufferBackend),
}

pub(crate) enum PendingPresent {
    VirtioGpu(crate::virtio_gpu_backend::PendingPresent),
}

impl DisplayBackend {
    pub(crate) fn present_startup_frame(&mut self) -> Result<(), u64> {
        // ViewKit's mochiOS accent. Binder replaces this frame as soon as the
        // compositor publishes the desktop.
        const STARTUP_COLOR: u32 = 0x0076_51c9;
        match self {
            Self::Framebuffer(backend) if !backend.gpu_scene_supported() => {
                backend.present_startup_frame(STARTUP_COLOR)
            }
            Self::Framebuffer(_) => Ok(()),
            Self::VirtioGpu(_) => Ok(()),
        }
    }

    pub(crate) fn renderer_caps(&self) -> u32 {
        match self {
            Self::VirtioGpu(backend) if backend.gpu_scene_supported() => {
                crate::protocol::RENDERER_CAP_GPU_SCENE
            }
            // mDriver's shared framebuffer transport only proves that a Linux
            // framebuffer exists.  It does not prove that the separate KMS/EGL
            // renderer owns a working scanout.  Advertising GPU scenes here
            // made every client discard its CPU buffer before that renderer
            // was ready, leaving no visible fallback when KMS setup failed.
            // Keep physical displays on the framebuffer path until mDriver
            // provides an explicit renderer-ready handshake.
            Self::Framebuffer(_) => 0,
            _ => 0,
        }
    }

    pub(crate) fn initialize() -> Result<Self, u64> {
        // A framebuffer reported by the kernel is already the selected display
        // path. It is either mediated by mDriver (address zero) or the firmware
        // framebuffer retained for a system without an IOMMU (non-zero). In
        // both cases PCI probing from mochiOS is invalid and may never complete
        // because mBoot deliberately exposes no PCI functions.
        if mochi_user_platform::memory::framebuffer_info().is_ok() {
            return FramebufferBackend::initialize().map(Self::Framebuffer);
        }
        match VirtioGpuBackend::initialize() {
            Ok(backend) => {
                mochi_user_platform::logln!("display.driver: backend=virtio-gpu");
                if let Some((capset, version, size)) = backend.virgl_capability() {
                    mochi_user_platform::logln!(
                        "display.driver: virgl capset={} version={} size={}",
                        capset,
                        version,
                        size
                    );
                }
                Ok(Self::VirtioGpu(backend))
            }
            Err(error) => {
                log_fallback_once(error);
                FramebufferBackend::initialize().map(Self::Framebuffer)
            }
        }
    }

    pub(crate) fn geometry(&self) -> DisplayGeometry {
        match self {
            Self::VirtioGpu(backend) => backend.geometry(),
            Self::Framebuffer(backend) => backend.geometry(),
        }
    }

    pub(crate) fn prepare_present(
        &mut self,
        frame: &PresentFrame<'_>,
    ) -> Result<Option<PendingPresent>, u64> {
        match self {
            Self::VirtioGpu(backend) => backend
                .prepare_present(frame)
                .map(|pending| pending.map(PendingPresent::VirtioGpu))
                .map_err(GpuError::errno),
            Self::Framebuffer(backend) => backend.present(frame).map(|_| None),
        }
    }

    pub(crate) fn finish_present(&mut self, pending: PendingPresent) -> Result<(), u64> {
        match (self, pending) {
            (Self::VirtioGpu(backend), PendingPresent::VirtioGpu(pending)) => {
                backend.finish_present(pending).map_err(GpuError::errno)
            }
            (Self::Framebuffer(_), PendingPresent::VirtioGpu(_)) => Err(mochi_user_syscall::EINVAL),
        }
    }

    pub(crate) fn present_gpu_panel(&mut self, frame: &PanelFrame<'_>) -> Result<(), u64> {
        match self {
            Self::VirtioGpu(backend) => backend.present_gpu_panel(frame).map_err(|error| {
                mochi_user_platform::logln!(
                    "display.driver: virgl panel backend error={:?}",
                    error
                );
                error.errno()
            }),
            Self::Framebuffer(_) => Err(mochi_user_syscall::ENOSYS),
        }
    }

    pub(crate) fn present_gpu_scene(
        &mut self,
        scene: &mochios_viewkit_gpu_protocol::compositor::Scene<'_>,
        bytes: &[u8],
    ) -> Result<(), u64> {
        match self {
            Self::VirtioGpu(backend) => backend.present_gpu_scene(scene).map_err(|error| {
                mochi_user_platform::logln!(
                    "display.driver: ViewKit GPU backend error={:?}",
                    error
                );
                error.errno()
            }),
            Self::Framebuffer(backend) => backend.present_gpu_scene(bytes),
        }
    }

    pub(crate) fn set_cursor_image(
        &mut self,
        width: u32,
        height: u32,
        hotspot_x: u32,
        hotspot_y: u32,
        rgba: &[u8],
    ) -> Result<(), u64> {
        match self {
            Self::VirtioGpu(backend) => backend
                .set_cursor_image(width, height, hotspot_x, hotspot_y, rgba)
                .map_err(|error| {
                    mochi_user_platform::logln!(
                        "display.driver: hardware cursor backend error={:?}",
                        error
                    );
                    error.errno()
                }),
            Self::Framebuffer(_) => Err(mochi_user_syscall::ENOSYS),
        }
    }

    pub(crate) fn set_cursor_position(&mut self, x: u32, y: u32, visible: bool) -> Result<(), u64> {
        match self {
            Self::VirtioGpu(backend) => backend
                .set_cursor_position(x, y, visible)
                .map_err(GpuError::errno),
            Self::Framebuffer(_) => Err(mochi_user_syscall::ENOSYS),
        }
    }
}

fn log_fallback_once(error: GpuError) {
    mochi_user_platform::logln!(
        "display.driver: virtio-gpu unavailable, using framebuffer fallback reason={:?}",
        error
    );
}
