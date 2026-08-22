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
    pub(crate) fn renderer_caps(&self) -> u32 {
        match self {
            Self::VirtioGpu(backend) if backend.gpu_scene_supported() => {
                crate::protocol::RENDERER_CAP_GPU_SCENE
            }
            _ => 0,
        }
    }

    pub(crate) fn initialize() -> Result<Self, u64> {
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
    ) -> Result<(), u64> {
        match self {
            Self::VirtioGpu(backend) => backend.present_gpu_scene(scene).map_err(|error| {
                mochi_user_platform::logln!(
                    "display.driver: ViewKit GPU backend error={:?}",
                    error
                );
                error.errno()
            }),
            Self::Framebuffer(_) => Err(mochi_user_syscall::ENOSYS),
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
