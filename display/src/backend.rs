use crate::framebuffer_backend::FramebufferBackend;
use crate::present::{DisplayGeometry, PresentFrame};
use crate::virtio_gpu_backend::{GpuError, VirtioGpuBackend};

pub(crate) enum DisplayBackend {
    VirtioGpu(VirtioGpuBackend),
    Framebuffer(FramebufferBackend),
}

impl DisplayBackend {
    pub(crate) fn initialize() -> Result<Self, u64> {
        match VirtioGpuBackend::initialize() {
            Ok(backend) => {
                mochi_user_platform::println!("display.driver: backend=virtio-gpu");
                if let Some((capset, version, size)) = backend.virgl_capability() {
                    mochi_user_platform::println!(
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

    pub(crate) fn present(&mut self, frame: &PresentFrame<'_>) -> Result<(), u64> {
        match self {
            Self::VirtioGpu(backend) => backend.present(frame).map_err(GpuError::errno),
            Self::Framebuffer(backend) => backend.present(frame),
        }
    }
}

fn log_fallback_once(error: GpuError) {
    mochi_user_platform::println!(
        "display.driver: virtio-gpu unavailable, using framebuffer fallback reason={:?}",
        error
    );
}
