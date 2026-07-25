use mochios_virtio_gpu_protocol::{DecodeError, EncodeError, ResponseError};
use plugkit::virtio::VirtioError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GpuError {
    Transport(VirtioError),
    Encode(EncodeError),
    Decode(DecodeError),
    DeviceResponse(ResponseError),
    InvalidDisplayInfo,
    InvalidFrame,
    System(u64),
}

impl GpuError {
    pub(crate) const fn errno(self) -> u64 {
        match self {
            Self::System(errno) => errno,
            Self::InvalidFrame | Self::Encode(_) => mochi_user_syscall::EINVAL,
            Self::Transport(_)
            | Self::Decode(_)
            | Self::DeviceResponse(_)
            | Self::InvalidDisplayInfo => mochi_user_syscall::EIO,
        }
    }
}

impl From<VirtioError> for GpuError {
    fn from(error: VirtioError) -> Self {
        Self::Transport(error)
    }
}

impl From<EncodeError> for GpuError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

impl From<DecodeError> for GpuError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}
