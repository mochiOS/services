use mochios_virtio_gpu_protocol::{Command, DisplayInfoView, Response};

use super::control::ControlChannel;
use super::error::GpuError;

pub(super) fn query(channel: &mut ControlChannel) -> Result<(u32, u32, u32), GpuError> {
    let length = channel.execute(Command::GetDisplayInfo)?;
    match Response::decode(channel.response(length))? {
        Response::DisplayInfo(view) => select_scanout(view),
        Response::Error(error) => Err(GpuError::DeviceResponse(error)),
        Response::NoData => Err(GpuError::InvalidDisplayInfo),
    }
}

fn select_scanout(view: DisplayInfoView<'_>) -> Result<(u32, u32, u32), GpuError> {
    for index in 0..mochios_virtio_gpu_protocol::DISPLAY_MODE_COUNT {
        let mode = view.mode(index)?.ok_or(GpuError::InvalidDisplayInfo)?;
        if mode.enabled
            && mode.rect.width != 0
            && mode.rect.height != 0
            && mode.rect.width <= crate::present::MAX_DIMENSION
            && mode.rect.height <= crate::present::MAX_DIMENSION
        {
            return Ok((index as u32, mode.rect.width, mode.rect.height));
        }
    }
    Err(GpuError::InvalidDisplayInfo)
}
