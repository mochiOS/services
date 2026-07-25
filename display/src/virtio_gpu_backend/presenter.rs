use mochios_virtio_gpu_protocol::{Command, Rect, TransferToHost2d};

use crate::present::{DisplayGeometry, PresentFrame};

use super::control::ControlChannel;
use super::dma::BackingStore;
use super::error::GpuError;
use super::resource::RESOURCE_ID;

pub(super) fn present(
    channel: &mut ControlChannel,
    backing: &mut BackingStore,
    geometry: DisplayGeometry,
    frame: &PresentFrame<'_>,
) -> Result<(), GpuError> {
    frame.validate().map_err(GpuError::System)?;
    if frame.geometry.width != geometry.width
        || frame.geometry.height != geometry.height
        || frame.geometry.format != geometry.format
    {
        return Err(GpuError::InvalidFrame);
    }
    if frame.damage.is_empty() {
        return Ok(());
    }
    backing
        .copy_rect(
            frame.pixels,
            frame.geometry.stride,
            geometry.stride,
            frame.damage,
        )
        .map_err(GpuError::System)?;
    let rect = Rect {
        x: frame.damage.x,
        y: frame.damage.y,
        width: frame.damage.width,
        height: frame.damage.height,
    };
    let offset = u64::from(frame.damage.y)
        .checked_mul(u64::from(geometry.stride))
        .and_then(|pixels| pixels.checked_add(u64::from(frame.damage.x)))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(GpuError::InvalidFrame)?;
    transfer_and_flush(channel, rect, offset)
}

pub(super) fn present_initial(
    channel: &mut ControlChannel,
    geometry: DisplayGeometry,
) -> Result<(), GpuError> {
    let rect = Rect {
        x: 0,
        y: 0,
        width: geometry.width,
        height: geometry.height,
    };
    transfer_and_flush(channel, rect, 0)
}

fn transfer_and_flush(
    channel: &mut ControlChannel,
    rect: Rect,
    offset: u64,
) -> Result<(), GpuError> {
    channel.submit_no_data(Command::TransferToHost2d(TransferToHost2d {
        rect,
        offset,
        resource_id: RESOURCE_ID,
    }))?;
    channel.submit_no_data(Command::ResourceFlush {
        rect,
        resource_id: RESOURCE_ID,
    })
}
