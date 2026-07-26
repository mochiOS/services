use mochios_virtio_gpu_protocol::{Command, Rect, SetScanout};

use crate::present::DisplayGeometry;

use super::control::ControlChannel;
use super::error::GpuError;
use super::resource::RESOURCE_ID;

#[derive(Default)]
pub(super) struct ScanoutState {
    enabled: bool,
}

impl ScanoutState {
    pub(super) fn enable(
        &mut self,
        channel: &mut ControlChannel,
        scanout_id: u32,
        geometry: DisplayGeometry,
    ) -> Result<(), GpuError> {
        channel.submit_no_data(Command::SetScanout(SetScanout {
            rect: Rect {
                x: 0,
                y: 0,
                width: geometry.width,
                height: geometry.height,
            },
            scanout_id,
            resource_id: RESOURCE_ID,
        }))?;
        self.enabled = true;
        Ok(())
    }

    pub(super) fn cleanup(&mut self, channel: &mut ControlChannel, scanout_id: u32) {
        if !self.enabled {
            return;
        }
        let _ = channel.submit_no_data(Command::SetScanout(SetScanout {
            rect: Rect::default(),
            scanout_id,
            resource_id: 0,
        }));
        self.enabled = false;
    }
}
