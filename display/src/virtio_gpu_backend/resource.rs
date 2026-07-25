use mochios_virtio_gpu_protocol::{
    AttachBacking, Command, PixelFormat, Rect, ResourceCreate2d, ResourceOperation, SetScanout,
};

use crate::present::DisplayGeometry;

use super::control::ControlChannel;
use super::dma::BackingStore;
use super::error::GpuError;

pub(super) const RESOURCE_ID: u32 = 1;

#[derive(Default)]
pub(super) struct ResourceState {
    created: bool,
    backing_attached: bool,
    scanout_set: bool,
}

impl ResourceState {
    pub(super) fn create(
        &mut self,
        channel: &mut ControlChannel,
        backing: &BackingStore,
        geometry: DisplayGeometry,
        scanout_id: u32,
    ) -> Result<(), GpuError> {
        channel.submit_no_data(Command::ResourceCreate2d(ResourceCreate2d {
            resource_id: RESOURCE_ID,
            format: PixelFormat::B8G8R8X8_UNORM,
            width: geometry.width,
            height: geometry.height,
        }))?;
        self.created = true;
        channel.submit_no_data(Command::ResourceAttachBacking(AttachBacking {
            resource_id: RESOURCE_ID,
            entries: backing.entries(),
        }))?;
        self.backing_attached = true;
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
        self.scanout_set = true;
        Ok(())
    }

    pub(super) fn cleanup(&mut self, channel: &mut ControlChannel, scanout_id: u32) {
        if self.scanout_set {
            let _ = channel.submit_no_data(Command::SetScanout(SetScanout {
                rect: Rect::default(),
                scanout_id,
                resource_id: 0,
            }));
            self.scanout_set = false;
        }
        if self.backing_attached {
            let _ = channel.submit_no_data(Command::ResourceDetachBacking(ResourceOperation {
                resource_id: RESOURCE_ID,
            }));
            self.backing_attached = false;
        }
        if self.created {
            let _ = channel.submit_no_data(Command::ResourceUnref(ResourceOperation {
                resource_id: RESOURCE_ID,
            }));
            self.created = false;
        }
    }
}
