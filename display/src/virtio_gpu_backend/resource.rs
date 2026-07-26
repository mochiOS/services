use mochios_virtio_gpu_protocol::{
    AttachBacking, Command, PixelFormat, ResourceCreate2d, ResourceOperation,
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
}

impl ResourceState {
    pub(super) fn create(
        &mut self,
        channel: &mut ControlChannel,
        backing: &BackingStore,
        geometry: DisplayGeometry,
    ) -> Result<(), GpuError> {
        channel.submit_no_data(Command::ResourceCreate2d(ResourceCreate2d {
            resource_id: RESOURCE_ID,
            format: PixelFormat::B8G8R8X8_UNORM,
            width: geometry.width,
            height: geometry.height,
        }))?;
        self.created = true;
        if let Err(error) = channel.submit_no_data(Command::ResourceAttachBacking(AttachBacking {
            resource_id: RESOURCE_ID,
            entries: backing.entries(),
        })) {
            self.cleanup(channel);
            return Err(error);
        }
        self.backing_attached = true;
        Ok(())
    }

    pub(super) fn cleanup(&mut self, channel: &mut ControlChannel) {
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
