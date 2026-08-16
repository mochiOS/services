use mochios_virtio_gpu_protocol::{
    AttachBacking, Command, CursorPosition, CursorUpdate, PixelFormat, Rect, ResourceCreate2d,
    ResourceOperation, TransferToHost2d,
};

use super::control::ControlChannel;
use super::dma::BackingStore;
use super::error::GpuError;

const CURSOR_RESOURCE_ID: u32 = 2;
const MAX_CURSOR_EXTENT: u32 = 64;
const CURSOR_BACKING_SIZE: usize = MAX_CURSOR_EXTENT as usize * MAX_CURSOR_EXTENT as usize * 4;

#[derive(Default)]
pub(super) struct CursorState {
    backing: Option<BackingStore>,
    created: bool,
    backing_attached: bool,
    image_ready: bool,
    visible: bool,
    hotspot_x: u32,
    hotspot_y: u32,
}

impl CursorState {
    pub(super) fn initialize() -> Result<Self, u64> {
        Ok(Self {
            backing: Some(BackingStore::allocate(CURSOR_BACKING_SIZE)?),
            ..Self::default()
        })
    }

    pub(super) fn set_image(
        &mut self,
        channel: &mut ControlChannel,
        width: u32,
        height: u32,
        hotspot_x: u32,
        hotspot_y: u32,
        rgba: &[u8],
    ) -> Result<(), GpuError> {
        if width == 0
            || height == 0
            || width > MAX_CURSOR_EXTENT
            || height > MAX_CURSOR_EXTENT
            || hotspot_x >= width
            || hotspot_y >= height
        {
            return Err(GpuError::InvalidFrame);
        }
        let length = (width as usize)
            .checked_mul(height as usize)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(GpuError::InvalidFrame)?;
        if rgba.len() != length {
            return Err(GpuError::InvalidFrame);
        }

        self.cleanup_resource(channel);
        let backing = self.backing.as_mut().ok_or(GpuError::InvalidFrame)?;
        backing
            .write_cursor_rgba(width, height, MAX_CURSOR_EXTENT, rgba)
            .map_err(GpuError::System)?;
        channel.submit_no_data(Command::ResourceCreate2d(ResourceCreate2d {
            resource_id: CURSOR_RESOURCE_ID,
            format: PixelFormat::B8G8R8A8_UNORM,
            width: MAX_CURSOR_EXTENT,
            height: MAX_CURSOR_EXTENT,
        }))?;
        self.created = true;
        if let Err(error) = channel.submit_no_data(Command::ResourceAttachBacking(AttachBacking {
            resource_id: CURSOR_RESOURCE_ID,
            entries: backing.entries(),
        })) {
            self.cleanup(channel);
            return Err(error);
        }
        self.backing_attached = true;
        let rect = Rect {
            x: 0,
            y: 0,
            width: MAX_CURSOR_EXTENT,
            height: MAX_CURSOR_EXTENT,
        };
        if let Err(error) = channel.submit_no_data(Command::TransferToHost2d(TransferToHost2d {
            rect,
            offset: 0,
            resource_id: CURSOR_RESOURCE_ID,
        })) {
            self.cleanup(channel);
            return Err(error);
        }
        self.image_ready = true;
        self.visible = false;
        self.hotspot_x = hotspot_x;
        self.hotspot_y = hotspot_y;
        Ok(())
    }

    pub(super) fn set_position(
        &mut self,
        channel: &mut ControlChannel,
        scanout_id: u32,
        x: u32,
        y: u32,
        visible: bool,
    ) -> Result<(), GpuError> {
        if visible && self.visible {
            if !self.image_ready {
                return Err(GpuError::InvalidFrame);
            }
            channel.submit_cursor(Command::MoveCursor(CursorPosition { scanout_id, x, y }))
        } else if visible {
            if !self.image_ready {
                return Err(GpuError::InvalidFrame);
            }
            channel.submit_cursor(Command::UpdateCursor(CursorUpdate {
                position: CursorPosition { scanout_id, x, y },
                resource_id: CURSOR_RESOURCE_ID,
                hotspot_x: self.hotspot_x,
                hotspot_y: self.hotspot_y,
            }))?;
            self.visible = true;
            Ok(())
        } else {
            let result = channel.submit_cursor(Command::UpdateCursor(CursorUpdate {
                position: CursorPosition { scanout_id, x, y },
                resource_id: 0,
                hotspot_x: 0,
                hotspot_y: 0,
            }));
            if result.is_ok() {
                self.visible = false;
            }
            result
        }
    }

    pub(super) fn cleanup(&mut self, channel: &mut ControlChannel) {
        self.cleanup_resource(channel);
        self.backing = None;
    }

    fn cleanup_resource(&mut self, channel: &mut ControlChannel) {
        self.image_ready = false;
        self.visible = false;
        if self.backing_attached {
            let _ = channel.submit_no_data(Command::ResourceDetachBacking(ResourceOperation {
                resource_id: CURSOR_RESOURCE_ID,
            }));
            self.backing_attached = false;
        }
        if self.created {
            let _ = channel.submit_no_data(Command::ResourceUnref(ResourceOperation {
                resource_id: CURSOR_RESOURCE_ID,
            }));
            self.created = false;
        }
    }
}
