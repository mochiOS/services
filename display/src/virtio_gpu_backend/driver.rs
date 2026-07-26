use crate::present::{DisplayGeometry, PresentFrame};

use super::control::ControlChannel;
use super::display_info;
use super::dma::BackingStore;
use super::error::GpuError;
use super::presenter;
use super::resource::ResourceState;
use super::scanout::ScanoutState;

pub(crate) struct VirtioGpuBackend {
    control: ControlChannel,
    backing: Option<BackingStore>,
    geometry: DisplayGeometry,
    scanout_id: u32,
    resource: ResourceState,
    scanout: ScanoutState,
}

impl VirtioGpuBackend {
    pub(crate) fn initialize() -> Result<Self, GpuError> {
        let mut control = ControlChannel::initialize()?;
        let (scanout_id, width, height) = display_info::query(&mut control)?;
        let geometry = DisplayGeometry {
            width,
            height,
            stride: width,
            format: crate::present::PIXEL_FORMAT_XRGB8888,
        };
        let framebuffer_size = geometry.byte_len().map_err(GpuError::System)?;
        let backing = BackingStore::allocate(framebuffer_size).map_err(GpuError::System)?;
        let mut resource = ResourceState::default();
        resource.create(&mut control, &backing, geometry)?;
        let mut scanout = ScanoutState::default();
        if let Err(error) = scanout.enable(&mut control, scanout_id, geometry) {
            resource.cleanup(&mut control);
            return Err(error);
        }
        if let Err(error) = presenter::present_initial(&mut control, geometry) {
            scanout.cleanup(&mut control, scanout_id);
            resource.cleanup(&mut control);
            return Err(error);
        }
        Ok(Self {
            control,
            backing: Some(backing),
            geometry,
            scanout_id,
            resource,
            scanout,
        })
    }

    pub(crate) const fn geometry(&self) -> DisplayGeometry {
        self.geometry
    }

    pub(crate) fn present(&mut self, frame: &PresentFrame<'_>) -> Result<(), GpuError> {
        let backing = self.backing.as_mut().ok_or(GpuError::InvalidFrame)?;
        presenter::present(&mut self.control, backing, self.geometry, frame)
    }

    fn cleanup(&mut self) {
        self.scanout.cleanup(&mut self.control, self.scanout_id);
        self.resource.cleanup(&mut self.control);
        self.backing = None;
    }
}

impl Drop for VirtioGpuBackend {
    fn drop(&mut self) {
        self.cleanup();
    }
}
