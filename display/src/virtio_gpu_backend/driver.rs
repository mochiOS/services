use crate::present::{DisplayGeometry, PresentFrame};

use super::control::ControlChannel;
use super::display_info;
use super::dma::BackingStore;
use super::error::GpuError;
use super::presenter;
use super::resource::ResourceState;
use super::scanout::ScanoutState;
use super::virgl::{self, VirglState};

pub(crate) struct VirtioGpuBackend {
    control: ControlChannel,
    backing: Option<BackingStore>,
    geometry: DisplayGeometry,
    scanout_id: u32,
    resource: ResourceState,
    scanout: ScanoutState,
    virgl: Option<VirglState>,
}

impl VirtioGpuBackend {
    pub(crate) fn initialize() -> Result<Self, GpuError> {
        let mut control = ControlChannel::initialize()?;
        let virgl_capability = virgl::query(&mut control)?;
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
        let virgl = if let Some(capability) = virgl_capability {
            match VirglState::initialize(&mut control, capability) {
                Ok(virgl) => Some(virgl),
                Err(error) => {
                    scanout.cleanup(&mut control, scanout_id);
                    resource.cleanup(&mut control);
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok(Self {
            control,
            backing: Some(backing),
            geometry,
            scanout_id,
            resource,
            scanout,
            virgl,
        })
    }

    pub(crate) const fn geometry(&self) -> DisplayGeometry {
        self.geometry
    }

    pub(crate) const fn virgl_capability(&self) -> Option<(u32, u32, u32)> {
        match &self.virgl {
            Some(state) => {
                let capability = state.capability();
                Some((capability.id, capability.version, capability.maximum_size))
            }
            None => None,
        }
    }

    pub(crate) fn present(&mut self, frame: &PresentFrame<'_>) -> Result<(), GpuError> {
        let backing = self.backing.as_mut().ok_or(GpuError::InvalidFrame)?;
        presenter::present(&mut self.control, backing, self.geometry, frame)
    }

    fn cleanup(&mut self) {
        if let Some(virgl) = &mut self.virgl {
            virgl.cleanup(&mut self.control);
        }
        self.virgl = None;
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
