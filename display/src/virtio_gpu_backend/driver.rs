use crate::present::{DisplayGeometry, PanelFrame, PresentFrame};

use super::control::ControlChannel;
use super::cursor::CursorState;
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
    cursor: CursorState,
    panel_active: bool,
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
        let cursor = CursorState::initialize().map_err(GpuError::System)?;
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
            match VirglState::initialize(&mut control, capability, geometry) {
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
            cursor,
            panel_active: false,
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

    pub(crate) fn gpu_scene_supported(&self) -> bool {
        self.virgl.as_ref().is_some_and(VirglState::scene_supported)
    }

    pub(crate) fn prepare_present(
        &mut self,
        frame: &PresentFrame<'_>,
    ) -> Result<Option<presenter::PendingPresent>, GpuError> {
        if self.panel_active {
            self.scanout
                .enable(&mut self.control, self.scanout_id, self.geometry)?;
            self.panel_active = false;
        }
        let backing = self.backing.as_mut().ok_or(GpuError::InvalidFrame)?;
        presenter::stage(backing, self.geometry, frame)
    }

    pub(crate) fn finish_present(
        &mut self,
        pending: presenter::PendingPresent,
    ) -> Result<(), GpuError> {
        presenter::flush(&mut self.control, pending)
    }

    pub(crate) fn present_gpu_panel(&mut self, frame: &PanelFrame<'_>) -> Result<(), GpuError> {
        let virgl = self.virgl.as_mut().ok_or(GpuError::InvalidFrame)?;
        virgl.present_panel(&mut self.control, self.scanout_id, self.geometry, frame)?;
        self.panel_active = true;
        Ok(())
    }

    pub(crate) fn present_gpu_scene(
        &mut self,
        scene: &mochios_viewkit_gpu_protocol::compositor::Scene<'_>,
    ) -> Result<(), GpuError> {
        let virgl = self.virgl.as_mut().ok_or(GpuError::InvalidFrame)?;
        virgl.present_scene(&mut self.control, self.scanout_id, scene)?;
        self.panel_active = true;
        Ok(())
    }

    pub(crate) fn set_cursor_image(
        &mut self,
        width: u32,
        height: u32,
        hotspot_x: u32,
        hotspot_y: u32,
        rgba: &[u8],
    ) -> Result<(), GpuError> {
        self.cursor
            .set_image(&mut self.control, width, height, hotspot_x, hotspot_y, rgba)
    }

    pub(crate) fn set_cursor_position(
        &mut self,
        x: u32,
        y: u32,
        visible: bool,
    ) -> Result<(), GpuError> {
        self.cursor
            .set_position(&mut self.control, self.scanout_id, x, y, visible)
    }

    fn cleanup(&mut self) {
        self.cursor.cleanup(&mut self.control);
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
