use mochios_virtio_gpu_protocol::{
    CAPSET_VIRGL, CAPSET_VIRGL2, CapsetInfo, Command, ContextCreate, GetCapset, Response,
};

use super::control::ControlChannel;
use super::error::GpuError;
use super::virgl_panel::PanelRenderer;
use super::virgl_scene::SceneRenderer;
use crate::present::{DisplayGeometry, PanelFrame};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VirglCapability {
    pub(super) id: u32,
    pub(super) version: u32,
    pub(super) maximum_size: u32,
}

pub(super) struct VirglState {
    capability: VirglCapability,
    context_id: u32,
    panel: Option<PanelRenderer>,
    scene: Option<SceneRenderer>,
}

impl VirglState {
    pub(super) fn initialize(
        channel: &mut ControlChannel,
        capability: VirglCapability,
        geometry: DisplayGeometry,
    ) -> Result<Self, GpuError> {
        let length = channel.execute(Command::GetCapset(GetCapset {
            capset_id: capability.id,
            version: capability.version,
        }))?;
        let data = match Response::decode(channel.response(length))? {
            Response::Capset(data) => data,
            Response::Error(error) => return Err(GpuError::DeviceResponse(error)),
            _ => return Err(GpuError::InvalidDisplayInfo),
        };
        if data.len() != capability.maximum_size as usize {
            return Err(GpuError::InvalidDisplayInfo);
        }
        let context_id = 1;
        channel.submit_no_data(Command::ContextCreate(ContextCreate {
            context_id,
            context_init: 0,
            debug_name: b"mochios-display",
        }))?;
        let panel = match PanelRenderer::initialize(channel, geometry) {
            Ok(panel) => Some(panel),
            Err(error) => {
                mochi_user_platform::println!(
                    "display.driver: virgl panel initialization failed error={:?}",
                    error
                );
                None
            }
        };
        let scene = match SceneRenderer::initialize(channel, geometry) {
            Ok(scene) => Some(scene),
            Err(error) => {
                mochi_user_platform::println!(
                    "display.driver: ViewKit GPU initialization failed error={:?}",
                    error
                );
                None
            }
        };
        Ok(Self {
            capability,
            context_id,
            panel,
            scene,
        })
    }

    pub(super) const fn capability(&self) -> VirglCapability {
        self.capability
    }

    pub(super) fn scene_supported(&self) -> bool {
        self.scene.is_some()
    }

    pub(super) fn present_scene(
        &mut self,
        channel: &mut ControlChannel,
        scanout_id: u32,
        scene: &mochios_viewkit_gpu_protocol::Scene<'_>,
    ) -> Result<(), GpuError> {
        self.scene
            .as_mut()
            .ok_or(GpuError::InvalidFrame)?
            .present(channel, scanout_id, scene)
    }

    pub(super) fn present_panel(
        &mut self,
        channel: &mut ControlChannel,
        scanout_id: u32,
        geometry: DisplayGeometry,
        frame: &PanelFrame<'_>,
    ) -> Result<(), GpuError> {
        let _ = geometry;
        self.panel
            .as_mut()
            .ok_or(GpuError::InvalidFrame)?
            .present(channel, scanout_id, frame)
    }

    pub(super) fn cleanup(&mut self, channel: &mut ControlChannel) {
        if self.context_id == 0 {
            return;
        }
        if let Some(panel) = &mut self.panel {
            panel.cleanup(channel);
        }
        self.panel = None;
        if let Some(scene) = &mut self.scene {
            scene.cleanup(channel);
        }
        self.scene = None;
        let _ = channel.submit_no_data(Command::ContextDestroy {
            context_id: self.context_id,
        });
        self.context_id = 0;
    }
}

pub(super) fn query(channel: &mut ControlChannel) -> Result<Option<VirglCapability>, GpuError> {
    if !channel.virgl_supported() {
        return Ok(None);
    }
    let mut selected = None;
    for index in 0..channel.capset_count() {
        let length = channel.execute(Command::GetCapsetInfo { index })?;
        let info = match Response::decode(channel.response(length))? {
            Response::CapsetInfo(info) => info,
            Response::Error(error) => return Err(GpuError::DeviceResponse(error)),
            _ => return Err(GpuError::InvalidDisplayInfo),
        };
        if matches!(info.id, CAPSET_VIRGL | CAPSET_VIRGL2) {
            let candidate = from_info(info);
            if selected.is_none_or(|current: VirglCapability| candidate.id > current.id) {
                selected = Some(candidate);
            }
        }
    }
    Ok(selected)
}

const fn from_info(info: CapsetInfo) -> VirglCapability {
    VirglCapability {
        id: info.id,
        version: info.maximum_version,
        maximum_size: info.maximum_size,
    }
}
