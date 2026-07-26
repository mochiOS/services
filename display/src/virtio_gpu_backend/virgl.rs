use mochios_virtio_gpu_protocol::{
    CAPSET_VIRGL, CAPSET_VIRGL2, CapsetInfo, Command, ContextCreate, GetCapset, Response,
};

use super::control::ControlChannel;
use super::error::GpuError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VirglCapability {
    pub(super) id: u32,
    pub(super) version: u32,
    pub(super) maximum_size: u32,
}

pub(super) struct VirglState {
    capability: VirglCapability,
    context_id: u32,
}

impl VirglState {
    pub(super) fn initialize(
        channel: &mut ControlChannel,
        capability: VirglCapability,
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
        Ok(Self {
            capability,
            context_id,
        })
    }

    pub(super) const fn capability(&self) -> VirglCapability {
        self.capability
    }

    pub(super) fn cleanup(&mut self, channel: &mut ControlChannel) {
        if self.context_id == 0 {
            return;
        }
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
