use core::cmp;

use mochi_user_platform as platform;
use mochios_virtio_gpu_protocol::{
    AttachBacking, Command, DecodeError, DisplayInfoView, EncodeError, PixelFormat, Rect,
    ResourceCreate2d, ResourceOperation, Response, ResponseError, SetScanout, TransferToHost2d,
};
use plugkit::virtio::{
    Descriptor, DmaMemory, FeatureSet, SplitVirtqueue, VIRTIO_F_VERSION_1, VirtioDevice,
    VirtioError, VirtioPciTransport, VirtqueueLayout,
};

use crate::present::{DisplayGeometry, PresentFrame};

use super::dma::{BackingStore, DmaRegion};
use super::pci::{MappedBars, connect};

const CONTROL_QUEUE_INDEX: u16 = 0;
const MAX_CONTROL_QUEUE_SIZE: u16 = 128;
const COMMAND_BUFFER_SIZE: usize = 4096;
const RESPONSE_BUFFER_SIZE: usize = 4096;
const COMMAND_TIMEOUT_POLLS: u32 = 100_000;
const RESOURCE_ID: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GpuError {
    Transport(VirtioError),
    Encode(EncodeError),
    Decode(DecodeError),
    DeviceResponse(ResponseError),
    InvalidDisplayInfo,
    InvalidFrame,
    System(u64),
}

impl GpuError {
    pub(crate) const fn errno(self) -> u64 {
        match self {
            Self::System(errno) => errno,
            Self::InvalidFrame | Self::Encode(_) => mochi_user_syscall::EINVAL,
            Self::Transport(_)
            | Self::Decode(_)
            | Self::DeviceResponse(_)
            | Self::InvalidDisplayInfo => mochi_user_syscall::EIO,
        }
    }
}

impl From<VirtioError> for GpuError {
    fn from(error: VirtioError) -> Self {
        Self::Transport(error)
    }
}

impl From<EncodeError> for GpuError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

impl From<DecodeError> for GpuError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

pub(crate) struct VirtioGpuBackend {
    device: VirtioDevice<MappedBars>,
    control_queue: SplitVirtqueue<DmaRegion>,
    control_notify_offset: u16,
    command: DmaRegion,
    response: DmaRegion,
    backing: Option<BackingStore>,
    geometry: DisplayGeometry,
    scanout_id: u32,
    resource_created: bool,
    backing_attached: bool,
    scanout_set: bool,
}

impl VirtioGpuBackend {
    pub(crate) fn initialize() -> Result<Self, GpuError> {
        let (capabilities, mapped_bars) = connect()?;
        let transport = VirtioPciTransport::new(capabilities, mapped_bars);
        let mut device = VirtioDevice::new(transport);
        device.begin_initialization()?;
        device.negotiate_features(
            FeatureSet::new(VIRTIO_F_VERSION_1),
            FeatureSet::new(VIRTIO_F_VERSION_1),
        )?;

        let maximum = device.transport_mut().queue_max_size(CONTROL_QUEUE_INDEX)?;
        let queue_size = queue_size(maximum).ok_or(VirtioError::InvalidQueueSize)?;
        let layout = VirtqueueLayout::calculate(queue_size)?;
        let queue_memory = DmaRegion::allocate(layout.total_size).map_err(GpuError::System)?;
        let control_queue = SplitVirtqueue::new(queue_memory, queue_size)?;
        let control_notify_offset = device.transport_mut().configure_queue(
            CONTROL_QUEUE_INDEX,
            queue_size,
            control_queue.descriptor_address()?,
            control_queue.available_address()?,
            control_queue.used_address()?,
        )?;
        device.finish_initialization()?;

        let mut backend = Self {
            device,
            control_queue,
            control_notify_offset,
            command: DmaRegion::allocate(COMMAND_BUFFER_SIZE).map_err(GpuError::System)?,
            response: DmaRegion::allocate(RESPONSE_BUFFER_SIZE).map_err(GpuError::System)?,
            backing: None,
            geometry: DisplayGeometry {
                width: 0,
                height: 0,
                stride: 0,
                format: crate::present::PIXEL_FORMAT_XRGB8888,
            },
            scanout_id: 0,
            resource_created: false,
            backing_attached: false,
            scanout_set: false,
        };
        let (scanout_id, width, height) = backend.get_display_info()?;
        let geometry = DisplayGeometry {
            width,
            height,
            stride: width,
            format: crate::present::PIXEL_FORMAT_XRGB8888,
        };
        let framebuffer_size = geometry.byte_len().map_err(GpuError::System)?;
        backend.geometry = geometry;
        backend.scanout_id = scanout_id;
        backend.backing = Some(BackingStore::allocate(framebuffer_size).map_err(GpuError::System)?);
        backend.create_resource()?;
        backend.present_initial_frame()?;
        Ok(backend)
    }

    pub(crate) const fn geometry(&self) -> DisplayGeometry {
        self.geometry
    }

    pub(crate) fn present(&mut self, frame: &PresentFrame<'_>) -> Result<(), GpuError> {
        frame.validate().map_err(GpuError::System)?;
        if frame.geometry.width != self.geometry.width
            || frame.geometry.height != self.geometry.height
            || frame.geometry.format != self.geometry.format
        {
            return Err(GpuError::InvalidFrame);
        }
        if frame.damage.is_empty() {
            return Ok(());
        }
        let backing = self.backing.as_mut().ok_or(GpuError::InvalidFrame)?;
        backing
            .copy_rect(
                frame.pixels,
                frame.geometry.stride,
                self.geometry.stride,
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
            .checked_mul(u64::from(self.geometry.stride))
            .and_then(|pixels| pixels.checked_add(u64::from(frame.damage.x)))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(GpuError::InvalidFrame)?;
        self.submit_no_data(Command::TransferToHost2d(TransferToHost2d {
            rect,
            offset,
            resource_id: RESOURCE_ID,
        }))?;
        self.submit_no_data(Command::ResourceFlush {
            rect,
            resource_id: RESOURCE_ID,
        })
    }

    fn get_display_info(&mut self) -> Result<(u32, u32, u32), GpuError> {
        let length = self.execute(Command::GetDisplayInfo)?;
        match Response::decode(&self.response.bytes()[..length])? {
            Response::DisplayInfo(view) => select_scanout(view),
            Response::Error(error) => Err(GpuError::DeviceResponse(error)),
            Response::NoData => Err(GpuError::InvalidDisplayInfo),
        }
    }

    fn create_resource(&mut self) -> Result<(), GpuError> {
        self.submit_no_data(Command::ResourceCreate2d(ResourceCreate2d {
            resource_id: RESOURCE_ID,
            format: PixelFormat::B8G8R8X8_UNORM,
            width: self.geometry.width,
            height: self.geometry.height,
        }))?;
        self.resource_created = true;
        let entries = self
            .backing
            .as_ref()
            .ok_or(GpuError::InvalidDisplayInfo)?
            .entries()
            .to_vec();
        self.submit_no_data(Command::ResourceAttachBacking(AttachBacking {
            resource_id: RESOURCE_ID,
            entries: &entries,
        }))?;
        self.backing_attached = true;
        self.submit_no_data(Command::SetScanout(SetScanout {
            rect: Rect {
                x: 0,
                y: 0,
                width: self.geometry.width,
                height: self.geometry.height,
            },
            scanout_id: self.scanout_id,
            resource_id: RESOURCE_ID,
        }))?;
        self.scanout_set = true;
        Ok(())
    }

    fn present_initial_frame(&mut self) -> Result<(), GpuError> {
        let rect = Rect {
            x: 0,
            y: 0,
            width: self.geometry.width,
            height: self.geometry.height,
        };
        self.submit_no_data(Command::TransferToHost2d(TransferToHost2d {
            rect,
            offset: 0,
            resource_id: RESOURCE_ID,
        }))?;
        self.submit_no_data(Command::ResourceFlush {
            rect,
            resource_id: RESOURCE_ID,
        })
    }

    fn submit_no_data(&mut self, command: Command<'_>) -> Result<(), GpuError> {
        let length = self.execute(command)?;
        match Response::decode(&self.response.bytes()[..length])? {
            Response::NoData => Ok(()),
            Response::Error(error) => Err(GpuError::DeviceResponse(error)),
            Response::DisplayInfo(_) => Err(GpuError::InvalidDisplayInfo),
        }
    }

    fn execute(&mut self, command: Command<'_>) -> Result<usize, GpuError> {
        let command_length = command.encode(self.command.bytes_mut())?;
        self.response.bytes_mut().fill(0);
        let descriptors = [
            Descriptor {
                address: self.command.device_address(),
                length: u32::try_from(command_length).map_err(|_| GpuError::InvalidFrame)?,
                device_writable: false,
            },
            Descriptor {
                address: self.response.device_address(),
                length: u32::try_from(self.response.len()).map_err(|_| GpuError::InvalidFrame)?,
                device_writable: true,
            },
        ];
        self.command.sync_for_device()?;
        self.response.sync_for_device()?;
        let head = self.control_queue.enqueue(&descriptors)?;
        self.device
            .transport_mut()
            .notify_queue(CONTROL_QUEUE_INDEX, self.control_notify_offset)?;
        let mut polls = 0u32;
        let used = self
            .control_queue
            .wait_for_used(head, COMMAND_TIMEOUT_POLLS, || {
                polls = polls.wrapping_add(1);
                if polls & 0xff == 0 {
                    platform::thread::yield_now();
                } else {
                    core::hint::spin_loop();
                }
            })?;
        self.response.sync_for_cpu()?;
        let written = usize::try_from(used.written).map_err(|_| GpuError::InvalidFrame)?;
        if written < 24 || written > self.response.len() {
            return Err(GpuError::InvalidDisplayInfo);
        }
        Ok(written)
    }

    fn cleanup(&mut self) {
        if self.scanout_set {
            let _ = self.submit_no_data(Command::SetScanout(SetScanout {
                rect: Rect::default(),
                scanout_id: self.scanout_id,
                resource_id: 0,
            }));
            self.scanout_set = false;
        }
        if self.backing_attached {
            let _ = self.submit_no_data(Command::ResourceDetachBacking(ResourceOperation {
                resource_id: RESOURCE_ID,
            }));
            self.backing_attached = false;
        }
        if self.resource_created {
            let _ = self.submit_no_data(Command::ResourceUnref(ResourceOperation {
                resource_id: RESOURCE_ID,
            }));
            self.resource_created = false;
        }
        self.backing = None;
    }
}

impl Drop for VirtioGpuBackend {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn queue_size(maximum: u16) -> Option<u16> {
    let limit = cmp::min(maximum, MAX_CONTROL_QUEUE_SIZE);
    if limit < 2 {
        return None;
    }
    let shift = 15u32.saturating_sub(limit.leading_zeros());
    Some(1u16 << shift)
}

fn select_scanout(view: DisplayInfoView<'_>) -> Result<(u32, u32, u32), GpuError> {
    for index in 0..mochios_virtio_gpu_protocol::DISPLAY_MODE_COUNT {
        let mode = view.mode(index)?.ok_or(GpuError::InvalidDisplayInfo)?;
        if mode.enabled
            && mode.rect.width != 0
            && mode.rect.height != 0
            && mode.rect.width <= crate::present::MAX_DIMENSION
            && mode.rect.height <= crate::present::MAX_DIMENSION
        {
            return Ok((index as u32, mode.rect.width, mode.rect.height));
        }
    }
    Err(GpuError::InvalidDisplayInfo)
}
