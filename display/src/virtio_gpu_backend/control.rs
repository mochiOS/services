use core::cmp;

use mochi_user_platform as platform;
use mochios_virtio_gpu_protocol::{Command, Response};
use plugkit::virtio::{
    Descriptor, DmaMemory, FeatureSet, SplitVirtqueue, VIRTIO_F_VERSION_1, VirtioDevice,
    VirtioError, VirtioPciTransport, VirtqueueLayout,
};

use super::dma::DmaRegion;
use super::error::GpuError;
use super::pci::{MappedBars, connect};

const CONTROL_QUEUE_INDEX: u16 = 0;
const MAX_CONTROL_QUEUE_SIZE: u16 = 128;
const COMMAND_BUFFER_SIZE: usize = 4096;
const RESPONSE_BUFFER_SIZE: usize = 4096;
const COMMAND_TIMEOUT_POLLS: u32 = 100_000;

pub(super) struct ControlChannel {
    device: VirtioDevice<MappedBars>,
    queue: SplitVirtqueue<DmaRegion>,
    notify_offset: u16,
    command: DmaRegion,
    response: DmaRegion,
}

impl ControlChannel {
    pub(super) fn initialize() -> Result<Self, GpuError> {
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
        let queue = SplitVirtqueue::new(queue_memory, queue_size)?;
        let notify_offset = device.transport_mut().configure_queue(
            CONTROL_QUEUE_INDEX,
            queue_size,
            queue.descriptor_address()?,
            queue.available_address()?,
            queue.used_address()?,
        )?;
        device.finish_initialization()?;

        Ok(Self {
            device,
            queue,
            notify_offset,
            command: DmaRegion::allocate(COMMAND_BUFFER_SIZE).map_err(GpuError::System)?,
            response: DmaRegion::allocate(RESPONSE_BUFFER_SIZE).map_err(GpuError::System)?,
        })
    }

    pub(super) fn submit_no_data(&mut self, command: Command<'_>) -> Result<(), GpuError> {
        let length = self.execute(command)?;
        match Response::decode(&self.response.bytes()[..length])? {
            Response::NoData => Ok(()),
            Response::Error(error) => Err(GpuError::DeviceResponse(error)),
            Response::DisplayInfo(_) => Err(GpuError::InvalidDisplayInfo),
        }
    }

    pub(super) fn execute(&mut self, command: Command<'_>) -> Result<usize, GpuError> {
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
        let head = self.queue.enqueue(&descriptors)?;
        self.device
            .transport_mut()
            .notify_queue(CONTROL_QUEUE_INDEX, self.notify_offset)?;
        let mut polls = 0u32;
        let used = self.queue.wait_for_used(head, COMMAND_TIMEOUT_POLLS, || {
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

    pub(super) fn response(&self, length: usize) -> &[u8] {
        &self.response.bytes()[..length]
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
