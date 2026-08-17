use core::cmp;

use mochi_user_platform as platform;
use mochios_virtio_gpu_protocol::{Command, Response, VIRTIO_GPU_F_VIRGL};
use plugkit::virtio::{
    Descriptor, DmaMemory, FeatureSet, PciTransportAccess, SplitVirtqueue, VIRTIO_F_VERSION_1,
    VirtioDevice, VirtioError, VirtioPciTransport, VirtqueueLayout,
};

use super::dma::DmaRegion;
use super::error::GpuError;
use super::pci::{MappedBars, connect};

const CONTROL_QUEUE_INDEX: u16 = 0;
const CURSOR_QUEUE_INDEX: u16 = 1;
const MAX_CONTROL_QUEUE_SIZE: u16 = 128;
const COMMAND_BUFFER_SIZE: usize = 4096;
const RESPONSE_BUFFER_SIZE: usize = 4096;
const COMMAND_TIMEOUT_POLLS: u32 = 100_000;
const YIELD_INTERVAL_POLLS: u32 = 256;

pub(super) struct ControlChannel {
    device: VirtioDevice<MappedBars>,
    queue: SplitVirtqueue<DmaRegion>,
    notify_offset: u16,
    cursor_queue: SplitVirtqueue<DmaRegion>,
    cursor_notify_offset: u16,
    command: DmaRegion,
    response: DmaRegion,
    next_command: DmaRegion,
    next_response: DmaRegion,
    cursor_command: DmaRegion,
    virgl_supported: bool,
    capset_count: u32,
    next_fence_id: u64,
}

impl ControlChannel {
    pub(super) fn initialize() -> Result<Self, GpuError> {
        let (capabilities, mapped_bars) = connect()?;
        let transport = VirtioPciTransport::new(capabilities, mapped_bars);
        let mut device = VirtioDevice::new(transport);
        device.begin_initialization()?;
        let negotiated = device.negotiate_features(
            FeatureSet::new(VIRTIO_F_VERSION_1 | VIRTIO_GPU_F_VIRGL),
            FeatureSet::new(VIRTIO_F_VERSION_1),
        )?;
        let virgl_supported = negotiated.contains_all(FeatureSet::new(VIRTIO_GPU_F_VIRGL));
        let capset_count = if virgl_supported {
            read_capset_count(&mut device)?
        } else {
            0
        };

        let maximum = device.transport_mut().queue_max_size(CONTROL_QUEUE_INDEX)?;
        let control_queue_size = queue_size(maximum).ok_or(VirtioError::InvalidQueueSize)?;
        let layout = VirtqueueLayout::calculate(control_queue_size)?;
        let queue_memory = DmaRegion::allocate(layout.total_size).map_err(GpuError::System)?;
        let queue = SplitVirtqueue::new(queue_memory, control_queue_size)?;
        let notify_offset = device.transport_mut().configure_queue(
            CONTROL_QUEUE_INDEX,
            control_queue_size,
            queue.descriptor_address()?,
            queue.available_address()?,
            queue.used_address()?,
        )?;
        let cursor_maximum = device.transport_mut().queue_max_size(CURSOR_QUEUE_INDEX)?;
        let cursor_queue_size = queue_size(cursor_maximum).ok_or(VirtioError::InvalidQueueSize)?;
        let cursor_layout = VirtqueueLayout::calculate(cursor_queue_size)?;
        let cursor_queue_memory =
            DmaRegion::allocate(cursor_layout.total_size).map_err(GpuError::System)?;
        let cursor_queue = SplitVirtqueue::new(cursor_queue_memory, cursor_queue_size)?;
        let cursor_notify_offset = device.transport_mut().configure_queue(
            CURSOR_QUEUE_INDEX,
            cursor_queue_size,
            cursor_queue.descriptor_address()?,
            cursor_queue.available_address()?,
            cursor_queue.used_address()?,
        )?;
        device.finish_initialization()?;

        Ok(Self {
            device,
            queue,
            notify_offset,
            cursor_queue,
            cursor_notify_offset,
            command: DmaRegion::allocate(COMMAND_BUFFER_SIZE).map_err(GpuError::System)?,
            response: DmaRegion::allocate(RESPONSE_BUFFER_SIZE).map_err(GpuError::System)?,
            next_command: DmaRegion::allocate(COMMAND_BUFFER_SIZE).map_err(GpuError::System)?,
            next_response: DmaRegion::allocate(RESPONSE_BUFFER_SIZE).map_err(GpuError::System)?,
            cursor_command: DmaRegion::allocate(COMMAND_BUFFER_SIZE).map_err(GpuError::System)?,
            virgl_supported,
            capset_count,
            next_fence_id: 1,
        })
    }

    pub(super) const fn virgl_supported(&self) -> bool {
        self.virgl_supported
    }

    pub(super) const fn capset_count(&self) -> u32 {
        self.capset_count
    }

    pub(super) fn submit_no_data(&mut self, command: Command<'_>) -> Result<(), GpuError> {
        let length = self.execute(command)?;
        decode_no_data(&self.response.bytes()[..length])
    }

    pub(super) fn submit_fenced_no_data(
        &mut self,
        command: Command<'_>,
    ) -> Result<(), GpuError> {
        let fence_id = self.next_fence_id;
        self.next_fence_id = self.next_fence_id.checked_add(1).unwrap_or(1);
        let context_id = command.context_id();
        let command_length = command.encode_fenced(self.command.bytes_mut(), fence_id)?;
        let length = self.execute_encoded(command_length)?;
        match Response::decode_fenced(self.response(length), fence_id, context_id)? {
            Response::NoData => Ok(()),
            Response::Error(error) => Err(GpuError::DeviceResponse(error)),
            _ => Err(GpuError::InvalidDisplayInfo),
        }
    }

    pub(super) fn submit_cursor(&mut self, command: Command<'_>) -> Result<(), GpuError> {
        let length = command.encode(self.cursor_command.bytes_mut())?;
        let descriptors = [Descriptor {
            address: self.cursor_command.device_address(),
            length: u32::try_from(length).map_err(|_| GpuError::InvalidFrame)?,
            device_writable: false,
        }];
        self.cursor_command.sync_for_device()?;
        let head = self.cursor_queue.enqueue(&descriptors)?;
        self.device
            .transport_mut()
            .notify_queue(CURSOR_QUEUE_INDEX, self.cursor_notify_offset)?;
        let mut polls = 0u32;
        let _ = self
            .cursor_queue
            .wait_for_used(head, COMMAND_TIMEOUT_POLLS, || {
                polls = polls.wrapping_add(1);
                if polls % YIELD_INTERVAL_POLLS == 0 {
                    platform::thread::yield_now();
                } else {
                    core::hint::spin_loop();
                }
            })?;
        Ok(())
    }

    pub(super) fn submit_pair_no_data(
        &mut self,
        first: Command<'_>,
        second: Command<'_>,
    ) -> Result<(), GpuError> {
        if self.queue.free_descriptor_count() < 4 {
            self.submit_no_data(first)?;
            return self.submit_no_data(second);
        }
        let first_length = first.encode(self.command.bytes_mut())?;
        let second_length = second.encode(self.next_command.bytes_mut())?;
        self.response.bytes_mut().fill(0);
        self.next_response.bytes_mut().fill(0);
        let first_descriptors = [
            Descriptor {
                address: self.command.device_address(),
                length: u32::try_from(first_length).map_err(|_| GpuError::InvalidFrame)?,
                device_writable: false,
            },
            Descriptor {
                address: self.response.device_address(),
                length: u32::try_from(self.response.len()).map_err(|_| GpuError::InvalidFrame)?,
                device_writable: true,
            },
        ];
        let second_descriptors = [
            Descriptor {
                address: self.next_command.device_address(),
                length: u32::try_from(second_length).map_err(|_| GpuError::InvalidFrame)?,
                device_writable: false,
            },
            Descriptor {
                address: self.next_response.device_address(),
                length: u32::try_from(self.next_response.len())
                    .map_err(|_| GpuError::InvalidFrame)?,
                device_writable: true,
            },
        ];
        self.command.sync_for_device()?;
        self.response.sync_for_device()?;
        self.next_command.sync_for_device()?;
        self.next_response.sync_for_device()?;
        let first_head = self.queue.enqueue(&first_descriptors)?;
        let second_head = self.queue.enqueue(&second_descriptors)?;
        self.device
            .transport_mut()
            .notify_queue(CONTROL_QUEUE_INDEX, self.notify_offset)?;
        let (first_written, second_written) = self.wait_for_pair(first_head, second_head)?;
        self.response.sync_for_cpu()?;
        self.next_response.sync_for_cpu()?;
        let first_written = response_length(first_written, self.response.len())?;
        let second_written = response_length(second_written, self.next_response.len())?;
        decode_no_data(&self.response.bytes()[..first_written])?;
        decode_no_data(&self.next_response.bytes()[..second_written])
    }

    fn wait_for_used(&mut self, head: u16) -> Result<plugkit::virtio::UsedDescriptor, GpuError> {
        let mut polls = 0u32;
        self.queue
            .wait_for_used(head, COMMAND_TIMEOUT_POLLS, || {
                polls = polls.wrapping_add(1);
                if polls % YIELD_INTERVAL_POLLS == 0 {
                    platform::thread::yield_now();
                } else {
                    core::hint::spin_loop();
                }
            })
            .map_err(Into::into)
    }

    fn wait_for_pair(
        &mut self,
        first_head: u16,
        second_head: u16,
    ) -> Result<
        (
            plugkit::virtio::UsedDescriptor,
            plugkit::virtio::UsedDescriptor,
        ),
        GpuError,
    > {
        let mut first = None;
        let mut second = None;
        for polls in 0..COMMAND_TIMEOUT_POLLS {
            while let Some(completed) = self.queue.pop_used()? {
                if completed.head == first_head {
                    first = Some(completed);
                } else if completed.head == second_head {
                    second = Some(completed);
                } else {
                    return Err(VirtioError::InvalidUsedIndex.into());
                }
            }
            if let (Some(first), Some(second)) = (first, second) {
                return Ok((first, second));
            }
            if polls % YIELD_INTERVAL_POLLS == YIELD_INTERVAL_POLLS - 1 {
                platform::thread::yield_now();
            } else {
                core::hint::spin_loop();
            }
        }
        Err(VirtioError::CommandTimeout.into())
    }

    pub(super) fn execute(&mut self, command: Command<'_>) -> Result<usize, GpuError> {
        let command_length = command.encode(self.command.bytes_mut())?;
        self.execute_encoded(command_length)
    }

    fn execute_encoded(&mut self, command_length: usize) -> Result<usize, GpuError> {
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
        let used = self.wait_for_used(head)?;
        self.response.sync_for_cpu()?;
        response_length(used, self.response.len())
    }

    pub(super) fn response(&self, length: usize) -> &[u8] {
        &self.response.bytes()[..length]
    }
}

fn decode_no_data(bytes: &[u8]) -> Result<(), GpuError> {
    match Response::decode(bytes)? {
        Response::NoData => Ok(()),
        Response::Error(error) => Err(GpuError::DeviceResponse(error)),
        Response::DisplayInfo(_) | Response::CapsetInfo(_) | Response::Capset(_) => {
            Err(GpuError::InvalidDisplayInfo)
        }
    }
}

fn response_length(
    used: plugkit::virtio::UsedDescriptor,
    capacity: usize,
) -> Result<usize, GpuError> {
    let written = usize::try_from(used.written).map_err(|_| GpuError::InvalidFrame)?;
    if written < 24 || written > capacity {
        return Err(GpuError::InvalidDisplayInfo);
    }
    Ok(written)
}

fn read_capset_count(device: &mut VirtioDevice<MappedBars>) -> Result<u32, GpuError> {
    const NUM_CAPSETS_OFFSET: u32 = 12;
    let region = device
        .transport_mut()
        .capabilities()
        .device
        .ok_or(VirtioError::RegisterOutOfBounds)?;
    if region.length < NUM_CAPSETS_OFFSET + 4 {
        return Err(VirtioError::RegisterOutOfBounds.into());
    }
    let offset = region
        .offset
        .checked_add(NUM_CAPSETS_OFFSET)
        .ok_or(VirtioError::RegionOverflow)?;
    device
        .transport_mut()
        .access_mut()
        .read_u32(region.bar, offset)
        .map_err(Into::into)
}

fn queue_size(maximum: u16) -> Option<u16> {
    let limit = cmp::min(maximum, MAX_CONTROL_QUEUE_SIZE);
    if limit < 2 {
        return None;
    }
    let shift = 15u32.saturating_sub(limit.leading_zeros());
    Some(1u16 << shift)
}
