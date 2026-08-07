mod dma;
mod pci;

use std::collections::VecDeque;

use plugkit::virtio::{
    Descriptor, DeviceStatus, DmaMemory, FeatureSet, PciTransportAccess, SplitVirtqueue,
    VirtioDevice, VirtioError, VirtioPciTransport, VirtqueueLayout,
};

use super::model::{
    PortStatus, REQUIRED_FEATURES, drain_received, is_target_name, port_queue_indices,
    write_chunk_length,
};
use super::{ControlTransport, TransportError};
use dma::DmaRegion;
use pci::MappedBars;

const REQUESTED_FEATURES: u64 = REQUIRED_FEATURES;
const CONTROL_RX_QUEUE: u16 = 2;
const CONTROL_TX_QUEUE: u16 = 3;
const MAX_PORTS: usize = 32;
const MAX_QUEUE_SIZE: u16 = 16;
const CONTROL_BUFFER_COUNT: usize = 8;
const CONTROL_BUFFER_LEN: usize = 256;
const DATA_BUFFER_COUNT: usize = 8;
const DATA_BUFFER_LEN: usize = 1024;
const RECEIVED_LIMIT: usize = 16 * 1024;

const DEVICE_READY: u16 = 0;
const PORT_ADD: u16 = 1;
const PORT_REMOVE: u16 = 2;
const PORT_READY: u16 = 3;
const PORT_OPEN: u16 = 6;
const PORT_NAME: u16 = 7;

struct Queue {
    ring: SplitVirtqueue<DmaRegion>,
    notify: u16,
}

struct BufferSlot {
    dma: DmaRegion,
    head: Option<u16>,
}

struct PortQueues {
    receive: Queue,
    transmit: Queue,
    receive_buffers: Vec<BufferSlot>,
    transmit_buffers: Vec<BufferSlot>,
    status: PortStatus,
}

pub struct VirtioSerialTransport {
    device: VirtioDevice<MappedBars>,
    control_receive: Queue,
    control_transmit: Queue,
    control_receive_buffers: Vec<BufferSlot>,
    control_transmit_buffers: Vec<BufferSlot>,
    ports: Vec<PortQueues>,
    target_port: Option<usize>,
    received: VecDeque<u8>,
}

impl VirtioSerialTransport {
    pub fn initialize() -> Result<Self, TransportError> {
        let (capabilities, bars) = pci::connect().map_err(virtio_error)?;
        let device_config = capabilities.device.ok_or(TransportError::InvalidDevice)?;
        let mut device = VirtioDevice::new(VirtioPciTransport::new(capabilities, bars));
        device.begin_initialization().map_err(virtio_error)?;
        device
            .negotiate_features(
                FeatureSet::new(REQUESTED_FEATURES),
                FeatureSet::new(REQUIRED_FEATURES),
            )
            .map_err(virtio_error)?;
        let max_ports = device
            .transport_mut()
            .access_mut()
            .read_u32(device_config.bar, device_config.offset + 4)
            .map_err(virtio_error)? as usize;
        if max_ports == 0 || max_ports > MAX_PORTS {
            device.fail();
            return Err(TransportError::InvalidDevice);
        }

        let control_receive = make_queue(&mut device, CONTROL_RX_QUEUE)?;
        let control_transmit = make_queue(&mut device, CONTROL_TX_QUEUE)?;
        let mut ports = Vec::with_capacity(max_ports);
        for port_id in 0..max_ports {
            let (receive_index, transmit_index) =
                port_queue_indices(port_id as u32).ok_or(TransportError::InvalidDevice)?;
            ports.push(PortQueues {
                receive: make_queue(&mut device, receive_index)?,
                transmit: make_queue(&mut device, transmit_index)?,
                receive_buffers: Vec::new(),
                transmit_buffers: Vec::new(),
                status: PortStatus::default(),
            });
        }
        let mut transport = Self {
            device,
            control_receive,
            control_transmit,
            control_receive_buffers: allocate_buffers(CONTROL_BUFFER_COUNT, CONTROL_BUFFER_LEN)?,
            control_transmit_buffers: allocate_buffers(CONTROL_BUFFER_COUNT, CONTROL_BUFFER_LEN)?,
            ports,
            target_port: None,
            received: VecDeque::with_capacity(RECEIVED_LIMIT),
        };
        transport
            .device
            .finish_initialization()
            .map_err(virtio_error)?;
        for slot in 0..transport.control_receive_buffers.len() {
            transport.post_control_receive(slot)?;
        }
        transport.notify(CONTROL_RX_QUEUE, transport.control_receive.notify)?;
        transport.send_control(0, DEVICE_READY, 1)?;
        Ok(transport)
    }

    fn post_control_receive(&mut self, slot: usize) -> Result<(), TransportError> {
        let buffer = self
            .control_receive_buffers
            .get_mut(slot)
            .ok_or(TransportError::InvalidDevice)?;
        buffer.dma.bytes_mut().fill(0);
        buffer.dma.sync_for_device().map_err(virtio_error)?;
        let head = self
            .control_receive
            .ring
            .enqueue(&[Descriptor {
                address: buffer.dma.device_address(),
                length: CONTROL_BUFFER_LEN as u32,
                device_writable: true,
            }])
            .map_err(virtio_error)?;
        buffer.head = Some(head);
        Ok(())
    }

    fn send_control(&mut self, id: u32, event: u16, value: u16) -> Result<(), TransportError> {
        self.reclaim_control_transmit()?;
        let slot = self
            .control_transmit_buffers
            .iter()
            .position(|buffer| buffer.head.is_none())
            .ok_or(TransportError::WouldBlock)?;
        let buffer = &mut self.control_transmit_buffers[slot];
        let bytes = buffer.dma.bytes_mut();
        bytes[..4].copy_from_slice(&id.to_le_bytes());
        bytes[4..6].copy_from_slice(&event.to_le_bytes());
        bytes[6..8].copy_from_slice(&value.to_le_bytes());
        buffer.dma.sync_for_device().map_err(virtio_error)?;
        let head = self
            .control_transmit
            .ring
            .enqueue(&[Descriptor {
                address: buffer.dma.device_address(),
                length: 8,
                device_writable: false,
            }])
            .map_err(virtio_error)?;
        buffer.head = Some(head);
        self.notify(CONTROL_TX_QUEUE, self.control_transmit.notify)
    }

    fn reclaim_control_transmit(&mut self) -> Result<(), TransportError> {
        while let Some(used) = self
            .control_transmit
            .ring
            .pop_used()
            .map_err(virtio_error)?
        {
            let buffer = self
                .control_transmit_buffers
                .iter_mut()
                .find(|buffer| buffer.head == Some(used.head))
                .ok_or(TransportError::InvalidDevice)?;
            buffer.head = None;
        }
        Ok(())
    }

    fn poll_control(&mut self) -> Result<(), TransportError> {
        self.reclaim_control_transmit()?;
        while let Some(used) = self.control_receive.ring.pop_used().map_err(virtio_error)? {
            let slot = self
                .control_receive_buffers
                .iter()
                .position(|buffer| buffer.head == Some(used.head))
                .ok_or(TransportError::InvalidDevice)?;
            self.control_receive_buffers[slot].head = None;
            self.control_receive_buffers[slot]
                .dma
                .sync_for_cpu()
                .map_err(virtio_error)?;
            let length = (used.written as usize).min(CONTROL_BUFFER_LEN);
            let event =
                ControlEvent::decode(&self.control_receive_buffers[slot].dma.bytes()[..length]);
            self.post_control_receive(slot)?;
            self.notify(CONTROL_RX_QUEUE, self.control_receive.notify)?;
            if let Some(event) = event {
                self.handle_control(event)?;
            }
        }
        Ok(())
    }

    fn handle_control(&mut self, event: ControlEvent) -> Result<(), TransportError> {
        let port_id = event.id as usize;
        match event.event {
            PORT_ADD if event.value != 0 && port_id < self.ports.len() => {
                self.activate_port(port_id)?;
                self.send_control(event.id, PORT_READY, 1)?;
            }
            PORT_REMOVE if port_id < self.ports.len() => {
                let port = &mut self.ports[port_id];
                port.status.remove();
                if self.target_port == Some(port_id) {
                    self.target_port = None;
                    self.received.clear();
                }
            }
            PORT_NAME if port_id < self.ports.len() => {
                let matches = is_target_name(&event.payload);
                self.ports[port_id].status.set_name(&event.payload);
                if matches {
                    self.send_control(event.id, PORT_OPEN, 1)?;
                    self.ports[port_id].status.set_guest_open(true);
                    self.target_port = Some(port_id);
                } else if self.target_port == Some(port_id) {
                    self.target_port = None;
                    self.received.clear();
                }
            }
            PORT_OPEN if port_id < self.ports.len() => {
                self.ports[port_id].status.set_open(event.value != 0);
                if self.target_port == Some(port_id) && event.value == 0 {
                    self.received.clear();
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn activate_port(&mut self, port_id: usize) -> Result<(), TransportError> {
        if self.ports[port_id].status.added {
            return Ok(());
        }
        let receive_count =
            DATA_BUFFER_COUNT.min(usize::from(self.ports[port_id].receive.ring.size()));
        let transmit_count =
            DATA_BUFFER_COUNT.min(usize::from(self.ports[port_id].transmit.ring.size()));
        self.ports[port_id].receive_buffers = allocate_buffers(receive_count, DATA_BUFFER_LEN)?;
        self.ports[port_id].transmit_buffers = allocate_buffers(transmit_count, DATA_BUFFER_LEN)?;
        self.ports[port_id].status.add();
        for slot in 0..receive_count {
            self.post_port_receive(port_id, slot)?;
        }
        let (receive_queue, _) =
            port_queue_indices(port_id as u32).ok_or(TransportError::InvalidDevice)?;
        let notify = self.ports[port_id].receive.notify;
        self.notify(receive_queue, notify)
    }

    fn post_port_receive(&mut self, port_id: usize, slot: usize) -> Result<(), TransportError> {
        let port = self
            .ports
            .get_mut(port_id)
            .ok_or(TransportError::InvalidDevice)?;
        let buffer = port
            .receive_buffers
            .get_mut(slot)
            .ok_or(TransportError::InvalidDevice)?;
        buffer.dma.bytes_mut().fill(0);
        buffer.dma.sync_for_device().map_err(virtio_error)?;
        let head = port
            .receive
            .ring
            .enqueue(&[Descriptor {
                address: buffer.dma.device_address(),
                length: DATA_BUFFER_LEN as u32,
                device_writable: true,
            }])
            .map_err(virtio_error)?;
        buffer.head = Some(head);
        Ok(())
    }

    fn poll_ports(&mut self) -> Result<(), TransportError> {
        for port_id in 0..self.ports.len() {
            if !self.ports[port_id].status.added {
                continue;
            }
            while let Some(used) = self.ports[port_id]
                .receive
                .ring
                .pop_used()
                .map_err(virtio_error)?
            {
                let slot = self.ports[port_id]
                    .receive_buffers
                    .iter()
                    .position(|buffer| buffer.head == Some(used.head))
                    .ok_or(TransportError::InvalidDevice)?;
                self.ports[port_id].receive_buffers[slot].head = None;
                self.ports[port_id].receive_buffers[slot]
                    .dma
                    .sync_for_cpu()
                    .map_err(virtio_error)?;
                let length = (used.written as usize).min(DATA_BUFFER_LEN);
                if self.target_port == Some(port_id) && self.ports[port_id].status.host_open {
                    let available = RECEIVED_LIMIT.saturating_sub(self.received.len());
                    let length = length.min(available);
                    self.received.extend(
                        self.ports[port_id].receive_buffers[slot].dma.bytes()[..length]
                            .iter()
                            .copied(),
                    );
                }
                self.post_port_receive(port_id, slot)?;
                let (receive_queue, _) =
                    port_queue_indices(port_id as u32).ok_or(TransportError::InvalidDevice)?;
                let notify = self.ports[port_id].receive.notify;
                self.notify(receive_queue, notify)?;
            }
            while let Some(used) = self.ports[port_id]
                .transmit
                .ring
                .pop_used()
                .map_err(virtio_error)?
            {
                let buffer = self.ports[port_id]
                    .transmit_buffers
                    .iter_mut()
                    .find(|buffer| buffer.head == Some(used.head))
                    .ok_or(TransportError::InvalidDevice)?;
                buffer.head = None;
            }
        }
        Ok(())
    }

    fn notify(&mut self, queue: u16, offset: u16) -> Result<(), TransportError> {
        self.device
            .transport_mut()
            .notify_queue(queue, offset)
            .map_err(virtio_error)
    }
}

impl ControlTransport for VirtioSerialTransport {
    fn poll(&mut self) -> Result<(), TransportError> {
        let status = self
            .device
            .transport_mut()
            .read_status()
            .map_err(virtio_error)?;
        if !status.contains(DeviceStatus::DRIVER_OK)
            || status.contains(DeviceStatus::DEVICE_NEEDS_RESET)
        {
            self.target_port = None;
            self.received.clear();
            return Err(TransportError::Disconnected);
        }
        self.poll_control()?;
        self.poll_ports()
    }

    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        if !self.is_connected() {
            return Err(TransportError::Disconnected);
        }
        let length = drain_received(&mut self.received, buffer);
        if length == 0 {
            Err(TransportError::WouldBlock)
        } else {
            Ok(length)
        }
    }

    fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError> {
        let port_id = self.target_port.ok_or(TransportError::Disconnected)?;
        if !self.ports[port_id].status.host_open {
            return Err(TransportError::Disconnected);
        }
        self.poll_ports()?;
        let slot = self.ports[port_id]
            .transmit_buffers
            .iter()
            .position(|buffer| buffer.head.is_none())
            .ok_or(TransportError::WouldBlock)?;
        let length = write_chunk_length(buffer.len(), DATA_BUFFER_LEN);
        if length == 0 {
            return Ok(0);
        }
        let port = &mut self.ports[port_id];
        port.transmit_buffers[slot].dma.bytes_mut()[..length].copy_from_slice(&buffer[..length]);
        port.transmit_buffers[slot]
            .dma
            .sync_for_device()
            .map_err(virtio_error)?;
        let head = port
            .transmit
            .ring
            .enqueue(&[Descriptor {
                address: port.transmit_buffers[slot].dma.device_address(),
                length: length as u32,
                device_writable: false,
            }])
            .map_err(virtio_error)?;
        port.transmit_buffers[slot].head = Some(head);
        let (_, transmit_queue) =
            port_queue_indices(port_id as u32).ok_or(TransportError::InvalidDevice)?;
        let notify = port.transmit.notify;
        self.notify(transmit_queue, notify)?;
        Ok(length)
    }

    fn is_connected(&self) -> bool {
        self.target_port
            .and_then(|port| self.ports.get(port))
            .is_some_and(|port| port.status.connected())
    }

    fn reset_connection(&mut self) {
        self.received.clear();
    }
}

#[derive(Clone)]
struct ControlEvent {
    id: u32,
    event: u16,
    value: u16,
    payload: Vec<u8>,
}

impl ControlEvent {
    fn decode(bytes: &[u8]) -> Option<Self> {
        let header = bytes.get(..8)?;
        Some(Self {
            id: u32::from_le_bytes([header[0], header[1], header[2], header[3]]),
            event: u16::from_le_bytes([header[4], header[5]]),
            value: u16::from_le_bytes([header[6], header[7]]),
            payload: bytes[8..].to_vec(),
        })
    }
}

fn make_queue(device: &mut VirtioDevice<MappedBars>, index: u16) -> Result<Queue, TransportError> {
    let maximum = device
        .transport_mut()
        .queue_max_size(index)
        .map_err(virtio_error)?;
    let size = maximum.min(MAX_QUEUE_SIZE);
    if size < 2 {
        return Err(TransportError::InvalidDevice);
    }
    let size = 1u16 << (15 - size.leading_zeros() as u16);
    let layout = VirtqueueLayout::calculate(size).map_err(virtio_error)?;
    let memory = DmaRegion::allocate(layout.total_size).map_err(TransportError::Io)?;
    let ring = SplitVirtqueue::new(memory, size).map_err(virtio_error)?;
    let notify = device
        .transport_mut()
        .configure_queue(
            index,
            size,
            ring.descriptor_address().map_err(virtio_error)?,
            ring.available_address().map_err(virtio_error)?,
            ring.used_address().map_err(virtio_error)?,
        )
        .map_err(virtio_error)?;
    Ok(Queue { ring, notify })
}

fn allocate_buffers(count: usize, length: usize) -> Result<Vec<BufferSlot>, TransportError> {
    let mut buffers = Vec::with_capacity(count);
    for _ in 0..count {
        buffers.push(BufferSlot {
            dma: DmaRegion::allocate(length).map_err(TransportError::Io)?,
            head: None,
        });
    }
    Ok(buffers)
}

fn virtio_error(_error: VirtioError) -> TransportError {
    TransportError::Io(mochi_user_syscall::EIO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_and_multiport_features_are_required() {
        assert_eq!(REQUESTED_FEATURES, (1 << 32) | (1 << 1));
        assert_eq!(REQUIRED_FEATURES, REQUESTED_FEATURES);
    }

    #[test]
    fn queue_indices_follow_the_virtio_console_layout() {
        assert_eq!(port_queue_indices(0), Some((0, 1)));
        assert_eq!(port_queue_indices(1), Some((4, 5)));
        assert_eq!(port_queue_indices(2), Some((6, 7)));
    }

    #[test]
    fn only_the_exact_control_port_name_matches() {
        assert!(is_target_name(b"org.mochios.mboot.control\0"));
        assert!(!is_target_name(b"org.mochios.mboot.debug\0"));
        assert!(!is_target_name(b"org.mochios.mboot.control.extra\0"));
    }

    #[test]
    fn control_open_and_close_events_decode() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&PORT_OPEN.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        let opened = ControlEvent::decode(&bytes).unwrap();
        assert_eq!(opened.id, 1);
        assert_eq!(opened.event, PORT_OPEN);
        assert_eq!(opened.value, 1);
        bytes[6..8].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(ControlEvent::decode(&bytes).unwrap().value, 0);
    }
}
