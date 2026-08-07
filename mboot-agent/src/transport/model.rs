use std::collections::VecDeque;

pub(crate) const TARGET_PORT_NAME: &[u8] = b"org.mochios.mboot.control";
pub(crate) const VIRTIO_VENDOR_ID: u16 = 0x1af4;
pub(crate) const VIRTIO_CONSOLE_DEVICE_ID: u16 = 0x1043;
pub(crate) const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub(crate) const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;
pub(crate) const REQUIRED_FEATURES: u64 = VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_MULTIPORT;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PortStatus {
    pub(crate) added: bool,
    pub(crate) name_matches: bool,
    pub(crate) host_open: bool,
    pub(crate) guest_open: bool,
}

impl PortStatus {
    pub(crate) fn add(&mut self) {
        self.added = true;
    }

    pub(crate) fn remove(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn set_name(&mut self, name: &[u8]) {
        self.name_matches = is_target_name(name);
    }

    pub(crate) fn set_open(&mut self, open: bool) {
        self.host_open = open;
    }

    pub(crate) fn set_guest_open(&mut self, open: bool) {
        self.guest_open = open;
    }

    pub(crate) const fn connected(self) -> bool {
        self.added && self.name_matches && self.host_open && self.guest_open
    }
}

#[cfg(test)]
pub(crate) const fn is_supported_device(vendor: u16, device: u16) -> bool {
    vendor == VIRTIO_VENDOR_ID && device == VIRTIO_CONSOLE_DEVICE_ID
}

#[cfg(test)]
pub(crate) const fn supports_required_features(features: u64) -> bool {
    features & REQUIRED_FEATURES == REQUIRED_FEATURES
}

pub(crate) fn is_target_name(payload: &[u8]) -> bool {
    payload.strip_suffix(&[0]).unwrap_or(payload) == TARGET_PORT_NAME
}

pub(crate) fn port_queue_indices(port_id: u32) -> Option<(u16, u16)> {
    if port_id == 0 {
        return Some((0, 1));
    }
    let receive = port_id.checked_mul(2)?.checked_add(2)?;
    let transmit = receive.checked_add(1)?;
    Some((u16::try_from(receive).ok()?, u16::try_from(transmit).ok()?))
}

pub(crate) fn drain_received(received: &mut VecDeque<u8>, output: &mut [u8]) -> usize {
    let length = output.len().min(received.len());
    for destination in &mut output[..length] {
        if let Some(byte) = received.pop_front() {
            *destination = byte;
        }
    }
    length
}

pub(crate) const fn write_chunk_length(input_length: usize, buffer_length: usize) -> usize {
    if input_length < buffer_length {
        input_length
    } else {
        buffer_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_only_the_virtio_console_device() {
        assert!(is_supported_device(0x1af4, 0x1043));
        assert!(!is_supported_device(0x1af4, 0x1042));
        assert!(!is_supported_device(0x1234, 0x1043));
    }

    #[test]
    fn requires_modern_multiport_features() {
        assert!(supports_required_features(REQUIRED_FEATURES));
        assert!(!supports_required_features(VIRTIO_F_VERSION_1));
        assert!(!supports_required_features(VIRTIO_CONSOLE_F_MULTIPORT));
    }

    #[test]
    fn target_port_name_and_open_state_are_exact() {
        let mut port = PortStatus::default();
        port.add();
        port.set_name(b"org.mochios.mboot.debug\0");
        port.set_open(true);
        assert!(!port.connected());
        port.set_name(b"org.mochios.mboot.control\0");
        assert!(!port.connected());
        port.set_guest_open(true);
        assert!(port.connected());
        port.set_open(false);
        assert!(!port.connected());
    }

    #[test]
    fn remove_resets_port_for_reconnect() {
        let mut port = PortStatus {
            added: true,
            name_matches: true,
            host_open: true,
            guest_open: true,
        };
        port.remove();
        assert_eq!(port, PortStatus::default());
    }

    #[test]
    fn queue_indices_follow_the_virtio_console_layout() {
        assert_eq!(port_queue_indices(0), Some((0, 1)));
        assert_eq!(port_queue_indices(1), Some((4, 5)));
        assert_eq!(port_queue_indices(2), Some((6, 7)));
    }

    #[test]
    fn partial_reads_preserve_remaining_bytes() {
        let mut received = VecDeque::from(Vec::from(&b"abcdef"[..]));
        let mut first = [0u8; 2];
        let mut second = [0u8; 8];
        assert_eq!(drain_received(&mut received, &mut first), 2);
        assert_eq!(&first, b"ab");
        assert_eq!(drain_received(&mut received, &mut second), 4);
        assert_eq!(&second[..4], b"cdef");
        assert!(received.is_empty());
    }

    #[test]
    fn partial_writes_are_bounded_by_dma_buffer() {
        assert_eq!(write_chunk_length(4096, 1024), 1024);
        assert_eq!(write_chunk_length(512, 1024), 512);
    }
}
