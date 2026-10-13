//! User-space null-device open description; no pathname or kernel policy.

use mochios_filesystem_protocol as protocol;

const EACCES: i32 = 13;
const EINVAL: i32 = 22;
const ENOTSUP: i32 = 95;
const STATUS_FLAGS: u32 = protocol::OPEN_STATUS_APPEND | protocol::OPEN_STATUS_NONBLOCK;

/// One open-file description. Duplicated/forwarded Handles must retain this
/// same instance, not copy its mutable status flags into individual FDs.
/// Access mode is fixed at open and cannot be expanded through status flags.
pub struct NullDescription {
    read: bool,
    write: bool,
    flags: u32,
}

impl NullDescription {
    pub fn new(read: bool, write: bool, flags: u32) -> Result<Self, i32> {
        if (!read && !write) || flags & !STATUS_FLAGS != 0 {
            return Err(EINVAL);
        }
        Ok(Self { read, write, flags })
    }

    pub fn read_into(&self, _output: &mut [u8]) -> Result<usize, i32> {
        if !self.read {
            return Err(EACCES);
        }
        Ok(0)
    }

    pub fn write(&self, input: &[u8]) -> Result<usize, i32> {
        if !self.write {
            return Err(EACCES);
        }
        Ok(input.len())
    }

    /// A null device has no byte-addressed position. Sequential and positioned
    /// reads return EOF; writes discard their bytes regardless of the offset.
    pub fn read_at(&self, output: &mut [u8], _offset: u64) -> Result<usize, i32> {
        self.read_into(output)
    }

    pub fn write_at(&self, input: &[u8], _offset: u64) -> Result<usize, i32> {
        self.write(input)
    }

    pub fn seek(&self, _offset: i64, basis: u64) -> Result<u64, i32> {
        if basis > 2 {
            return Err(EINVAL);
        }
        Ok(0)
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn set_flags(&mut self, flags: u32) -> Result<(), i32> {
        if flags & !STATUS_FLAGS != 0 {
            return Err(EINVAL);
        }
        self.flags = flags;
        Ok(())
    }

    /// Null-device data is not a file-backed VM object. In particular, do not
    /// represent discarded writes as pages in a regular-file cache.
    pub fn memory_object(&self) -> Result<u64, i32> {
        Err(ENOTSUP)
    }

    /// Construct metadata only after the namespace has resolved this device's
    /// node identity. The caller supplies volume/inode IDs, not an FD or PID.
    pub fn status(&self, device: u64, node_id: u64) -> protocol::NodeStatus {
        node_status(device, node_id)
    }
}

/// Metadata belongs to the device node, independently of an open description.
pub fn node_status(device: u64, node_id: u64) -> protocol::NodeStatus {
    protocol::NodeStatus {
        device,
        node_id,
        kind: protocol::NODE_TYPE_SPECIAL,
        mode: 0o020666,
        link_count: 1,
        special_device: (1 << 8) | 3,
        block_size: 4096,
        ..protocol::NodeStatus::default()
    }
}
