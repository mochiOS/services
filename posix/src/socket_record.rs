//! Bounded UNIX datagram receive records. This is service-side state, not a
//! native stream Provider: splitting HandleRead/HandleWrite would destroy the
//! record boundary. The adapter must authenticate socket authority and resolve
//! the destination before calling `push`; source names are captured by that
//! adapter, never trusted from an unauthenticated client request.

use mochios_posix_protocol::socket::{Address, MAX_ADDRESS_LEN};
use std::collections::VecDeque;

pub const MAX_RECORD_SIZE: usize = super::socket::RECEIVE_CAPACITY;
/// Bound metadata as well as payload storage, including empty datagrams.
pub const MAX_QUEUED_RECORDS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceAddress {
    bytes: [u8; MAX_ADDRESS_LEN],
    length: usize,
}

impl SourceAddress {
    pub fn new(address: Address<'_>) -> Result<Self, i32> {
        if !matches!(
            address,
            Address::UnixUnnamed | Address::UnixPath(_) | Address::UnixAbstract(_)
        ) {
            return Err(-97);
        }
        let mut bytes = [0; MAX_ADDRESS_LEN];
        let length = address.encode(&mut bytes).map_err(|_| -22)?;
        Ok(Self { bytes, length })
    }

    pub fn encoded(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

struct Record {
    source: SourceAddress,
    payload: Vec<u8>,
}

impl Record {
    fn charge(&self) -> usize {
        self.payload.len().max(1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedRecord {
    pub copied: usize,
    pub length: usize,
    pub source: SourceAddress,
}

impl ReceivedRecord {
    pub const fn truncated(&self) -> bool {
        self.copied < self.length
    }
}

/// Externally serialized with destination resolution, send commitment and
/// readiness notification. No FD, PID lookup, native Handle, EOF or stream
/// aggregation is hidden here. Empty queue is EAGAIN, not a zero-byte record.
pub struct RecordQueue {
    records: VecDeque<Record>,
    charged: usize,
    capacity: usize,
}

impl Default for RecordQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordQueue {
    pub const fn new() -> Self {
        Self {
            records: VecDeque::new(),
            charged: 0,
            capacity: super::socket::RECEIVE_CAPACITY,
        }
    }

    pub fn is_readable(&self) -> bool {
        !self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn charged(&self) -> usize {
        self.charged
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Like stream SO_RCVBUF, clamp the requested limit without discarding
    /// previously committed data, even if it now exceeds the effective limit.
    pub fn set_capacity(&mut self, requested: u32) -> Result<(), i32> {
        if requested > i32::MAX as u32 {
            return Err(-22);
        }
        self.capacity = (requested as usize).clamp(
            super::socket::MIN_RECEIVE_CAPACITY,
            super::socket::RECEIVE_CAPACITY,
        );
        Ok(())
    }

    /// A permanently oversized message is EMSGSIZE; temporary queue pressure
    /// is false/EAGAIN. A sender must wait for the whole record, never commit
    /// a prefix. Empty messages consume a slot and one unit of queue budget.
    pub fn can_push(&self, length: usize, send_capacity: usize) -> Result<bool, i32> {
        let charge = length.max(1);
        if length > MAX_RECORD_SIZE || charge > self.capacity.min(send_capacity) {
            return Err(-90);
        }
        Ok(self.records.len() < MAX_QUEUED_RECORDS
            && charge <= self.capacity.saturating_sub(self.charged))
    }

    pub fn push(
        &mut self,
        source: SourceAddress,
        payload: &[u8],
        send_capacity: usize,
    ) -> Result<usize, i32> {
        if !self.can_push(payload.len(), send_capacity)? {
            return Err(-11);
        }
        // All fallible allocations precede commitment. On failure the caller
        // retains ownership, and the queue contents and charge are unchanged.
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(payload.len()).map_err(|_| -12)?;
        bytes.extend_from_slice(payload);
        self.records.try_reserve(1).map_err(|_| -12)?;
        self.charged += bytes.len().max(1);
        self.records.push_back(Record {
            source,
            payload: bytes,
        });
        Ok(payload.len())
    }

    /// Copy at most one complete record's prefix. A consuming receive drops
    /// any uncopied suffix; PEEK preserves both the record and all capacity.
    /// A zero-length output still consumes one record unless peeking. The
    /// returned source and original length belong to that exact same record.
    pub fn receive(&mut self, output: &mut [u8], peek: bool) -> Result<ReceivedRecord, i32> {
        let record = self.records.front().ok_or(-11)?;
        let copied = output.len().min(record.payload.len());
        output[..copied].copy_from_slice(&record.payload[..copied]);
        let received = ReceivedRecord {
            copied,
            length: record.payload.len(),
            source: record.source,
        };
        if !peek {
            self.charged -= record.charge();
            self.records.pop_front();
        }
        Ok(received)
    }

    /// Read shutdown/final release discards queued records and their payloads.
    pub fn clear(&mut self) {
        self.records.clear();
        self.charged = 0;
    }
}
