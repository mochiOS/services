//! Byte stream plus owned ancillary markers. No client FD or wire identity is
//! stored here. Queue mutation is serialized by the socket worker.
use crate::socket_rights::{Bundle, Lease};
use std::collections::VecDeque;

pub const MAX_MARKERS: usize = 256;

struct Marker {
    start: usize,
    end: usize,
    rights: Bundle,
}

pub struct StreamQueue {
    bytes: VecDeque<u8>,
    markers: VecDeque<Marker>,
}
impl Default for StreamQueue {
    fn default() -> Self {
        Self::new()
    }
}
impl StreamQueue {
    pub const fn new() -> Self {
        Self {
            bytes: VecDeque::new(),
            markers: VecDeque::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub fn ancillary_leases(&self) -> impl Iterator<Item = &Lease> {
        self.markers
            .iter()
            .flat_map(|marker| marker.rights.leases())
    }
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.markers.clear();
    }
    pub fn write(&mut self, input: &[u8]) -> Result<usize, i32> {
        if input.len() > crate::socket::RECEIVE_CAPACITY.saturating_sub(self.len()) {
            return Err(-11);
        }
        self.bytes.try_reserve(input.len()).map_err(|_| -12)?;
        self.bytes.extend(input);
        Ok(input.len())
    }
    /// All allocations precede byte or rights publication. A nonempty bundle
    /// needs a data byte: an empty stream send transfers no references.
    /// Errors return the unchanged bundle to the staging owner.
    pub fn write_with_rights(
        &mut self,
        input: &[u8],
        rights: Bundle,
    ) -> Result<usize, (i32, Bundle)> {
        if input.is_empty() || rights.is_empty() {
            return self.write(input).map_err(|error| (error, rights));
        }
        if input.len() > crate::socket::RECEIVE_CAPACITY.saturating_sub(self.len())
            || self.markers.len() == MAX_MARKERS
        {
            return Err((-11, rights));
        }
        if self.bytes.try_reserve(input.len()).is_err() || self.markers.try_reserve(1).is_err() {
            return Err((-12, rights));
        }
        let start = self.bytes.len();
        self.bytes.extend(input);
        self.markers.push_back(Marker {
            start,
            end: start + input.len(),
            rights,
        });
        Ok(input.len())
    }
    /// A consuming read may include preceding plain bytes and the first
    /// rights-bearing segment, but cannot cross its boundary into later sends.
    pub fn read_length(&self, maximum: usize) -> usize {
        let count = maximum.min(self.len());
        match self.markers.front() {
            Some(marker) if marker.start < count => count.min(marker.end),
            _ => count,
        }
    }
    pub fn read_rights(&self, maximum: usize) -> Option<&Bundle> {
        self.markers
            .front()
            .filter(|marker| marker.start < self.read_length(maximum))
            .map(|marker| &marker.rights)
    }
    /// Inspect without moving references or advancing the receive head.
    pub fn peek(&self, offset: usize, output: &mut [u8]) -> usize {
        let mut count = output.len().min(self.len().saturating_sub(offset));
        if let Some(marker) = self.markers.iter().find(|marker| marker.end > offset) {
            if marker.start < offset.saturating_add(count) {
                count = count.min(marker.end - offset);
            }
        }
        for (target, byte) in output[..count]
            .iter_mut()
            .zip(self.bytes.iter().skip(offset))
        {
            *target = *byte;
        }
        count
    }
    pub fn read_owned(&mut self, output: &mut [u8]) -> (usize, Option<Bundle>) {
        let count = self.read_length(output.len());
        for byte in &mut output[..count] {
            *byte = self.bytes.pop_front().unwrap();
        }
        let rights = if self
            .markers
            .front()
            .is_some_and(|marker| marker.start < count)
        {
            Some(self.markers.pop_front().unwrap().rights)
        } else {
            None
        };
        for marker in &mut self.markers {
            marker.start -= count;
            marker.end -= count;
        }
        (count, rights)
    }
    /// Ordinary read/recv discards any consumed ancillary references once.
    pub fn read(&mut self, output: &mut [u8]) -> usize {
        self.read_owned(output).0
    }
}
