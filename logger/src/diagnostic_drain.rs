//! Reader-owned diagnostic persistence. Partial writes and failed syncs retain
//! their progress; a fresh kernel snapshot is not taken until commit succeeds.

const CHUNK_BYTES: usize = 4096;
const GAP_PREFIX_BYTES: usize = 96;

pub struct Batch {
    pub bytes: usize,
    pub next_cursor: u64,
    pub dropped: u64,
}

pub trait Backend {
    type Error;
    fn read(&mut self, cursor: u64, bytes: &mut [u8]) -> Result<Batch, Self::Error>;
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error>;
    fn sync(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Backend(E),
    InvalidRead,
    InvalidWrite,
    WriteZero,
}

pub struct Drain {
    cursor: u64,
    next_cursor: u64,
    bytes: [u8; CHUNK_BYTES + GAP_PREFIX_BYTES],
    length: usize,
    written: usize,
    pending: bool,
}

impl Drain {
    pub const fn new() -> Self {
        Self {
            cursor: 0,
            next_cursor: 0,
            bytes: [0; CHUNK_BYTES + GAP_PREFIX_BYTES],
            length: 0,
            written: 0,
            pending: false,
        }
    }

    /// Returns true after one durable batch, false if history is caught up.
    /// On failure, callers retry this same object, not a newly created reader.
    pub fn step<B: Backend>(&mut self, backend: &mut B) -> Result<bool, Error<B::Error>> {
        if !self.pending {
            let batch = backend
                .read(self.cursor, &mut self.bytes[GAP_PREFIX_BYTES..])
                .map_err(Error::Backend)?;
            if batch.bytes > CHUNK_BYTES
                || self
                    .cursor
                    .checked_add(batch.dropped)
                    .and_then(|start| start.checked_add(batch.bytes as u64))
                    != Some(batch.next_cursor)
            {
                return Err(Error::InvalidRead);
            }
            if batch.bytes == 0 && batch.dropped == 0 {
                return Ok(false);
            }
            let prefix = if batch.dropped == 0 {
                String::new()
            } else {
                format!(
                    "\n[diagnostics: {} bytes overwritten before persistence]\n",
                    batch.dropped
                )
            };
            if prefix.len() > GAP_PREFIX_BYTES {
                return Err(Error::InvalidRead);
            }
            self.bytes.copy_within(
                GAP_PREFIX_BYTES..GAP_PREFIX_BYTES + batch.bytes,
                prefix.len(),
            );
            self.bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
            self.length = prefix.len() + batch.bytes;
            self.next_cursor = batch.next_cursor;
            self.written = 0;
            self.pending = true;
        }
        while self.written < self.length {
            let remaining = &self.bytes[self.written..self.length];
            let written = backend.write(remaining).map_err(Error::Backend)?;
            if written == 0 {
                return Err(Error::WriteZero);
            }
            if written > remaining.len() {
                return Err(Error::InvalidWrite);
            }
            self.written += written;
        }
        backend.sync().map_err(Error::Backend)?;
        self.cursor = self.next_cursor;
        self.pending = false;
        Ok(true)
    }
}
