use std::collections::VecDeque;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;

use ext4plus::{Ext4Read, Ext4Write};

use crate::storage::{PartitionIo, SectorDevice};

pub struct Ext4Storage<D> {
    partition: Arc<PartitionIo<D>>,
}

impl<D> Clone for Ext4Storage<D> {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
        }
    }
}

impl<D> Ext4Storage<D> {
    pub fn new(partition: Arc<PartitionIo<D>>) -> Self {
        Self { partition }
    }
}

impl<D> Ext4Read for Ext4Storage<D>
where
    D: SectorDevice + Send,
    D::Error: Error + Send + Sync + 'static,
{
    fn read(
        &self,
        start_byte: u64,
        destination: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        self.partition
            .read(start_byte, destination)
            .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync + 'static>)
    }
}

impl<D> Ext4Write for Ext4Storage<D>
where
    D: SectorDevice + Send,
    D::Error: Error + Send + Sync + 'static,
{
    fn write(
        &self,
        start_byte: u64,
        source: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        self.partition
            .write(start_byte, source)
            .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync + 'static>)
    }
}

const READ_WINDOW_BYTES: u64 = 64 * 1024;
const READ_CACHE_WINDOWS: usize = 16;

/// Bounded read-ahead for a partition that remains immutable while mounted.
/// This adapter deliberately implements no writer. Never use it for Data or
/// an image that another owner can modify during the mount's lifetime.
pub struct ImmutableExt4Storage<D> {
    partition: Arc<PartitionIo<D>>,
    windows: Mutex<VecDeque<(u64, Vec<u8>)>>,
}

impl<D> ImmutableExt4Storage<D> {
    pub fn new(partition: Arc<PartitionIo<D>>) -> Self {
        Self {
            partition,
            windows: Mutex::new(VecDeque::new()),
        }
    }
}

impl<D> Ext4Read for ImmutableExt4Storage<D>
where
    D: SectorDevice + Send,
    D::Error: Error + Send + Sync + 'static,
{
    fn read(&self, start: u64, output: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let end = start
            .checked_add(u64::try_from(output.len())?)
            .ok_or_else(|| std::io::Error::other("filesystem offset overflow"))?;
        if end > self.partition.byte_len() {
            return Err(std::io::Error::other("filesystem access is outside its partition").into());
        }
        let mut windows = self
            .windows
            .lock()
            .map_err(|_| std::io::Error::other("immutable read cache lock poisoned"))?;
        let mut copied = 0;
        while copied < output.len() {
            let position = start + copied as u64;
            let window_start = position / READ_WINDOW_BYTES * READ_WINDOW_BYTES;
            let window = if let Some(index) = windows
                .iter()
                .position(|(offset, _)| *offset == window_start)
            {
                windows
                    .remove(index)
                    .ok_or_else(|| std::io::Error::other("immutable cache entry disappeared"))?
            } else {
                let length =
                    (self.partition.byte_len() - window_start).min(READ_WINDOW_BYTES) as usize;
                let mut bytes = vec![0; length];
                self.partition.read(window_start, &mut bytes)?;
                (window_start, bytes)
            };
            let offset = (position - window_start) as usize;
            let count = (output.len() - copied).min(window.1.len() - offset);
            output[copied..copied + count].copy_from_slice(&window.1[offset..offset + count]);
            copied += count;
            windows.push_front(window);
            windows.truncate(READ_CACHE_WINDOWS);
        }
        Ok(())
    }
}
