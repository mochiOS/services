use std::error::Error;
use std::sync::Arc;

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
