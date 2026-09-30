use std::fmt;
use std::sync::Mutex;

pub const SECTOR_BYTES: usize = 512;
const MAX_TRANSFER_BYTES: usize = 256 * 1024;

pub trait SectorDevice {
    type Error;

    fn read_sectors(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), Self::Error>;
    fn write_sectors(&mut self, lba: u64, bytes: &[u8]) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum PartitionIoError<E> {
    Device(E),
    OutOfBounds,
    OffsetOverflow,
    Poisoned,
}

impl<E: fmt::Display> fmt::Display for PartitionIoError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => write!(formatter, "storage device error: {error}"),
            Self::OutOfBounds => formatter.write_str("filesystem access is outside its partition"),
            Self::OffsetOverflow => formatter.write_str("filesystem byte offset overflow"),
            Self::Poisoned => formatter.write_str("filesystem storage lock is poisoned"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for PartitionIoError<E> {}

pub struct PartitionIo<D> {
    device: Mutex<D>,
    first_lba: u64,
    sector_count: u64,
}

impl<D> PartitionIo<D> {
    pub const fn new(device: D, first_lba: u64, sector_count: u64) -> Self {
        Self {
            device: Mutex::new(device),
            first_lba,
            sector_count,
        }
    }

    pub const fn byte_len(&self) -> u64 {
        self.sector_count.saturating_mul(SECTOR_BYTES as u64)
    }
}

impl<D: SectorDevice> PartitionIo<D> {
    pub fn read(
        &self,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), PartitionIoError<D::Error>> {
        self.check_range(offset, destination.len())?;
        if destination.is_empty() {
            return Ok(());
        }
        let mut device = self.device.lock().map_err(|_| PartitionIoError::Poisoned)?;
        transfer_read(&mut *device, self.first_lba, offset, destination)
    }

    pub fn write(&self, offset: u64, source: &[u8]) -> Result<(), PartitionIoError<D::Error>> {
        self.check_range(offset, source.len())?;
        if source.is_empty() {
            return Ok(());
        }
        let mut device = self.device.lock().map_err(|_| PartitionIoError::Poisoned)?;
        transfer_write(&mut *device, self.first_lba, offset, source)
    }

    pub fn flush(&self) -> Result<(), PartitionIoError<D::Error>> {
        self.device
            .lock()
            .map_err(|_| PartitionIoError::Poisoned)?
            .flush()
            .map_err(PartitionIoError::Device)
    }

    fn check_range(&self, offset: u64, length: usize) -> Result<(), PartitionIoError<D::Error>> {
        let end = offset
            .checked_add(u64::try_from(length).map_err(|_| PartitionIoError::OffsetOverflow)?)
            .ok_or(PartitionIoError::OffsetOverflow)?;
        if end > self.byte_len() {
            return Err(PartitionIoError::OutOfBounds);
        }
        Ok(())
    }
}

fn transfer_read<D: SectorDevice>(
    device: &mut D,
    first_lba: u64,
    offset: u64,
    destination: &mut [u8],
) -> Result<(), PartitionIoError<D::Error>> {
    let first_sector = offset / SECTOR_BYTES as u64;
    let offset_in_sector = offset as usize % SECTOR_BYTES;
    let covered = offset_in_sector
        .checked_add(destination.len())
        .ok_or(PartitionIoError::OffsetOverflow)?;
    let transfer_len = covered
        .checked_add(SECTOR_BYTES - 1)
        .ok_or(PartitionIoError::OffsetOverflow)?
        / SECTOR_BYTES
        * SECTOR_BYTES;
    let mut copied = 0;
    let mut sector_offset = 0;
    let mut buffer = vec![0u8; MAX_TRANSFER_BYTES];
    while sector_offset < transfer_len {
        let length = (transfer_len - sector_offset).min(buffer.len());
        let lba = first_lba
            .checked_add(first_sector)
            .and_then(|value| value.checked_add((sector_offset / SECTOR_BYTES) as u64))
            .ok_or(PartitionIoError::OffsetOverflow)?;
        device
            .read_sectors(lba, &mut buffer[..length])
            .map_err(PartitionIoError::Device)?;
        let start = if sector_offset == 0 {
            offset_in_sector
        } else {
            0
        };
        let count = (length - start).min(destination.len() - copied);
        destination[copied..copied + count].copy_from_slice(&buffer[start..start + count]);
        copied += count;
        sector_offset += length;
    }
    Ok(())
}

fn transfer_write<D: SectorDevice>(
    device: &mut D,
    first_lba: u64,
    offset: u64,
    source: &[u8],
) -> Result<(), PartitionIoError<D::Error>> {
    let mut consumed = 0;
    let mut current = offset;
    let mut sector = [0u8; SECTOR_BYTES];
    while consumed < source.len() {
        let offset_in_sector = current as usize % SECTOR_BYTES;
        let count = (SECTOR_BYTES - offset_in_sector).min(source.len() - consumed);
        let lba = first_lba
            .checked_add(current / SECTOR_BYTES as u64)
            .ok_or(PartitionIoError::OffsetOverflow)?;
        if offset_in_sector != 0 || count != SECTOR_BYTES {
            device
                .read_sectors(lba, &mut sector)
                .map_err(PartitionIoError::Device)?;
        }
        sector[offset_in_sector..offset_in_sector + count]
            .copy_from_slice(&source[consumed..consumed + count]);
        device
            .write_sectors(lba, &sector)
            .map_err(PartitionIoError::Device)?;
        consumed += count;
        current = current
            .checked_add(count as u64)
            .ok_or(PartitionIoError::OffsetOverflow)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryDisk(Vec<u8>);

    impl SectorDevice for MemoryDisk {
        type Error = &'static str;

        fn read_sectors(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let start = lba as usize * SECTOR_BYTES;
            bytes.copy_from_slice(self.0.get(start..start + bytes.len()).ok_or("read range")?);
            Ok(())
        }

        fn write_sectors(&mut self, lba: u64, bytes: &[u8]) -> Result<(), Self::Error> {
            let start = lba as usize * SECTOR_BYTES;
            self.0
                .get_mut(start..start + bytes.len())
                .ok_or("write range")?
                .copy_from_slice(bytes);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn unaligned_io_is_scoped_to_the_partition() {
        let mut bytes = vec![0xa5; SECTOR_BYTES * 6];
        bytes[SECTOR_BYTES..SECTOR_BYTES * 5].fill(0);
        let io = PartitionIo::new(MemoryDisk(bytes), 1, 4);

        io.write(510, &[1, 2, 3, 4]).unwrap();
        let mut result = [0u8; 4];
        io.read(510, &mut result).unwrap();
        assert_eq!(result, [1, 2, 3, 4]);

        let disk = io.device.into_inner().unwrap();
        assert!(disk.0[..SECTOR_BYTES].iter().all(|byte| *byte == 0xa5));
        assert!(disk.0[SECTOR_BYTES * 5..].iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn rejects_partition_overrun_and_offset_overflow() {
        let io = PartitionIo::new(MemoryDisk(vec![0; SECTOR_BYTES * 2]), 0, 2);
        assert_eq!(
            io.read(1023, &mut [0; 2]),
            Err(PartitionIoError::OutOfBounds)
        );
        assert_eq!(
            io.write(u64::MAX, &[1]),
            Err(PartitionIoError::OffsetOverflow)
        );
    }
}
