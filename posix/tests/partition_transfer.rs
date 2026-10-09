use std::sync::{Arc, Mutex};

use filesystem_service::storage::{PartitionIo, PartitionIoError, SectorDevice};

type Calls = Arc<Mutex<Vec<(u64, usize, usize)>>>;
struct Disk(Calls);
impl SectorDevice for Disk {
    type Error = &'static str;
    fn read_sectors(&mut self, lba: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        assert!(output.len().is_multiple_of(512));
        assert!(output.len() <= 256 * 1024);
        self.0
            .lock()
            .unwrap()
            .push((lba, output.len(), output.as_ptr() as usize));
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = ((lba * 512 + index as u64) % 251) as u8;
        }
        Ok(())
    }
    fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
        panic!("read path must not write")
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        panic!("read path must not flush")
    }
}

#[test]
fn aligned_partition_reads_use_the_destination_directly_and_bound_each_transfer() {
    let calls = Calls::default();
    let io = PartitionIo::new(Disk(calls.clone()), 17, 2048);
    let mut bytes = vec![0; 256 * 1024 + 1024];
    let pointer = bytes.as_ptr() as usize;
    io.read(512, &mut bytes).unwrap();
    assert_eq!(
        *calls.lock().unwrap(),
        [(18, 256 * 1024, pointer), (530, 1024, pointer + 256 * 1024)]
    );
    for (index, byte) in bytes.iter().enumerate() {
        assert_eq!(*byte, ((18 * 512 + index) % 251) as u8);
    }
}

#[test]
fn unaligned_reads_cover_only_required_sectors_and_respect_partition_bounds() {
    let calls = Calls::default();
    let io = PartitionIo::new(Disk(calls.clone()), 17, 2048);
    for (offset, length) in [(511, 3), (513, 1), (3, 256 * 1024 + 7)] {
        calls.lock().unwrap().clear();
        let mut bytes = vec![0; length];
        io.read(offset, &mut bytes).unwrap();
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, ((17 * 512 + offset + index as u64) % 251) as u8);
        }
        let transfers = calls.lock().unwrap();
        assert_eq!(transfers[0].0, 17 + offset / 512);
        assert_eq!(
            transfers.iter().map(|(_, length, _)| length).sum::<usize>(),
            ((offset as usize % 512 + length).div_ceil(512)) * 512
        );
    }
    calls.lock().unwrap().clear();
    assert_eq!(
        io.read(2048 * 512 - 1, &mut [0; 2]),
        Err(PartitionIoError::OutOfBounds)
    );
    assert_eq!(
        io.read(u64::MAX, &mut [0; 1]),
        Err(PartitionIoError::OffsetOverflow)
    );
    io.read(2048 * 512, &mut []).unwrap();
    assert!(calls.lock().unwrap().is_empty());
}
