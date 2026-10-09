use ext4plus::Ext4Read;
use filesystem_service::ext4::ImmutableExt4Storage;
use filesystem_service::storage::{PartitionIo, SectorDevice};
use std::sync::{Arc, Mutex};

struct Disk {
    calls: Arc<Mutex<Vec<(u64, usize)>>>,
    fail: Arc<Mutex<bool>>,
}
impl SectorDevice for Disk {
    type Error = std::io::Error;
    fn read_sectors(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.calls.lock().unwrap().push((lba, bytes.len()));
        if *self.fail.lock().unwrap() {
            return Err(std::io::Error::other("injected read failure"));
        }
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = ((lba * 512 + index as u64) % 251) as u8;
        }
        Ok(())
    }
    fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
        panic!("immutable storage cannot write")
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        panic!("immutable storage cannot flush")
    }
}

#[test]
fn immutable_reads_reuse_windows_cross_boundaries_and_clip_the_partition_tail() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(Mutex::new(false));
    let storage = ImmutableExt4Storage::new(Arc::new(PartitionIo::new(
        Disk {
            calls: calls.clone(),
            fail,
        },
        7,
        129,
    )));
    for (offset, length) in [(0, 4), (500, 4096), (65530, 100), (65536, 512)] {
        let mut output = vec![0; length];
        storage.read(offset, &mut output).unwrap();
        for (index, byte) in output.iter().enumerate() {
            assert_eq!(*byte, ((7 * 512 + offset + index as u64) % 251) as u8);
        }
    }
    assert_eq!(*calls.lock().unwrap(), [(7, 65536), (135, 512)]);
    let mut output = [0xaa; 2];
    assert!(storage.read(129 * 512 - 1, &mut output).is_err());
    assert!(storage.read(u64::MAX, &mut output).is_err());
    assert_eq!(output, [0xaa; 2]);
    storage.read(129 * 512, &mut []).unwrap();
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn immutable_read_failures_are_not_cached_and_old_windows_are_evicted() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(Mutex::new(true));
    let storage = ImmutableExt4Storage::new(Arc::new(PartitionIo::new(
        Disk {
            calls: calls.clone(),
            fail: fail.clone(),
        },
        7,
        4096,
    )));
    let mut byte = [0];
    assert!(storage.read(0, &mut byte).is_err());
    *fail.lock().unwrap() = false;
    storage.read(0, &mut byte).unwrap();
    for window in 1..=16 {
        storage.read(window * 65536, &mut byte).unwrap();
    }
    storage.read(0, &mut byte).unwrap();
    assert_eq!(calls.lock().unwrap().len(), 19);
}
