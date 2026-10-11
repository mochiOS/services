use ext4plus::{Ext4, Ext4Read};
use filesystem_service::{
    ext4::ImmutableExt4Storage,
    service::{FilesystemService, PathAnchors},
    storage::{PartitionIo, SectorDevice},
};
use mochios_filesystem_protocol as wire;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::FileExt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

struct Image {
    file: File,
    reads: Arc<AtomicUsize>,
}
impl SectorDevice for Image {
    type Error = std::io::Error;
    fn read_sectors(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.file.read_exact_at(
            bytes,
            lba.checked_mul(512)
                .ok_or_else(|| std::io::Error::other("offset overflow"))?,
        )
    }
    fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
        panic!("immutable image must not be written")
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        panic!("read-only probe must not flush")
    }
}

/// Compare the actual filesystem backend with the native C probe, without a
/// VM. Paths must be explicit: no assumption that an old build is current.
#[test]
#[ignore = "requires POSIX_DICTIONARY_IMAGE and POSIX_DICTIONARY_REFERENCE"]
fn production_immutable_backend_reads_the_whole_dictionary() {
    let file = File::open(std::env::var_os("POSIX_DICTIONARY_IMAGE").unwrap()).unwrap();
    let length = file.metadata().unwrap().len();
    assert_eq!(length % 512, 0);
    let reads = Arc::new(AtomicUsize::new(0));
    let partition = Arc::new(PartitionIo::new(
        Image {
            file,
            reads: reads.clone(),
        },
        0,
        length / 512,
    ));
    let storage = ImmutableExt4Storage::new(partition);
    // Exercise the same adapter and ext4plus configuration as filesystem.service.
    let filesystem = Ext4::load(Box::new(storage) as Box<dyn Ext4Read>).unwrap();
    let mut service = FilesystemService::new(filesystem);
    let mut credential_bytes = [0; wire::CREDENTIALS_MAX_LEN];
    let size = wire::encode_credentials_payload(0, 0, &[], &[], &mut credential_bytes).unwrap();
    let credentials = wire::decode_credentials_payload(&credential_bytes[..size])
        .unwrap()
        .0;
    let open = service
        .open_at(
            wire::Header {
                opcode: wire::OP_OPEN_AT,
                flags: wire::OPEN_AT_READ,
                ..Default::default()
            },
            b"/system/libraries/ime/ja.mime",
            PathAnchors::default(),
            credentials,
        )
        .unwrap()
        .header
        .open_id;
    let baseline = reads.load(Ordering::Relaxed);
    let started = Instant::now();
    let mut buffer = vec![0; mnu_abi::provider::MAX_SHARED_READ_LEN];
    let mut digest = Sha256::new();
    let mut total = 0u64;
    loop {
        let (count, start) = service.provider_read_into(open, &mut buffer).unwrap();
        assert_eq!(start, total);
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        total += count as u64;
    }
    let elapsed = started.elapsed();
    let calls = reads.load(Ordering::Relaxed) - baseline;
    let mut reference =
        File::open(std::env::var_os("POSIX_DICTIONARY_REFERENCE").unwrap()).unwrap();
    assert_eq!(total, reference.metadata().unwrap().len());
    let mut expected = Sha256::new();
    loop {
        let count = reference.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        expected.update(&buffer[..count]);
    }
    assert_eq!(digest.finalize(), expected.finalize());
    service.provider_close(open).unwrap();
    eprintln!("immutable-dictionary: {total} bytes in {elapsed:?}; {calls} device reads");
}
