//! Fail-closed installation of a signed update into the inactive A/B slots.
//!
//! A v1 update payload is the exact concatenation of one complete Boot slot
//! image and one complete System filesystem image. The installed GPT fixes
//! both lengths. This deliberately cannot resize or rewrite the partition map.

use mochios_boot_selection::gpt_identity::{PartitionRange, UpdateLayout};
use mochios_boot_selection::storage::{self, RecordIo, StoreError};
use mochios_boot_selection::{RECORD_LEN, Slot};
use mochios_system_image::{Architecture, ArtifactDigests, Manifest, SlotHeader, MANIFEST_LEN, SLOT_HEADER_LEN};
use sha2::{Digest, Sha256};

use crate::os_update::VerifiedManifest;

const SECTOR_BYTES: usize = 512;
const CHUNK_BYTES: usize = 1024 * 1024;
const STATE_COPY_SECTORS: [u64; 2] = [0, 8];

pub trait BlockDevice {
    type Error;
    fn read(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), Self::Error>;
    fn write(&mut self, lba: u64, bytes: &[u8]) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

pub trait RangeSource {
    type Error;
    fn fetch(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallError<DiskError, FetchError> {
    Disk(DiskError),
    Fetch(FetchError),
    InvalidLayout,
    InvalidPayload,
    WrongArchitecture,
    WrongRelease,
    ArtifactChecksum,
    SlotVerification,
    State(StoreError<DiskError>),
}

fn bytes(range: PartitionRange) -> Option<u64> { range.sectors().checked_mul(SECTOR_BYTES as u64) }

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).fold(0u8, |difference, (a, b)| difference | (a ^ b)) == 0
}

fn architecture() -> Architecture {
    #[cfg(target_arch = "x86_64")]
    { Architecture::X86_64 }
    #[cfg(target_arch = "aarch64")]
    { Architecture::Aarch64 }
}

/// Writes only the inactive Boot/System pair and publishes it by updating the
/// redundant boot-state record only after full read-back verification.
pub fn install<D: BlockDevice, S: RangeSource>(
    disk: &mut D,
    source: &mut S,
    layout: UpdateLayout,
    running: Slot,
    current_build: u64,
    offer: &VerifiedManifest,
    system_keys: &[[u8; 32]],
) -> Result<Slot, InstallError<D::Error, S::Error>> {
    let target = running.other();
    let target_index = if target == Slot::A { 0 } else { 1 };
    let boot = layout.boot[target_index];
    let system = layout.system[target_index];
    let boot_bytes = bytes(boot).ok_or(InstallError::InvalidLayout)?;
    let system_bytes = bytes(system).ok_or(InstallError::InvalidLayout)?;
    let payload_bytes = boot_bytes.checked_add(system_bytes).ok_or(InstallError::InvalidLayout)?;
    if offer.size_bytes() != payload_bytes || payload_bytes == 0
        || boot.first_lba <= layout.esp.last_lba
        || offer.architecture() != std::env::consts::ARCH
    {
        return Err(InstallError::InvalidPayload);
    }

    let mut state = StateRecords { disk, first_lba: layout.state.first_lba };
    let record = storage::load(&mut state).map_err(InstallError::State)?.record;
    if record.active() != running || record.pending().is_some() || offer.build_number() <= current_build {
        return Err(InstallError::WrongRelease);
    }

    let mut artifact_digest = Sha256::new();
    let mut offset = 0u64;
    while offset < payload_bytes {
        let partition_remaining = if offset < boot_bytes {
            boot_bytes - offset
        } else {
            payload_bytes - offset
        };
        let length = core::cmp::min(CHUNK_BYTES as u64, partition_remaining) as usize;
        let chunk = source.fetch(offset, length).map_err(InstallError::Fetch)?;
        if chunk.len() != length || chunk.len() % SECTOR_BYTES != 0 {
            return Err(InstallError::InvalidPayload);
        }
        if offset == 0 {
            let header = chunk.get(..SLOT_HEADER_LEN).ok_or(InstallError::InvalidPayload)?;
            let header = SlotHeader::decode(header).map_err(|_| InstallError::InvalidPayload)?;
            if header.architecture != architecture() || header.image_size != boot_bytes {
                return Err(InstallError::WrongArchitecture);
            }
        }
        artifact_digest.update(&chunk);
        let (partition, partition_offset) = if offset < boot_bytes {
            (boot, offset)
        } else {
            (system, offset - boot_bytes)
        };
        state.disk.write(partition.first_lba + partition_offset / SECTOR_BYTES as u64, &chunk)
            .map_err(InstallError::Disk)?;
        offset += length as u64;
    }
    state.disk.flush().map_err(InstallError::Disk)?;
    if !constant_time_eq(&artifact_digest.finalize(), offer.sha256()) {
        return Err(InstallError::ArtifactChecksum);
    }

    verify_installed(state.disk, boot, system, offer, system_keys)?;
    state.disk.flush().map_err(InstallError::Disk)?;
    storage::stage(&mut state, target).map_err(InstallError::State)?;
    Ok(target)
}

/// Commits a trial only after the update service itself has started from that
/// slot. A stable boot is a no-op; contradictory state fails closed.
pub fn confirm_running<D: BlockDevice>(
    disk: &mut D,
    layout: UpdateLayout,
    running: Slot,
) -> Result<bool, InstallError<D::Error, core::convert::Infallible>> {
    let mut state = StateRecords { disk, first_lba: layout.state.first_lba };
    let record = storage::load(&mut state).map_err(InstallError::State)?.record;
    match record.pending() {
        None if record.active() == running => Ok(false),
        Some(slot) if slot == running && record.attempts_remaining() < mochios_boot_selection::MAX_TRIAL_BOOTS => {
            storage::confirm(&mut state, running).map_err(InstallError::State)?;
            Ok(true)
        }
        _ => Err(InstallError::WrongRelease),
    }
}

fn verify_installed<D: BlockDevice, FetchError>(
    disk: &mut D,
    boot: PartitionRange,
    system: PartitionRange,
    offer: &VerifiedManifest,
    system_keys: &[[u8; 32]],
) -> Result<(), InstallError<D::Error, FetchError>> {
    let mut header_bytes = [0u8; SLOT_HEADER_LEN];
    disk.read(boot.first_lba, &mut header_bytes).map_err(InstallError::Disk)?;
    let header = SlotHeader::decode(&header_bytes).map_err(|_| InstallError::SlotVerification)?;
    if header.image_size != bytes(boot).ok_or(InstallError::InvalidLayout)?
        || header.architecture != architecture()
    {
        return Err(InstallError::SlotVerification);
    }
    let mut manifest_bytes = [0u8; MANIFEST_LEN];
    read_region(disk, boot, header.manifest.offset, &mut manifest_bytes)?;
    let manifest = Manifest::decode(&manifest_bytes).map_err(|_| InstallError::SlotVerification)?;
    if manifest.architecture() != architecture()
        || manifest.image_size() != bytes(system).ok_or(InstallError::InvalidLayout)?
        || manifest.build() != offer.build_number() || manifest.version() != offer.version()
    {
        return Err(InstallError::WrongRelease);
    }
    let digests = ArtifactDigests {
        system: hash_partition(disk, system)?,
        kernel: hash_region(disk, boot, header.kernel.offset, header.kernel.length)?,
        kernel_meta: hash_region(disk, boot, header.kernel_meta.offset, header.kernel_meta.length)?,
        initfs: hash_region(disk, boot, header.initfs.offset, header.initfs.length)?,
    };
    manifest.verify(&digests, system_keys).map_err(|_| InstallError::SlotVerification)
}

fn read_region<D: BlockDevice, FetchError>(
    disk: &mut D,
    partition: PartitionRange,
    offset: u64,
    output: &mut [u8],
) -> Result<(), InstallError<D::Error, FetchError>> {
    if offset % SECTOR_BYTES as u64 != 0 { return Err(InstallError::InvalidPayload); }
    let rounded = output.len().checked_add(SECTOR_BYTES - 1).ok_or(InstallError::InvalidPayload)?
        / SECTOR_BYTES * SECTOR_BYTES;
    if offset.checked_add(rounded as u64).is_none_or(|end| end > bytes(partition).unwrap_or(0)) {
        return Err(InstallError::InvalidPayload);
    }
    let mut block = vec![0u8; rounded];
    disk.read(partition.first_lba + offset / SECTOR_BYTES as u64, &mut block)
        .map_err(InstallError::Disk)?;
    output.copy_from_slice(&block[..output.len()]);
    Ok(())
}

fn hash_partition<D: BlockDevice, FetchError>(
    disk: &mut D,
    partition: PartitionRange,
) -> Result<[u8; 32], InstallError<D::Error, FetchError>> {
    hash_region(disk, partition, 0, bytes(partition).ok_or(InstallError::InvalidLayout)?)
}

fn hash_region<D: BlockDevice, FetchError>(
    disk: &mut D,
    partition: PartitionRange,
    offset: u64,
    length: u64,
) -> Result<[u8; 32], InstallError<D::Error, FetchError>> {
    if offset % SECTOR_BYTES as u64 != 0 || length == 0
        || offset.checked_add(length).is_none_or(|end| end > bytes(partition).unwrap_or(0))
    {
        return Err(InstallError::InvalidPayload);
    }
    let mut digest = Sha256::new();
    let mut consumed = 0u64;
    let mut buffer = vec![0u8; CHUNK_BYTES];
    while consumed < length {
        let count = core::cmp::min(buffer.len() as u64, length - consumed) as usize;
        let rounded = count.checked_add(SECTOR_BYTES - 1).ok_or(InstallError::InvalidPayload)?
            / SECTOR_BYTES * SECTOR_BYTES;
        disk.read(partition.first_lba + (offset + consumed) / SECTOR_BYTES as u64, &mut buffer[..rounded])
            .map_err(InstallError::Disk)?;
        digest.update(&buffer[..count]);
        consumed += count as u64;
    }
    Ok(digest.finalize().into())
}

struct StateRecords<'a, D> {
    disk: &'a mut D,
    first_lba: u64,
}

#[cfg(target_os = "mochios")]
pub struct SystemDisk {
    disk_id: u32,
}

#[cfg(target_os = "mochios")]
impl SystemDisk {
    pub const fn boot_disk() -> Self { Self { disk_id: 0 } }
}

#[cfg(target_os = "mochios")]
impl BlockDevice for SystemDisk {
    type Error = mochi_user_platform::syscall::SysError;

    fn read(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        for (index, chunk) in bytes.chunks_mut(256 * 1024).enumerate() {
            mochi_user_platform::storage::block_read(
                self.disk_id, lba + (index * 256 * 1024 / SECTOR_BYTES) as u64, chunk,
            )?;
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        for (index, chunk) in bytes.chunks(256 * 1024).enumerate() {
            mochi_user_platform::storage::block_write(
                self.disk_id, lba + (index * 256 * 1024 / SECTOR_BYTES) as u64, chunk,
            )?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        mochi_user_platform::storage::block_flush(self.disk_id).map(|_| ())
    }
}

#[cfg(target_os = "mochios")]
impl mochios_boot_selection::gpt_identity::SectorReader for SystemDisk {
    type Error = mochi_user_platform::syscall::SysError;

    fn read_sector(&mut self, lba: u64, sector: &mut [u8; SECTOR_BYTES]) -> Result<(), Self::Error> {
        self.read(lba, sector)
    }
}

#[cfg(target_os = "mochios")]
#[derive(Debug)]
pub enum DiscoveryError {
    Io(mochi_user_platform::syscall::SysError),
    InvalidGpt,
    WrongDisk,
}

#[cfg(target_os = "mochios")]
pub fn discover_layout(disk: &mut SystemDisk) -> Result<UpdateLayout, DiscoveryError> {
    let guid = mochi_user_platform::boot::esp_guid().map_err(DiscoveryError::Io)?;
    let mut header = [0u8; SECTOR_BYTES];
    disk.read(1, &mut header).map_err(DiscoveryError::Io)?;
    if &header[..8] != b"EFI PART" { return Err(DiscoveryError::InvalidGpt); }
    let last_lba = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let sectors = last_lba.checked_add(1).ok_or(DiscoveryError::InvalidGpt)?;
    mochios_boot_selection::gpt_identity::find_update_layout(disk, sectors, guid)
        .map_err(|error| match error {
            mochios_boot_selection::gpt_identity::MatchError::Read(error) => DiscoveryError::Io(error),
            _ => DiscoveryError::InvalidGpt,
        })?
        .ok_or(DiscoveryError::WrongDisk)
}

impl<D: BlockDevice> RecordIo for StateRecords<'_, D> {
    type Error = D::Error;

    fn read_copy(&mut self, index: usize) -> Result<[u8; RECORD_LEN], Self::Error> {
        let mut sector = [0u8; SECTOR_BYTES];
        self.disk.read(self.first_lba + STATE_COPY_SECTORS[index], &mut sector)?;
        let mut record = [0u8; RECORD_LEN];
        record.copy_from_slice(&sector[..RECORD_LEN]);
        Ok(record)
    }

    fn write_copy(&mut self, index: usize, bytes: &[u8; RECORD_LEN]) -> Result<(), Self::Error> {
        let mut sector = [0u8; SECTOR_BYTES];
        self.disk.read(self.first_lba + STATE_COPY_SECTORS[index], &mut sector)?;
        sector[..RECORD_LEN].copy_from_slice(bytes);
        self.disk.write(self.first_lba + STATE_COPY_SECTORS[index], &sector)
    }

    fn sync(&mut self) -> Result<(), Self::Error> { self.disk.flush() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const SECTORS: usize = 512;

    struct MemoryDisk {
        bytes: Vec<u8>,
        fail_write: bool,
    }

    impl BlockDevice for MemoryDisk {
        type Error = &'static str;
        fn read(&mut self, lba: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            let start = lba as usize * SECTOR_BYTES;
            output.copy_from_slice(self.bytes.get(start..start + output.len()).ok_or("read")?);
            Ok(())
        }
        fn write(&mut self, lba: u64, input: &[u8]) -> Result<(), Self::Error> {
            if self.fail_write { return Err("write"); }
            let start = lba as usize * SECTOR_BYTES;
            self.bytes.get_mut(start..start + input.len()).ok_or("write")?.copy_from_slice(input);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), Self::Error> { Ok(()) }
    }

    struct Bytes(Vec<u8>);
    impl RangeSource for Bytes {
        type Error = ();
        fn fetch(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, Self::Error> {
            Ok(self.0[offset as usize..offset as usize + length].to_vec())
        }
    }

    fn range(first_lba: u64, sectors: u64, index: u32) -> PartitionRange {
        PartitionRange { partition_index: index, first_lba, last_lba: first_lba + sectors - 1 }
    }

    fn fixture() -> (MemoryDisk, UpdateLayout, Vec<u8>, VerifiedManifest, [u8; 32]) {
        let layout = UpdateLayout {
            esp: range(1, 8, 0),
            boot: [range(16, 128, 1), range(144, 128, 3)],
            system: [range(272, 16, 2), range(288, 16, 4)],
            data: range(304, 128, 5),
            state: range(432, 16, 6),
        };
        let system = vec![0x5a; 16 * SECTOR_BYTES];
        let kernel = vec![0x11; 512];
        let kernel_meta = vec![0x22; 512];
        let initfs = vec![0x33; 512];
        let signing = SigningKey::from_bytes(&[7; 32]);
        let digests = ArtifactDigests {
            system: Sha256::digest(&system).into(),
            kernel: Sha256::digest(&kernel).into(),
            kernel_meta: Sha256::digest(&kernel_meta).into(),
            initfs: Sha256::digest(&initfs).into(),
        };
        let manifest = Manifest::create(
            "26.10", 2, architecture(), system.len() as u64, digests, &signing,
        ).unwrap();
        let boot_len = 128 * SECTOR_BYTES;
        let (header_bytes, header) = SlotHeader::create(
            architecture(), boot_len as u64, kernel.len() as u64,
            kernel_meta.len() as u64, initfs.len() as u64,
        ).unwrap();
        let mut boot = vec![0u8; boot_len];
        boot[..SLOT_HEADER_LEN].copy_from_slice(&header_bytes);
        boot[header.manifest.offset as usize..header.manifest.offset as usize + MANIFEST_LEN]
            .copy_from_slice(manifest.as_bytes());
        for (region, bytes) in [(header.kernel, &kernel), (header.kernel_meta, &kernel_meta), (header.initfs, &initfs)] {
            boot[region.offset as usize..region.offset as usize + bytes.len()].copy_from_slice(bytes);
        }
        let mut payload = boot;
        payload.extend_from_slice(&system);
        let offer = VerifiedManifest::fixture("26.10", 2, &payload);
        let mut disk = MemoryDisk { bytes: vec![0u8; SECTORS * SECTOR_BYTES], fail_write: false };
        let initial = mochios_boot_selection::BootRecord::initial().encode();
        for sector in [layout.state.first_lba, layout.state.first_lba + 8] {
            let start = sector as usize * SECTOR_BYTES;
            disk.bytes[start..start + RECORD_LEN].copy_from_slice(&initial);
        }
        (disk, layout, payload, offer, signing.verifying_key().to_bytes())
    }

    #[test]
    fn verifies_writes_reads_back_and_only_then_stages_inactive_slot() {
        let (mut disk, layout, payload, offer, key) = fixture();
        assert_eq!(install(&mut disk, &mut Bytes(payload.clone()), layout, Slot::A, 1, &offer, &[key]), Ok(Slot::B));
        let boot_start = layout.boot[1].first_lba as usize * SECTOR_BYTES;
        assert_eq!(&disk.bytes[boot_start..boot_start + 4096], &payload[..4096]);
        let mut state = StateRecords { disk: &mut disk, first_lba: layout.state.first_lba };
        let record = storage::load(&mut state).unwrap().record;
        assert_eq!(record.active(), Slot::A);
        assert_eq!(record.pending(), Some(Slot::B));
    }

    #[test]
    fn tamper_or_write_failure_never_publishes_target_slot() {
        let (mut disk, layout, mut payload, offer, key) = fixture();
        payload[20_000] ^= 1;
        assert_eq!(install(&mut disk, &mut Bytes(payload), layout, Slot::A, 1, &offer, &[key]), Err(InstallError::ArtifactChecksum));
        let mut state = StateRecords { disk: &mut disk, first_lba: layout.state.first_lba };
        assert_eq!(storage::load(&mut state).unwrap().record.pending(), None);

        let (mut disk, layout, payload, offer, key) = fixture();
        disk.fail_write = true;
        assert_eq!(install(&mut disk, &mut Bytes(payload), layout, Slot::A, 1, &offer, &[key]), Err(InstallError::Disk("write")));
        disk.fail_write = false;
        let mut state = StateRecords { disk: &mut disk, first_lba: layout.state.first_lba };
        assert_eq!(storage::load(&mut state).unwrap().record.pending(), None);
    }
}
