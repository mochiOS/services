//! Root-Handle-only storage observations. Never accepts data I/O or mutations.
use super::FilesystemService;
use ext4plus::Ext4;
use mnu_abi::{StorageControlResponse, provider};
use mochios_filesystem_protocol::storage_inventory as wire;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

type Backing = (u32, u64, u64);
pub(super) struct Mount {
    path: String,
    filesystem: Ext4,
    backing: Backing,
}
#[derive(Default)]
pub(super) struct State {
    mounts: Vec<Mount>,
    generation: u64,
    records: Vec<[u8; wire::RECORD_LEN]>,
    warning: u32,
    created: Option<Instant>,
}
#[derive(Clone)]
struct Item {
    kind: u8,
    id: u64,
    parent: u64,
    capacity: u64,
    used: u64,
    flags: u32,
    start: u64,
    sector_bytes: u32,
    name: String,
    format: String,
    mount: String,
}
impl Item {
    fn record(&self, generation: u64, warning: u32) -> wire::Record<'_> {
        wire::Record {
            generation,
            warning,
            kind: self.kind,
            id: self.id,
            parent: self.parent,
            capacity: self.capacity,
            used: self.used,
            flags: self.flags,
            start: self.start,
            sector_bytes: self.sector_bytes,
            name: &self.name,
            format: &self.format,
            mount: &self.mount,
        }
    }
}
fn identity(kind: u8, bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0xcbf29ce484222325u64 ^ kind as u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
        })
        .max(1)
}
fn control_value(response: StorageControlResponse) -> Result<StorageControlResponse, i32> {
    if response.status == mnu_abi::STORAGE_STATUS_OK {
        Ok(response)
    } else {
        Err(5)
    }
}
fn physical(
    mut control: impl FnMut(u16, u32, [u64; 4]) -> Result<StorageControlResponse, i32>,
) -> (Vec<Item>, BTreeMap<Backing, u64>, u32) {
    let mut items = vec![];
    let mut partitions = BTreeMap::new();
    let mut warning = 0;
    let mut devices = BTreeSet::new();
    for index in 0..=16 {
        let listed = match control(mnu_abi::STORAGE_CONTROL_LIST_DEVICE, 0, [index, 0, 0, 0]) {
            Ok(r) => r,
            Err(e) => {
                warning = e.unsigned_abs();
                break;
            }
        };
        if listed.status == mnu_abi::STORAGE_STATUS_END {
            break;
        }
        if index == 16 || listed.status != 0 || !devices.insert(listed.device_id) {
            warning = 5;
            break;
        }
        let disk = listed.device_id;
        let inspected = (|| -> Result<_, i32> {
            let d = control_value(control(
                mnu_abi::STORAGE_CONTROL_INSPECT,
                disk,
                [mnu_abi::STORAGE_QUERY_DISK, 0, 0, 0],
            )?)?;
            if d.values[2] == 0
                || d.values[3] < 512
                || !d.values[3].is_power_of_two()
                || d.values[3] > u32::MAX as u64
            {
                return Err(5);
            }
            let capacity = d.values[2].checked_mul(d.values[3]).ok_or(75)?;
            let mut guid = [0; 16];
            guid[..8].copy_from_slice(&d.values[0].to_le_bytes());
            guid[8..].copy_from_slice(&d.values[1].to_le_bytes());
            // A missing disk GUID must not alias every other unpartitioned disk.
            let key = if guid == [0; 16] {
                disk.to_le_bytes().to_vec()
            } else {
                guid.to_vec()
            };
            let id = identity(wire::DISK, &key);
            let flags = if listed.values[0] & (1 << 4) != 0 {
                wire::ACCESS_KNOWN | wire::READ_ONLY
            } else if listed.values[0] & (1 << 9) != 0 {
                wire::ACCESS_KNOWN
            } else {
                0
            };
            let disk_item = Item {
                kind: wire::DISK,
                id,
                parent: 0,
                capacity,
                used: 0,
                flags,
                start: 0,
                sector_bytes: d.values[3] as u32,
                name: format!("Disk {disk}"),
                format: if guid == [0; 16] { "" } else { "GPT" }.into(),
                mount: String::new(),
            };
            Ok((disk_item, d.values[2], key))
        })();
        let (disk_item, sectors, key) = match inspected {
            Ok(v) => v,
            Err(e) => {
                warning = e as u32;
                continue;
            }
        };
        let disk_id = disk_item.id;
        let sector_bytes = u64::from(disk_item.sector_bytes);
        items.push(disk_item.clone());
        let table = (|| -> Result<_, i32> {
            let mut entries = vec![];
            for ordinal in 0..=128 {
                let guids = control(
                    mnu_abi::STORAGE_CONTROL_INSPECT,
                    disk,
                    [mnu_abi::STORAGE_QUERY_PARTITION_GUIDS, ordinal, 0, 0],
                )?;
                if guids.status == mnu_abi::STORAGE_STATUS_END {
                    return Ok(entries);
                }
                if ordinal == 128 || guids.status != 0 {
                    return Err(5);
                }
                let range = control_value(control(
                    mnu_abi::STORAGE_CONTROL_INSPECT,
                    disk,
                    [mnu_abi::STORAGE_QUERY_PARTITION_RANGE, ordinal, 0, 0],
                )?)?;
                let start = range.values[0];
                let count = range.values[1];
                if count == 0 || start.checked_add(count).is_none_or(|end| end > sectors) {
                    return Err(5);
                }
                let mut part_key = key.clone();
                part_key.extend_from_slice(&guids.values[2].to_le_bytes());
                part_key.extend_from_slice(&guids.values[3].to_le_bytes());
                if guids.values[2..] == [0, 0] {
                    part_key.extend_from_slice(&start.to_le_bytes());
                }
                entries.push((start, count, identity(wire::PARTITION, &part_key), ordinal));
            }
            Err(5)
        })();
        let mut entries = match table {
            Ok(v) => v,
            Err(e) => {
                warning = e.unsigned_abs();
                continue;
            }
        };
        entries.sort_by_key(|entry| entry.0);
        let mut previous = 0;
        if entries.iter().any(|(start, count, _, _)| {
            let invalid = *start < previous;
            previous = start + count;
            invalid
        }) {
            warning = 5;
            continue;
        }
        let mut position = 0;
        for (start, count, id, ordinal) in &entries {
            if *start > position {
                items.push(outside(&disk_item, position, *start - position));
            }
            items.push(Item {
                kind: wire::PARTITION,
                id: *id,
                parent: disk_id,
                capacity: count * sector_bytes,
                used: 0,
                flags: disk_item.flags,
                start: *start,
                sector_bytes: disk_item.sector_bytes,
                name: format!("Partition {}", ordinal + 1),
                format: String::new(),
                mount: String::new(),
            });
            partitions.insert((disk, *start, *count), *id);
            position = start + count;
        }
        // GPT's usable range is not exposed by the driver. Label gaps honestly:
        // they can include partition-table metadata and are not writable claims.
        if !entries.is_empty() && position < sectors {
            items.push(outside(&disk_item, position, sectors - position));
        }
    }
    (items, partitions, warning)
}
fn outside(disk: &Item, start: u64, count: u64) -> Item {
    let mut key = disk.id.to_le_bytes().to_vec();
    key.extend_from_slice(&start.to_le_bytes());
    Item {
        kind: wire::OUTSIDE_PARTITIONS,
        id: identity(wire::OUTSIDE_PARTITIONS, &key),
        parent: disk.id,
        capacity: count * u64::from(disk.sector_bytes),
        used: 0,
        flags: 0,
        start,
        sector_bytes: disk.sector_bytes,
        name: "Outside partitions".into(),
        format: String::new(),
        mount: String::new(),
    }
}
#[cfg(target_os = "mochios")]
fn mounted_disk(disk_id: u32) -> Result<(Vec<Item>, BTreeMap<Backing, u64>), i32> {
    let table = crate::partition::inspect(&mut crate::platform_storage::MochiDisk::new(disk_id))
        .map_err(|_| 5)?;
    let disk = Item {
        kind: wire::DISK,
        id: identity(wire::DISK, &table.guid),
        parent: 0,
        capacity: table.sectors * 512,
        used: 0,
        flags: wire::CAPACITY_FROM_PARTITION_MAP,
        start: 0,
        sector_bytes: 512,
        name: format!("Disk {disk_id}"),
        format: "GPT".into(),
        mount: String::new(),
    };
    let mut items = vec![disk.clone()];
    let mut parents = BTreeMap::new();
    let mut position = 0;
    for (ordinal, part) in table.partitions.into_iter().enumerate() {
        let mut key = table.guid.to_vec();
        key.extend_from_slice(&part.guid);
        let id = identity(wire::PARTITION, &key);
        let start = part.range.first_lba;
        let count = part.range.sector_count;
        if start > position {
            items.push(outside(&disk, position, start - position));
        }
        let mut name = if part.name.is_empty() {
            format!("Partition {}", ordinal + 1)
        } else {
            part.name
        };
        while name.len() > 64 {
            name.pop();
        }
        items.push(Item {
            kind: wire::PARTITION,
            id,
            parent: disk.id,
            capacity: count * 512,
            used: 0,
            flags: 0,
            start,
            sector_bytes: 512,
            name,
            format: String::new(),
            mount: String::new(),
        });
        parents.insert((disk_id, start, count), id);
        position = start + count;
    }
    if position > 0 && position < table.sectors {
        items.push(outside(&disk, position, table.sectors - position));
    }
    Ok((items, parents))
}
impl FilesystemService {
    /// Startup-owned mount metadata; callers cannot register arbitrary disk IDs.
    pub fn record_storage_mount(
        &mut self,
        path: &str,
        filesystem: Ext4,
        disk: u32,
        start: u64,
        sectors: u64,
    ) -> Result<(), i32> {
        if self.next_open_id != 1
            || path.len() > 160
            || !path.starts_with('/')
            || path.contains('\0')
            || sectors == 0
            || self.storage_inventory.mounts.iter().any(|m| m.path == path)
        {
            return Err(22);
        }
        self.storage_inventory.mounts.push(Mount {
            path: path.into(),
            filesystem,
            backing: (disk, start, sectors),
        });
        Ok(())
    }
    pub fn storage_inventory_request(
        &mut self,
        header: provider::RequestHeader,
        payload: &[u8],
        attachments: u32,
    ) -> Result<(u64, Vec<u8>), i32> {
        if header.opcode != provider::OP_QUERY
            || header.basis != wire::GET
            || header.argument != 0
            || header.length != wire::RECORD_LEN as u32
            || header.data_length as usize != payload.len()
            || attachments != 0
        {
            return Err(22);
        }
        let request = wire::Request::decode(payload).ok_or(22)?;
        let open = self.opens.get(&header.object_id).ok_or(9)?;
        if open.volume != 0 || open.inode.index.get() != 2 || !open.inode.file_type().is_dir() {
            return Err(13);
        }
        if request.generation == 0
            && self
                .storage_inventory
                .created
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(2))
        {
            self.refresh_storage_inventory()?;
        }
        let state = &self.storage_inventory;
        if request.generation != 0 && request.generation != state.generation {
            return Err(11);
        }
        let bytes = match state.records.get(request.index as usize) {
            Some(bytes) => *bytes,
            None => wire::Record::end(state.generation, state.warning)
                .encode()
                .ok_or(5)?,
        };
        Ok((bytes.len() as u64, bytes.to_vec()))
    }
    fn refresh_storage_inventory(&mut self) -> Result<(), i32> {
        #[cfg(target_os = "mochios")]
        let (mut items, mut partitions, mut warning) =
            physical(|operation, device_id, arguments| {
                mochi_user_platform::storage::control(mnu_abi::StorageControlRequest {
                    operation,
                    device_id,
                    arguments,
                    reserved0: 0,
                })
                .map_err(|_| 5)
            });
        #[cfg(not(target_os = "mochios"))]
        let (mut items, partitions, mut warning) = physical(|_, _, _| Err(95));
        // The active legacy block session can reject mDriver inspection. The
        // owner may still read the validated GPT of disks it already mounted.
        // No guessed device IDs or probes of arbitrary raw disks are used.
        #[cfg(target_os = "mochios")]
        for disk in self
            .storage_inventory
            .mounts
            .iter()
            .map(|m| m.backing.0)
            .collect::<BTreeSet<_>>()
        {
            if partitions.keys().any(|backing| backing.0 == disk) {
                continue;
            }
            if let Ok((fallback, parents)) = mounted_disk(disk) {
                for item in fallback {
                    if !items.iter().any(|existing| existing.id == item.id) {
                        items.push(item);
                    }
                }
                partitions.extend(parents);
            }
        }
        for (volume, mount) in self.storage_inventory.mounts.iter().enumerate() {
            let status =
                match crate::volume_status::filesystem_status(&mount.filesystem, volume as u32) {
                    Ok(s) => s,
                    Err(e) => {
                        warning = e as u32;
                        continue;
                    }
                };
            let Some(capacity) = status.blocks.checked_mul(u64::from(status.block_bytes)) else {
                warning = 75;
                continue;
            };
            let Some(free) = status
                .free_blocks
                .checked_mul(u64::from(status.block_bytes))
            else {
                warning = 75;
                continue;
            };
            items.push(Item {
                kind: wire::VOLUME,
                id: identity(wire::VOLUME, mount.path.as_bytes()),
                parent: partitions.get(&mount.backing).copied().unwrap_or(0),
                capacity,
                used: capacity - free,
                flags: wire::USAGE_KNOWN
                    | wire::ACCESS_KNOWN
                    | if status.flags & 1 != 0 {
                        wire::READ_ONLY
                    } else {
                        0
                    },
                start: mount.backing.1,
                sector_bytes: 0,
                name: if mount.path == "/" {
                    "Data".into()
                } else {
                    mount.path.rsplit('/').next().unwrap_or("Volume").into()
                },
                format: "ext4".into(),
                mount: mount.path.clone(),
            });
        }
        if items.len() > wire::MAX_RECORDS {
            return Err(75);
        }
        let generation = self.storage_inventory.generation.checked_add(1).ok_or(75)?;
        let mut identities = BTreeSet::new();
        let records = items
            .iter()
            .map(|item| {
                if !identities.insert(item.id) {
                    return Err(5);
                }
                item.record(generation, warning).encode().ok_or(5)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.storage_inventory.generation = generation;
        self.storage_inventory.records = records;
        self.storage_inventory.warning = warning;
        self.storage_inventory.created = Some(Instant::now());
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn response(device_id: u32, values: [u64; 4]) -> StorageControlResponse {
        StorageControlResponse {
            device_id,
            status: 0,
            values,
        }
    }
    #[test]
    fn ranges_gaps_and_backing_identity_are_checked() {
        let (items, parents, warning) = physical(|op, disk, args| {
            Ok(match (op, args[0], args[1]) {
                (0, 0, _) => response(7, [1 << 9, 0, 0, 0]),
                (0, _, _) => StorageControlResponse {
                    status: 6,
                    ..Default::default()
                },
                (1, 0, _) => response(disk, [1, 2, 100, 512]),
                (1, 1, 0) => response(disk, [0, 0, 3, 4]),
                (1, 1, _) => StorageControlResponse {
                    status: 6,
                    ..Default::default()
                },
                (1, 2, 0) => response(disk, [10, 80, 0, 0]),
                _ => unreachable!(),
            })
        });
        assert_eq!(warning, 0);
        assert_eq!(
            items
                .iter()
                .filter(|i| i.parent == items[0].id)
                .map(|i| i.capacity)
                .sum::<u64>(),
            51200
        );
        assert_eq!(parents.len(), 1);
        assert!(parents.contains_key(&(7, 10, 80)));
        let (unavailable, _, warning) = physical(|_, _, _| Err(13));
        assert!(unavailable.is_empty());
        assert_eq!(warning, 13);
    }
    #[test]
    fn malformed_or_overlapping_partitions_never_become_free_space() {
        let (items, parents, warning) = physical(|op, disk, args| {
            Ok(match (op, args[0], args[1]) {
                (0, 0, _) => response(7, [0; 4]),
                (0, _, _) => StorageControlResponse {
                    status: 6,
                    ..Default::default()
                },
                (1, 0, _) => response(disk, [1, 2, 100, 512]),
                (1, 1, 0..=1) => response(disk, [0, 0, args[1] + 3, 4]),
                (1, 1, _) => StorageControlResponse {
                    status: 6,
                    ..Default::default()
                },
                (1, 2, _) => response(disk, [10, 80, 0, 0]),
                _ => unreachable!(),
            })
        });
        assert_eq!(items.len(), 1);
        assert!(parents.is_empty());
        assert_ne!(warning, 0);
    }
    #[test]
    fn root_handle_pagination_is_read_only_and_retains_live_volume_accounting() {
        use super::super::PathAnchors;
        use mochios_filesystem_protocol as fswire;
        let dir = std::env::temp_dir().join(format!(
            "mochios-inventory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("source/child")).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let image = dir.join("volume.ext4");
        let output = std::process::Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-F", "-d"])
            .arg(dir.join("source"))
            .arg(&image)
            .arg("16384")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let filesystem = Ext4::load(Box::new(std::fs::read(&image).unwrap())).unwrap();
        let mut service = FilesystemService::new(filesystem.clone());
        service
            .record_storage_mount("/", filesystem, 0, 2048, 32768)
            .unwrap();
        let mut credentials = [0; fswire::CREDENTIALS_MAX_LEN];
        let len = fswire::encode_credentials_payload(0, 0, &[], &[], &mut credentials).unwrap();
        let credentials = fswire::decode_credentials_payload(&credentials[..len])
            .unwrap()
            .0;
        let open = |service: &mut FilesystemService, path: &[u8]| {
            service
                .open_at(
                    fswire::Header {
                        opcode: fswire::OP_OPEN_AT,
                        flags: fswire::OPEN_AT_READ | fswire::OPEN_AT_DIRECTORY,
                        ..Default::default()
                    },
                    path,
                    PathAnchors::default(),
                    credentials,
                )
                .unwrap()
                .header
                .open_id
        };
        let root = open(&mut service, b"/");
        let child = open(&mut service, b"/child");
        let header = provider::RequestHeader {
            opcode: provider::OP_QUERY,
            object_id: root,
            argument: 0,
            basis: wire::GET,
            length: wire::RECORD_LEN as u32,
            data_length: 16,
        };
        let request = wire::Request {
            generation: 0,
            index: 0,
        }
        .encode();
        assert_eq!(
            service.storage_inventory_request(
                provider::RequestHeader {
                    object_id: child,
                    ..header
                },
                &request,
                0
            ),
            Err(13)
        );
        assert_eq!(
            service.storage_inventory_request(
                provider::RequestHeader {
                    object_id: u64::MAX,
                    ..header
                },
                &request,
                0
            ),
            Err(9)
        );
        assert_eq!(
            service.storage_inventory_request(
                provider::RequestHeader {
                    opcode: provider::OP_CONTROL,
                    ..header
                },
                &request,
                0
            ),
            Err(22)
        );
        assert_eq!(
            service.storage_inventory_request(header, &request, 1),
            Err(22)
        );
        let (_, bytes) = service
            .storage_inventory_request(header, &request, 0)
            .unwrap();
        let record = wire::Record::decode(&bytes).unwrap();
        assert_eq!(record.kind, wire::VOLUME);
        assert_eq!(record.mount, "/");
        assert!(record.capacity > 0 && record.used > 0 && record.used < record.capacity);
        assert_eq!(
            record.flags & (wire::ACCESS_KNOWN | wire::READ_ONLY),
            wire::ACCESS_KNOWN | wire::READ_ONLY
        );
        let (_, end) = service
            .storage_inventory_request(
                header,
                &wire::Request {
                    generation: record.generation,
                    index: 1,
                }
                .encode(),
                0,
            )
            .unwrap();
        assert_eq!(wire::Record::decode(&end).unwrap().kind, 0);
        assert_eq!(
            service.storage_inventory_request(
                header,
                &wire::Request {
                    generation: record.generation + 1,
                    index: 1
                }
                .encode(),
                0
            ),
            Err(11)
        );
    }
}
