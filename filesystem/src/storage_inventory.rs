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
    physical_disks: BTreeMap<u64, crate::storage_reservation::Disk>,
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
) -> (
    Vec<Item>,
    BTreeMap<Backing, u64>,
    u32,
    BTreeMap<u64, crate::storage_reservation::Disk>,
) {
    let mut observed = BTreeMap::new();
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
            Ok((
                disk_item,
                d.values[2],
                key,
                crate::storage_reservation::Disk {
                    device: disk,
                    guid: [d.values[0], d.values[1]],
                    capacity,
                    sector_bytes: d.values[3] as u32,
                    partitions: Vec::new(),
                },
            ))
        })();
        let (disk_item, sectors, key, mut observed_disk) = match inspected {
            Ok(v) => v,
            Err(e) => {
                warning = e as u32;
                continue;
            }
        };
        let disk_id = disk_item.id;
        let sector_bytes = u64::from(disk_item.sector_bytes);
        items.push(disk_item.clone());
        if observed_disk.guid == [0;2] { observed.insert(disk_id,observed_disk); continue; }
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
                entries.push((
                    start,
                    count,
                    identity(wire::PARTITION, &part_key),
                    ordinal,
                    guids.values,
                ));
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
        if entries.iter().any(|(start, count, _, _, _)| {
            let invalid = *start < previous;
            previous = start + count;
            invalid
        }) {
            warning = 5;
            continue;
        }
        let mut position = 0;
        for (start, count, id, ordinal, guids) in &entries {
            observed_disk.partitions.push((*guids, *start, *count));
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
        observed.insert(disk_id, observed_disk);
        // GPT's usable range is not exposed by the driver. Label gaps honestly:
        // they can include partition-table metadata and are not writable claims.
        if !entries.is_empty() && position < sectors {
            items.push(outside(&disk_item, position, sectors - position));
        }
    }
    (items, partitions, warning, observed)
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
    pub fn storage_epoch_request(
        &mut self,
        h: provider::RequestHeader,
        payload: &[u8],
        attachments: u32,
    ) -> Result<(u64, Vec<u8>), i32> {
        if h.opcode != provider::OP_QUERY
            || h.basis != mochios_filesystem_protocol::storage_region::EPOCH
            || h.argument != 0
            || h.length != 8
            || h.data_length != 16
            || payload.len() != 16
            || attachments != 0
        {
            return Err(22);
        }
        let open = self.opens.get(&h.object_id).ok_or(9)?;
        if open.volume != 0 || open.inode.index.get() != 2 || !open.inode.file_type().is_dir() {
            return Err(13);
        }
        let generation = u64::from_le_bytes(payload[..8].try_into().map_err(|_| 22)?);
        let disk = u64::from_le_bytes(payload[8..].try_into().map_err(|_| 22)?);
        let selected = self.selected_storage(generation, disk)?;
        #[cfg(not(target_os = "mochios"))]
        {
            let _ = selected;
            Err(95)
        }
        #[cfg(target_os = "mochios")]
        {
            let identity = mochi_user_platform::storage::control(mnu_abi::StorageControlRequest {
                operation: mnu_abi::STORAGE_CONTROL_INSPECT,
                device_id: selected.device,
                arguments: [mnu_abi::STORAGE_QUERY_DEVICE_IDENTITY, 0, 0, 0],
                reserved0: 0,
            })
            .map_err(|_| 5)?;
            if identity.status != 0
                || identity.values[0] == 0
                || identity.values[3] != 0
                || identity.values[2] != 512
                || identity.values[1].checked_mul(512) != Some(selected.capacity)
            {
                return Err(116);
            }
            Ok((8, identity.values[0].to_le_bytes().to_vec()))
        }
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
    pub(crate) fn refresh_storage_inventory(&mut self) -> Result<(), i32> {
        #[cfg(target_os = "mochios")]
        let (mut items, mut partitions, mut warning, observed) =
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
        let (mut items, partitions, mut warning, observed) = physical(|_, _, _| Err(95));
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
        self.storage_inventory.physical_disks = observed;
        self.storage_inventory.warning = warning;
        self.storage_inventory.created = Some(Instant::now());
        Ok(())
    }
}

impl FilesystemService {
    pub(crate) fn selected_storage(&self, generation:u64, disk:u64)->Result<crate::storage_reservation::Disk,i32> {
        if generation!=self.storage_inventory.generation {return Err(11)}
        self.reservable_disk(disk)
    }
    pub(crate) fn reservable_disk(&self, disk: u64) -> Result<crate::storage_reservation::Disk, i32> {
        let state = &self.storage_inventory;
        let mounted = self
            .namespace
            .as_ref()
            .map_or(1, |namespace| namespace.filesystem_volume_count());
        if mounted != state.mounts.len() {
            return Err(16);
        }
        if state.warning != 0 || state.created.is_none() {
            return Err(11);
        }
        let observed = state.physical_disks.get(&disk).ok_or(95)?;
        let records = state
            .records
            .iter()
            .map(|bytes| wire::Record::decode(bytes).ok_or(5))
            .collect::<Result<Vec<_>, _>>()?;
        let target = records
            .iter()
            .find(|r| r.kind == wire::DISK && r.id == disk)
            .ok_or(116)?;
        if target.flags & wire::READ_ONLY != 0 {
            return Err(30);
        }
        if target.flags & wire::ACCESS_KNOWN == 0
            || target.flags & wire::CAPACITY_FROM_PARTITION_MAP != 0
        {
            return Err(95);
        }
        if target.capacity != observed.capacity || target.sector_bytes != observed.sector_bytes {
            return Err(116);
        }
        // An unknown mount cannot establish that any physical target is safe.
        if !records
            .iter()
            .any(|r| r.kind == wire::VOLUME && r.mount == "/")
        {
            return Err(16);
        }
        for volume in records.iter().filter(|r| r.kind == wire::VOLUME) {
            let mut parent = volume.parent;
            let mut seen = BTreeSet::new();
            loop {
                if !seen.insert(parent) {
                    return Err(16);
                }
                let node = records.iter().find(|r| r.id == parent).ok_or(16)?;
                if node.kind == wire::DISK {
                    if node.id == disk {
                        return Err(16);
                    }
                    break;
                }
                parent = node.parent;
            }
        }
        Ok(observed.clone())
    }

    /// Called only after authenticated admission; never reachable via a numeric
    /// filesystem open/close message. This does not authorize block writes.
    pub fn reserve_storage(
        &mut self,
        admitted: crate::storage_reservation::Admission,
    ) -> Result<u64, i32> {
        self.reserve_storage_with_refresh(admitted.into_request(), |owner| {
            owner.refresh_storage_inventory()
        })
    }

    fn reserve_storage_with_refresh(
        &mut self,
        request: mochios_filesystem_protocol::storage_reservation::Request,
        refresh: impl FnOnce(&mut Self) -> Result<(), i32>,
    ) -> Result<u64, i32> {
        if request.generation != self.storage_inventory.generation {
            return Err(11);
        }
        let previous = self.reservable_disk(request.disk)?;
        refresh(self)?;
        let current = self.reservable_disk(request.disk)?;
        if previous != current {
            return Err(116);
        }
        self.retain_storage_reservation(request.disk, current)
    }

    pub(crate) fn retain_storage_reservation(
        &mut self,
        disk: u64,
        observed: crate::storage_reservation::Disk,
    ) -> Result<u64, i32> {
        let object = self.next_open_id;
        if object > i64::MAX as u64 {
            return Err(75);
        }
        let next = object.checked_add(1).ok_or(75)?;
        self.storage_reservations.acquire(object, disk, observed)?;
        self.next_open_id = next;
        Ok(object)
    }

    pub fn is_storage_reservation(&self, object: u64) -> bool {
        self.storage_reservations.contains(object)
    }

    pub fn validate_storage_reservation(
        &mut self,
        header: provider::RequestHeader,
        payload: &[u8],
        attachments: u32,
    ) -> Result<(u64, Vec<u8>), i32> {
        use mochios_filesystem_protocol::storage_reservation as reservation;
        if !matches!(header.opcode, provider::OP_QUERY | provider::OP_CONTROL)
            || header.basis != reservation::VALIDATE
        {
            return Err(95);
        }
        if !payload.is_empty()
            || header.data_length != 0
            || header.length != 8
            || header.argument != 0
            || attachments != 0
        {
            return Err(22);
        }
        let disk = self.storage_reservations.target(header.object_id)?;
        let current = self
            .refresh_storage_inventory()
            .and_then(|_| self.reservable_disk(disk));
        let id = self
            .storage_reservations
            .validate(header.object_id, current)?;
        Ok((8, id.to_le_bytes().to_vec()))
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
        let (items, parents, warning, _) = physical(|op, disk, args| {
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
        let (unavailable, _, warning, _) = physical(|_, _, _| Err(13));
        assert!(unavailable.is_empty());
        assert_eq!(warning, 13);
    }
    #[test]
    fn malformed_or_overlapping_partitions_never_become_free_space() {
        let (items, parents, warning, _) = physical(|op, disk, args| {
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
    fn reservation_fixture() -> FilesystemService {
        let dir = std::env::temp_dir().join(format!(
            "mochios-reservation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("volume.ext4");
        let result = std::process::Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-F"])
            .arg(&path)
            .arg("4096")
            .output()
            .unwrap();
        assert!(result.status.success());
        let image = std::fs::read(&path).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        let mut service = FilesystemService::new(Ext4::load(Box::new(image)).unwrap());
        let item = |kind, id, parent, mount: &str| Item {
            kind,
            id,
            parent,
            capacity: 51200,
            used: 0,
            flags: wire::ACCESS_KNOWN,
            start: 0,
            sector_bytes: 512,
            name: "Test".into(),
            format: if kind == wire::DISK {
                "GPT".into()
            } else {
                "".into()
            },
            mount: mount.into(),
        };
        service.storage_inventory.records = [
            item(wire::DISK, 1, 0, ""),
            item(wire::PARTITION, 2, 1, ""),
            item(wire::VOLUME, 3, 2, "/"),
            item(wire::DISK, 4, 0, ""),
            item(wire::PARTITION, 5, 4, ""),
        ]
        .into_iter()
        .map(|i| i.record(1, 0).encode().unwrap())
        .collect();
        service.storage_inventory.mounts.push(Mount {
            path: "/".into(),
            filesystem: service.fs.clone(),
            backing: (0, 0, 100),
        });
        service.storage_inventory.created = Some(Instant::now());
        service.storage_inventory.generation = 1;
        for id in [1, 4] {
            service.storage_inventory.physical_disks.insert(
                id,
                crate::storage_reservation::Disk {
                    device: id as u32,
                    guid: [id, id],
                    capacity: 51200,
                    sector_bytes: 512,
                    partitions: vec![([11, 12, id, id], 0, 100)],
                },
            );
        }
        service
    }

    #[test]
    fn reservation_rejects_mounted_unknown_readonly_and_partial_inventory() {
        let service = reservation_fixture();
        assert_eq!(service.reservable_disk(1), Err(16));
        assert!(service.reservable_disk(4).is_ok());
        assert!(service.reservable_disk(999).is_err());
        for mode in 0..5 {
            let mut service = reservation_fixture();
            let mut record = wire::Record::decode(
                &service.storage_inventory.records[if mode < 2 { 3 } else { 2 }],
            )
            .unwrap();
            match mode {
                0 => record.flags |= wire::READ_ONLY,
                1 => record.flags = 0,
                2 => record.parent = 0,
                3 => record.parent = 999,
                _ => service.storage_inventory.warning = 5,
            }
            let index = if mode < 2 { 3 } else { 2 };
            service.storage_inventory.records[index] = record.encode().unwrap();
            assert!(service.reservable_disk(4).is_err());
        }
    }

    #[test]
    fn acquire_rechecks_observations_before_publishing_any_reservation() {
        use mochios_filesystem_protocol::storage_reservation::Request;
        let request = Request {
            generation: 1,
            disk: 4,
        };
        let mut service = reservation_fixture();
        assert_eq!(
            service.reserve_storage_with_refresh(
                Request {
                    generation: 9,
                    ..request
                },
                |_| panic!("stale selection")
            ),
            Err(11)
        );
        assert_eq!(
            service.reserve_storage_with_refresh(request, |s| {
                s.storage_inventory.physical_disks.get_mut(&4).unwrap().guid[0] += 1;
                Ok(())
            }),
            Err(116)
        );
        assert!(service.storage_reservations.is_empty());
        let mut service = reservation_fixture();
        let object = service
            .reserve_storage_with_refresh(request, |_| Ok(()))
            .unwrap();
        assert!(service.is_storage_reservation(object));
        assert_eq!(
            service.reserve_storage_with_refresh(request, |_| Ok(())),
            Err(16)
        );
        assert_eq!(service.mount_volume(b"/", service.fs.clone()), Err(16));
        assert_eq!(
            service.mount_named_volume(b"/", b"temporary", service.fs.clone(), b"/"),
            Err(16)
        );
        service.provider_close(object).unwrap();
        assert!(service.storage_reservations.is_empty());
        assert!(
            service
                .reserve_storage_with_refresh(request, |_| Ok(()))
                .is_ok()
        );
    }

    #[test]
    fn reservation_objects_cannot_be_used_as_files_or_raw_io_controls() {
        let mut service = reservation_fixture();
        let observed = service.reservable_disk(4).unwrap();
        let object = service.retain_storage_reservation(4, observed).unwrap();
        let header = provider::RequestHeader {
            opcode: provider::OP_WRITE_AT,
            object_id: object,
            argument: 0,
            basis: 0,
            length: 0,
            data_length: 0,
        };
        assert_eq!(
            service.validate_storage_reservation(header, &[], 0),
            Err(95)
        );
        let header = provider::RequestHeader {
            opcode: provider::OP_QUERY,
            basis: mochios_filesystem_protocol::storage_reservation::VALIDATE,
            length: 8,
            ..header
        };
        assert_eq!(
            service.validate_storage_reservation(header, &[], 1),
            Err(22)
        );
        assert!(
            service
                .provider_write_at(object, 0, b"unauthorized")
                .is_err()
        );
        let closed = service.handle(
            mochios_filesystem_protocol::Header {
                opcode: mochios_filesystem_protocol::OP_CLOSE,
                open_id: object,
                ..Default::default()
            },
            &[],
        );
        assert!(closed.header.status < 0);
        assert!(service.is_storage_reservation(object));
        // Host discovery cannot prove physical identity. It must revoke, not
        // silently preserve the fabricated fixture as a native disk.
        assert_eq!(
            service.validate_storage_reservation(header, &[], 0),
            Err(116)
        );
        assert_eq!(service.storage_reservations.target(object), Err(116));
    }

    #[test]
    fn untracked_mounts_block_reservation_instead_of_implying_an_idle_disk() {
        let mut service = reservation_fixture();
        service.storage_inventory.mounts.clear();
        assert_eq!(service.reservable_disk(4), Err(16));
    }
}
