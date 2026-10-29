//! Provider-owned reservation state, separate from file/directory authority.
//! No numeric reservation ID or client-supplied permission is an IPC authority.
use mnu_abi::{HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_READ, HANDLE_RIGHT_TRANSFER};
use std::collections::HashMap;

pub const RIGHTS: u64 = HANDLE_RIGHT_READ | HANDLE_RIGHT_CONTROL | HANDLE_RIGHT_TRANSFER;
const MAX_RESERVATIONS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Disk {
    pub device: u32,
    pub guid: [u64; 2],
    pub capacity: u64,
    pub sector_bytes: u32,
    // Full type/unique GUIDs and geometry, not only inventory hashes.
    pub partitions: Vec<([u64; 4], u64, u64)>,
}
#[derive(Clone)]
struct Reservation {
    disk: u64,
    observed: Disk,
    revoked: bool,
}
#[derive(Default)]
pub(super) struct Reservations(HashMap<u64, Reservation>);
impl Reservations {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn contains(&self, object: u64) -> bool {
        self.0.contains_key(&object)
    }
    pub fn acquire(&mut self, object: u64, disk: u64, observed: Disk) -> Result<(), i32> {
        if object == 0 || self.contains(object) {
            return Err(22);
        }
        if self.0.len() >= MAX_RESERVATIONS
            || self.0.values().any(|r| {
                r.disk == disk
                    || r.observed.device == observed.device
                    || r.observed.guid == observed.guid
            })
        {
            return Err(16);
        }
        self.0.try_reserve(1).map_err(|_| 12)?;
        self.0.insert(
            object,
            Reservation {
                disk,
                observed,
                revoked: false,
            },
        );
        Ok(())
    }
    pub fn target(&self, object: u64) -> Result<u64, i32> {
        self.0
            .get(&object)
            .filter(|r| !r.revoked)
            .map(|r| r.disk)
            .ok_or(116)
    }
    pub fn validate(&mut self, object: u64, current: Result<Disk, i32>) -> Result<u64, i32> {
        let reservation = self.0.get_mut(&object).ok_or(9)?;
        if reservation.revoked {
            return Err(116);
        }
        match current {
            Ok(disk) if disk == reservation.observed => Ok(reservation.disk),
            _ => {
                reservation.revoked = true;
                Err(116)
            }
        }
    }
    pub fn release(&mut self, object: u64) -> bool {
        self.0.remove(&object).is_some()
    }
}

/// Created only by the authenticated admission adapter. Keep this distinct
/// from a decoded wire request so dispatch cannot accidentally skip admission.
#[derive(Debug, PartialEq, Eq)]
pub struct Admission {
    request: mochios_filesystem_protocol::storage_reservation::Request,
}
impl Admission {
    pub(crate) fn into_request(self) -> mochios_filesystem_protocol::storage_reservation::Request {
        self.request
    }
}

/// Admission executes on the owner thread. The native adapter supplies the
/// authenticated sender check; nothing in the request can claim capability.
pub fn admit(
    bytes: &[u8],
    attached: &mnu_abi::IpcObjectHandles,
    authorized: impl FnOnce() -> bool,
) -> Result<Admission, i32> {
    if !authorized() {
        return Err(13);
    }
    if attached.count != 0
        || !matches!(
            attached.delivery_flags,
            0 | mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
        )
    {
        return Err(13);
    }
    mochios_filesystem_protocol::storage_reservation::Request::decode(bytes)
        .map(|request| Admission { request })
        .ok_or(22)
}

/// Publishes only a restricted native provider reference. Creation failure
/// retires the unpublished reservation; post-publication release belongs to
/// the native object's final-reference notification, including lost replies.
pub fn publish(
    object: u64,
    mut create: impl FnMut(u64, u64) -> Result<u32, i32>,
    mut retire_unpublished: impl FnMut(u64),
) -> Result<mnu_abi::IpcObjectHandle, i32> {
    match create(object, RIGHTS) {
        Ok(handle) if handle != 0 => Ok(mnu_abi::IpcObjectHandle {
            handle,
            reserved: 0,
            rights: RIGHTS,
        }),
        result => {
            retire_unpublished(object);
            Err(result.err().unwrap_or(5))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn disk() -> Disk {
        Disk {
            device: 7,
            guid: [11, 12],
            capacity: 51200,
            sector_bytes: 512,
            partitions: vec![([1, 2, 3, 4], 10, 80)],
        }
    }
    #[test]
    fn admission_requires_real_authority_and_rejects_unexpected_object_delivery() {
        let request = mochios_filesystem_protocol::storage_reservation::Request {
            generation: 1,
            disk: 9,
        }
        .encode();
        let mut handles = mnu_abi::IpcObjectHandles::default();
        assert_eq!(admit(&request, &handles, || false), Err(13));
        assert_eq!(
            admit(b"claimed-device.storage", &handles, || false),
            Err(13)
        );
        assert!(admit(&request, &handles, || true).is_ok());
        handles.count = 1;
        assert_eq!(admit(&request, &handles, || true), Err(13));
        handles.count = 0;
        handles.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
        assert_eq!(admit(&request, &handles, || true), Err(13));
        handles.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
        assert!(admit(&request, &handles, || true).is_ok());
    }
    #[test]
    fn exclusive_reservations_reject_aliases_and_release_only_the_selected_object() {
        let mut owner = Reservations::default();
        owner.acquire(1, 9, disk()).unwrap();
        assert_eq!(owner.acquire(2, 9, disk()), Err(16));
        let mut alias = disk();
        alias.device = 8;
        assert_eq!(owner.acquire(2, 10, alias), Err(16));
        let mut alias = disk();
        alias.guid = [13, 14];
        assert_eq!(owner.acquire(2, 10, alias), Err(16));
        assert!(!owner.release(999));
        assert!(!owner.is_empty());
        assert!(owner.release(1));
        owner.acquire(2, 9, disk()).unwrap();
    }
    #[test]
    fn loss_or_identity_change_permanently_revokes_the_existing_reservation() {
        for mode in 0..7 {
            let mut owner = Reservations::default();
            owner.acquire(1, 9, disk()).unwrap();
            assert_eq!(owner.validate(1, Ok(disk())), Ok(9));
            let mut changed = disk();
            match mode {
                0 => changed.device += 1,
                1 => changed.guid[0] += 1,
                2 => changed.capacity += 512,
                3 => changed.sector_bytes *= 2,
                4 => changed.partitions[0].0[2] += 1,
                5 => changed.partitions[0].1 += 1,
                _ => {}
            }
            let observation = if mode == 6 { Err(16) } else { Ok(changed) };
            assert_eq!(owner.validate(1, observation), Err(116));
            assert_eq!(owner.validate(1, Ok(disk())), Err(116));
            assert_eq!(owner.target(1), Err(116));
        }
    }
    #[test]
    fn publication_returns_no_write_or_duplicate_right_and_cleans_only_unpublished_state() {
        let mut retired = vec![];
        for result in [Err(12), Ok(0)] {
            assert!(publish(4, |_, _| result, |id| retired.push(id)).is_err());
        }
        assert_eq!(retired, [4, 4]);
        let published = publish(
            4,
            |id, rights| {
                assert_eq!(id, 4);
                assert_eq!(
                    rights & (mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_DUPLICATE),
                    0
                );
                Ok(81)
            },
            |_| panic!("native publication must own retirement"),
        )
        .unwrap();
        assert_eq!(published.handle, 81);
        assert_eq!(published.rights, RIGHTS);
    }
    #[test]
    fn abandoned_reservations_cannot_exhaust_an_unbounded_owner_table() {
        let mut owner = Reservations::default();
        for id in 1..=MAX_RESERVATIONS as u64 {
            let mut observed = disk();
            observed.device = id as u32;
            observed.guid = [id, id];
            owner.acquire(id, id, observed).unwrap();
        }
        let mut observed = disk();
        observed.device = 99;
        observed.guid = [99, 99];
        assert_eq!(owner.acquire(99, 99, observed), Err(16));
    }
}
