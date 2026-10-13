use mochios_posix_client::named_semaphore::{Error, MappingOps, Mappings};
use std::collections::BTreeMap;

#[derive(Default)]
struct Backend {
    objects: BTreeMap<u32, u32>,
    mappings: BTreeMap<u64, u32>,
    closed: Vec<u32>,
    unmapped: Vec<u64>,
    fail_identity: bool,
    fail_map: bool,
    fail_unmap: bool,
}
impl MappingOps<u32> for Backend {
    type Error = i32;
    fn same_object(&mut self, left: u32, right: u32) -> Result<bool, i32> {
        if self.fail_identity {
            return Err(5);
        }
        Ok(self.objects[&left] == self.objects[&right])
    }
    fn map(&mut self, handle: u32) -> Result<u64, i32> {
        if self.fail_map {
            return Err(12);
        }
        let address = (handle as u64 + 1) * 4096;
        self.mappings.insert(address, self.objects[&handle]);
        Ok(address)
    }
    fn unmap(&mut self, address: u64) -> Result<(), i32> {
        if self.fail_unmap {
            return Err(14);
        }
        assert!(self.mappings.remove(&address).is_some());
        self.unmapped.push(address);
        Ok(())
    }
    fn close_handle(&mut self, handle: u32) {
        assert!(self.objects.remove(&handle).is_some());
        self.closed.push(handle);
    }
}

#[test]
fn repeated_opens_share_pointer_and_final_close_releases_exactly_once() {
    let mut mappings = Mappings::<u32, 2>::new();
    let mut backend = Backend::default();
    backend.objects.extend([(1, 100), (2, 100), (3, 100)]);
    let address = mappings.adopt(1, &mut backend).unwrap();
    assert_eq!(mappings.adopt(2, &mut backend), Ok(address));
    assert_eq!(mappings.adopt(3, &mut backend), Ok(address));
    assert_eq!(backend.closed, [2, 3]);
    assert_eq!(backend.mappings.len(), 1);
    for _ in 0..2 {
        mappings.close(address, &mut backend).unwrap();
        assert!(backend.unmapped.is_empty());
    }
    mappings.close(address, &mut backend).unwrap();
    assert_eq!(backend.unmapped, [address]);
    assert_eq!(backend.closed, [2, 3, 1]);
    assert_eq!(mappings.close(address, &mut backend), Err(Error::Invalid));
}

#[test]
fn recreated_name_with_distinct_object_never_reuses_old_mapping() {
    let mut mappings = Mappings::<u32, 2>::new();
    let mut backend = Backend::default();
    backend.objects.extend([(1, 100), (2, 101)]);
    let old = mappings.adopt(1, &mut backend).unwrap();
    let new = mappings.adopt(2, &mut backend).unwrap();
    assert_ne!(old, new);
    assert_eq!(backend.mappings[&old], 100);
    assert_eq!(backend.mappings[&new], 101);
    mappings.close(old, &mut backend).unwrap();
    assert_eq!(backend.mappings[&new], 101);
}

#[test]
fn failed_admission_always_releases_received_handle_without_losing_existing_mapping() {
    let mut mappings = Mappings::<u32, 1>::new();
    let mut backend = Backend::default();
    backend
        .objects
        .extend([(1, 100), (2, 101), (3, 102), (4, 103), (5, 100)]);
    backend.fail_map = true;
    assert_eq!(mappings.adopt(1, &mut backend), Err(Error::Backend(12)));
    assert_eq!(backend.closed, [1]);
    backend.fail_map = false;
    let address = mappings.adopt(2, &mut backend).unwrap();
    backend.fail_identity = true;
    assert_eq!(mappings.adopt(3, &mut backend), Err(Error::Backend(5)));
    backend.fail_identity = false;
    assert_eq!(mappings.adopt(4, &mut backend), Err(Error::Full));
    assert_eq!(backend.closed, [1, 3, 4]);
    mappings.close(address, &mut backend).unwrap();
    assert!(mappings.adopt(5, &mut backend).is_ok());
}

#[test]
fn failed_unmap_retains_ownership_for_retry_and_foreign_pointer_does_not_touch_resources() {
    let mut mappings = Mappings::<u32, 1>::new();
    let mut backend = Backend::default();
    backend.objects.insert(1, 100);
    let address = mappings.adopt(1, &mut backend).unwrap();
    assert_eq!(
        mappings.close(address + 8, &mut backend),
        Err(Error::Invalid)
    );
    backend.fail_unmap = true;
    assert_eq!(
        mappings.close(address, &mut backend),
        Err(Error::Backend(14))
    );
    assert!(backend.closed.is_empty());
    assert!(backend.mappings.contains_key(&address));
    backend.fail_unmap = false;
    mappings.close(address, &mut backend).unwrap();
    assert_eq!(backend.closed, [1]);
}
