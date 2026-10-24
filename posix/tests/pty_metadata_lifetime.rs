use mnu_abi::{HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_TRANSFER as T};
use posix_service::{
    pty::{EACCES, EBADF, ENOTSUP, PtyManager},
    filesystem_reference::{Backend, Reference},
};
use std::sync::{Arc, Mutex};

#[derive(Default, Debug)]
struct Calls {
    dropped: Vec<u32>,
    duplicates: Vec<(u32, u64)>,
}
#[derive(Debug)]
struct Metadata {
    handle: u32,
    calls: Arc<Mutex<Calls>>,
}
impl Backend for Metadata {
    fn duplicate(&self, rights: u64) -> Result<u32, i32> {
        self.calls
            .lock()
            .unwrap()
            .duplicates
            .push((self.handle, rights));
        Ok(90 + self.handle)
    }
}
impl Drop for Metadata {
    fn drop(&mut self) {
        self.calls.lock().unwrap().dropped.push(self.handle);
    }
}
fn reference(calls: &Arc<Mutex<Calls>>, handle: u32, rights: u64) -> Result<Reference, i32> {
    Reference::new(
        Box::new(Metadata {
            handle,
            calls: calls.clone(),
        }),
        rights,
    )
}

#[test]
fn metadata_lives_with_each_open_not_with_factory_or_master() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let factory = ptys.create_slave_factory(pair.master_object_id).unwrap();
    let first = ptys
        .open_slave_with_metadata(factory, reference(&calls, 1, D | T | C).unwrap())
        .unwrap();
    let second = ptys
        .open_slave_with_metadata(factory, reference(&calls, 2, D | T).unwrap())
        .unwrap();
    ptys.release(factory).unwrap();
    ptys.release(pair.master_object_id).unwrap();
    ptys.release(pair.slave_object_id).unwrap();
    assert!(calls.lock().unwrap().dropped.is_empty());
    // Metadata remains available after hangup and does not require READ.
    assert_eq!(ptys.duplicate_slave_metadata(first, T, T), Ok(91));
    ptys.release(first).unwrap();
    assert_eq!(calls.lock().unwrap().dropped, vec![1]);
    assert_eq!(ptys.duplicate_slave_metadata(first, T, T), Err(EBADF));
    assert_eq!(ptys.duplicate_slave_metadata(second, T, T), Ok(92));
    ptys.release(second).unwrap();
    assert_eq!(calls.lock().unwrap().dropped, vec![1, 2]);
}

#[test]
fn both_attached_data_authority_and_retained_metadata_limit_each_lookup() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let factory = ptys.create_slave_factory(pair.master_object_id).unwrap();
    let full = ptys
        .open_slave_with_metadata(factory, reference(&calls, 1, D | T | C).unwrap())
        .unwrap();
    let limited = ptys
        .open_slave_with_metadata(factory, reference(&calls, 2, D | T).unwrap())
        .unwrap();
    assert_eq!(ptys.duplicate_slave_metadata(full, C | T, C | T), Ok(91));
    assert_eq!(ptys.duplicate_slave_metadata(full, T, C | T), Err(EACCES));
    assert_eq!(
        ptys.duplicate_slave_metadata(limited, C | T, C | T),
        Err(EACCES)
    );
    assert_eq!(ptys.duplicate_slave_metadata(full, C, T), Err(EACCES));
    for rights in [
        0,
        C,
        T | D,
        T | mnu_abi::HANDLE_RIGHT_READ,
        T | mnu_abi::HANDLE_RIGHT_WRITE,
        u64::MAX,
    ] {
        assert_eq!(
            ptys.duplicate_slave_metadata(full, u64::MAX, rights),
            Err(EACCES)
        );
    }
    assert_eq!(
        ptys.duplicate_slave_metadata(pair.slave_object_id, T, T),
        Err(ENOTSUP)
    );
    for id in [pair.master_object_id, factory, u64::MAX] {
        assert_eq!(ptys.duplicate_slave_metadata(id, T, T), Err(EBADF));
    }
    assert_eq!(calls.lock().unwrap().duplicates, vec![(1, C | T)]);
}

#[test]
fn rejected_metadata_and_failed_open_drop_the_owned_reference_exactly_once() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    for (index, rights) in [T, D, 0, D | T | mnu_abi::HANDLE_RIGHT_READ]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            reference(&calls, index as u32, rights).unwrap_err(),
            EACCES
        );
    }
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let factory = ptys.create_slave_factory(pair.master_object_id).unwrap();
    ptys.release(pair.master_object_id).unwrap();
    assert_eq!(
        ptys.open_slave_with_metadata(factory, reference(&calls, 4, D | T).unwrap()),
        Err(EBADF)
    );
    assert_eq!(calls.lock().unwrap().dropped, vec![0, 1, 2, 3, 4]);
}

#[test]
fn publication_failure_discard_and_manager_destruction_release_only_owned_opens() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let factory = ptys.create_slave_factory(pair.master_object_id).unwrap();
    let failed = ptys
        .open_slave_with_metadata(factory, reference(&calls, 1, D | T).unwrap())
        .unwrap();
    // Native publication failed: reclaim this open, not the entire terminal.
    ptys.release(failed).unwrap();
    let _ = ptys
        .open_slave_with_metadata(factory, reference(&calls, 2, D | T).unwrap())
        .unwrap();
    let other = ptys.open().unwrap();
    let other_factory = ptys.create_slave_factory(other.master_object_id).unwrap();
    let retained = ptys
        .open_slave_with_metadata(other_factory, reference(&calls, 3, D | T).unwrap())
        .unwrap();
    ptys.discard(pair);
    assert_eq!(calls.lock().unwrap().dropped, vec![1, 2]);
    assert_eq!(ptys.duplicate_slave_metadata(retained, T, T), Ok(93));
    drop(ptys);
    assert_eq!(calls.lock().unwrap().dropped, vec![1, 2, 3]);
}
