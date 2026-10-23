use mochios_posix_client::fd::{Entry, FD_CLOEXEC, FdError, FdTable, HandleOps};

#[derive(Default)]
struct Handles {
    closed: Vec<u64>,
    fail: bool,
}
impl HandleOps<u64> for Handles {
    type Error = u32;
    fn clone_handle(&mut self, handle: u64, _: u64) -> Result<u64, u32> {
        if self.fail { Err(99) } else { Ok(handle + 100) }
    }
    fn close_handle(&mut self, handle: u64) {
        self.closed.push(handle);
    }
}
fn entry(handle: u64) -> Entry<u64> {
    Entry {
        handle,
        rights: 0x25,
        descriptor_flags: FD_CLOEXEC,
    }
}

#[test]
fn occupied_destination_stays_visible_but_cannot_be_consumed_while_the_table_lock_is_released() {
    use std::sync::{Arc, Barrier, Mutex};
    let table = Arc::new(Mutex::new(FdTable::new()));
    table.lock().unwrap().install(entry(10)).unwrap();
    table
        .lock()
        .unwrap()
        .install_at(7, entry(70), &mut Handles::default())
        .unwrap();
    let (reserved, original) = table.lock().unwrap().reserve_replacement(7).unwrap();
    assert_eq!(original, Some(entry(70)));
    let gate = Arc::new(Barrier::new(2));
    let other_table = table.clone();
    let other_gate = gate.clone();
    let other = std::thread::spawn(move || {
        let mut table = other_table.lock().unwrap();
        let mut handles = Handles::default();
        assert_eq!(table.get(7), Some(entry(70)));
        assert_eq!(table.take(7), Err(FdError::BusyDescriptor));
        assert_eq!(table.close(7, &mut handles), Err(FdError::BusyDescriptor));
        assert_eq!(
            table.install_at(7, entry(71), &mut handles),
            Err(FdError::BusyDescriptor)
        );
        assert_eq!(
            table.duplicate_to(0, 7, &mut handles),
            Err(FdError::BusyDescriptor)
        );
        assert!(handles.closed.is_empty());
        drop(table);
        other_gate.wait();
    });
    gate.wait();
    assert_eq!(
        table
            .lock()
            .unwrap()
            .commit_replacement(&reserved, entry(80)),
        Ok(Some(entry(70)))
    );
    other.join().unwrap();
    assert_eq!(table.lock().unwrap().get(7), Some(entry(80)));
    assert_eq!(table.lock().unwrap().get(0), Some(entry(10)));
}

#[test]
fn vacant_destination_is_unpublished_and_reserved_against_open_pair_and_duplicate_allocation() {
    let mut table = FdTable::new();
    let (reserved, original) = table.reserve_replacement(0).unwrap();
    assert_eq!(original, None);
    assert_eq!(table.get(0), None);
    assert_eq!(table.take(0), Err(FdError::BadDescriptor));
    assert_eq!(
        table.close(0, &mut Handles::default()),
        Err(FdError::BadDescriptor)
    );
    assert_eq!(table.install(entry(10)), Ok(1));
    let pair = table.reserve_pair_from(0, 4).unwrap();
    assert_eq!((pair[0].descriptor(), pair[1].descriptor()), (2, 3));
    assert_eq!(
        table.duplicate_from(1, 0, 4, false, &mut Handles::default()),
        Err(FdError::InvalidDescriptor)
    );
    table.cancel_reservation(&pair[0]);
    table.cancel_reservation(&pair[1]);
    assert!(table.cancel_replacement(&reserved));
    assert_eq!(table.install(entry(20)), Ok(0));
}

#[test]
fn cancellation_and_stale_tokens_cannot_close_or_overwrite_the_original_or_a_later_replacement() {
    let mut table = FdTable::new();
    table.install(entry(10)).unwrap();
    let (old, _) = table.reserve_replacement(0).unwrap();
    assert!(table.cancel_replacement(&old));
    assert_eq!(table.get(0), Some(entry(10)));
    let (next, _) = table.reserve_replacement(0).unwrap();
    assert!(!table.cancel_replacement(&old));
    assert_eq!(
        table.commit_replacement(&old, entry(30)),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.get(0), Some(entry(10)));
    assert_eq!(
        table.commit_replacement(&next, entry(20)),
        Ok(Some(entry(10)))
    );
    assert_eq!(
        table.commit_replacement(&next, entry(40)),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.get(0), Some(entry(20)));
}

#[test]
fn failed_native_clone_rolls_back_both_occupied_and_vacant_reservations_without_closing_either_file()
 {
    for occupied in [false, true] {
        let mut table = FdTable::new();
        let mut handles = Handles {
            fail: true,
            ..Default::default()
        };
        table.install(entry(10)).unwrap();
        if occupied {
            table.install_at(7, entry(70), &mut handles).unwrap();
        }
        assert_eq!(
            table.duplicate_to(0, 7, &mut handles),
            Err(FdError::Handle(99))
        );
        assert_eq!(table.get(0), Some(entry(10)));
        assert_eq!(table.get(7), occupied.then_some(entry(70)));
        assert!(handles.closed.is_empty());
        let (fresh, previous) = table.reserve_replacement(7).unwrap();
        assert_eq!(previous, occupied.then_some(entry(70)));
        table.cancel_replacement(&fresh);
    }
}

#[test]
fn fork_snapshot_contains_original_entries_but_cannot_commit_the_parents_reservation() {
    let mut parent = FdTable::new();
    parent.install(entry(10)).unwrap();
    let (reserved, _) = parent.reserve_replacement(0).unwrap();
    let mut child = parent.clone();
    assert_eq!(child.get(0), Some(entry(10)));
    assert_eq!(
        child.commit_replacement(&reserved, entry(20)),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(child.take(0), Ok(entry(10)));
    assert_eq!(
        parent.commit_replacement(&reserved, entry(30)),
        Ok(Some(entry(10)))
    );
    assert_eq!(parent.get(0), Some(entry(30)));
}

#[test]
fn close_on_exec_does_not_steal_a_prepared_destination_and_commit_returns_the_displaced_owner_once()
{
    let mut table = FdTable::new();
    table.install(entry(10)).unwrap();
    table.install(entry(20)).unwrap();
    let (reserved, _) = table.reserve_replacement(0).unwrap();
    let mut handles = Handles::default();
    table.close_on_exec(&mut handles);
    assert_eq!(handles.closed, [20]);
    assert_eq!(table.get(0), Some(entry(10)));
    let new = Entry {
        descriptor_flags: 0,
        ..entry(30)
    };
    let displaced = table.commit_replacement(&reserved, new).unwrap().unwrap();
    handles.close_handle(displaced.handle);
    table.close_on_exec(&mut handles);
    assert_eq!(handles.closed, [20, 10]);
    assert_eq!(table.get(0), Some(new));
}
