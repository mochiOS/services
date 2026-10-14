use mochios_posix_client::fd::{
    Entry, FD_CLOEXEC, FdError, FdTable, FileOps, HandleOps, SeekBasis,
};

fn test_entry(handle: u64) -> Entry<u64> {
    Entry {
        handle,
        rights: 0x25,
        descriptor_flags: 0,
    }
}

#[test]
fn ancillary_group_reserves_lowest_available_slots_up_to_limit() {
    let mut table = FdTable::new();
    let mut handles = FakeHandles::default();
    table.install_at(1, test_entry(10), &mut handles).unwrap();
    table.install_at(7, test_entry(70), &mut handles).unwrap();
    let pending_open = table.reserve_from(2, 3).unwrap();
    let group = table.reserve_up_to(0, 5, 253).unwrap();
    assert_eq!(group.len(), 3);
    assert!(!group.is_empty());
    for fd in [0, 3, 4] {
        assert_eq!(table.get(fd), None);
        assert_eq!(
            table.install_at(fd, test_entry(90), &mut handles),
            Err(FdError::BusyDescriptor)
        );
    }
    assert!(table.reserve_up_to(0, 5, 253).unwrap().is_empty());
    let mut output = [-1; 4];
    table
        .commit_group(&group, &[test_entry(20), test_entry(30)], &mut output)
        .unwrap();
    assert_eq!(output, [0, 3, -1, -1]);
    assert_eq!(table.get(0), Some(test_entry(20)));
    assert_eq!(table.get(3), Some(test_entry(30)));
    assert_eq!(table.install_from(0, 5, test_entry(40)), Ok(4));
    assert_eq!(table.get(7), Some(test_entry(70)));
    assert_eq!(
        table.commit_reservation(&pending_open, test_entry(50)),
        Ok(2)
    );
    assert_eq!(table.cancel_group(&group), 0);
    assert!(handles.closed.is_empty());
}

#[test]
fn ancillary_group_publishes_all_253_entries_without_changing_rights_or_cloexec() {
    let mut table = FdTable::new();
    for handle in 0..3 {
        table.install(test_entry(handle)).unwrap();
    }
    let group = table.reserve_up_to(0, 256, 253).unwrap();
    let entries: Vec<_> = (0..253)
        .map(|index| Entry {
            handle: 1000 + index,
            rights: 1 << (index % 8),
            descriptor_flags: if index % 2 == 0 { FD_CLOEXEC } else { 0 },
        })
        .collect();
    let mut output = [-1; 253];
    assert_eq!(group.len(), entries.len());
    table.commit_group(&group, &entries, &mut output).unwrap();
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(output[index], 3 + index as i32);
        assert_eq!(table.get(output[index]), Some(*entry));
    }
    assert_eq!(
        table.commit_group(&group, &entries, &mut output),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.cancel_group(&group), 0);
}

#[test]
fn ancillary_group_bad_lengths_leave_every_reservation_and_output_unchanged() {
    let mut table = FdTable::new();
    let group = table.reserve_up_to(0, 3, 2).unwrap();
    let mut output = [-1; 3];
    assert_eq!(
        table.commit_group(&group, &[test_entry(1); 3], &mut output),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(output, [-1; 3]);
    assert_eq!(
        table.commit_group(&group, &[test_entry(1); 2], &mut output[..1]),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(output, [-1; 3]);
    assert_eq!(table.install(test_entry(90)), Ok(2));
    assert_eq!(table.get(0), None);
    assert_eq!(table.get(1), None);
    assert_eq!(table.cancel_group(&group), 2);
    assert_eq!(table.install(test_entry(10)), Ok(0));
    assert_eq!(table.install(test_entry(20)), Ok(1));
}

#[test]
fn ancillary_stale_group_cannot_publish_or_release_another_receives_slots() {
    let mut table = FdTable::<u64>::new();
    let stale = table.reserve_up_to(0, 3, 3).unwrap();
    table.clear_reservations();
    let next = table.reserve_up_to(1, 3, 2).unwrap();
    let mut output = [-1; 3];
    assert_eq!(
        table.commit_group(&stale, &[test_entry(10); 3], &mut output),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(output, [-1; 3]);
    assert_eq!(table.get(0), None); // Even the first valid-looking slot is untouched.
    assert_eq!(table.cancel_group(&stale), 0);
    table
        .commit_group(&next, &[test_entry(20); 2], &mut output)
        .unwrap();
    assert_eq!(output, [1, 2, -1]);
}

#[test]
fn ancillary_group_is_not_inherited_and_parent_reservations_stay_exclusive() {
    let parent = std::sync::Mutex::new(FdTable::new());
    let group = parent.lock().unwrap().reserve_up_to(0, 4, 3).unwrap();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut table = parent.lock().unwrap();
                assert_eq!(table.install(test_entry(40)), Ok(3));
                let mut child = table.clone();
                assert_eq!(child.cancel_group(&group), 0);
                assert_eq!(child.install(test_entry(50)), Ok(0));
                let mut output = [-1; 3];
                assert_eq!(
                    child.commit_group(&group, &[test_entry(60); 3], &mut output),
                    Err(FdError::InvalidDescriptor)
                );
                assert_eq!(output, [-1; 3]);
            })
            .join()
            .unwrap();
    });
    let mut table = parent.lock().unwrap();
    let mut output = [-1; 3];
    table
        .commit_group(&group, &[test_entry(10); 3], &mut output)
        .unwrap();
    assert_eq!(output, [0, 1, 2]);
    assert_eq!(table.get(3), Some(test_entry(40)));
}

#[test]
fn ancillary_zero_capacity_and_invalid_ranges_do_not_reserve_slots() {
    let mut table = FdTable::<u64>::new();
    for (minimum, limit, maximum) in [(0, 0, 253), (256, 256, 253), (0, 256, 0)] {
        let group = table.reserve_up_to(minimum, limit, maximum).unwrap();
        assert!(group.is_empty());
        table.commit_group(&group, &[], &mut []).unwrap();
        assert_eq!(table.cancel_group(&group), 0);
    }
    for (minimum, limit, maximum) in [(-1, 2, 1), (2, 1, 1), (0, 257, 1), (0, -1, 1), (0, 2, 257)] {
        assert!(matches!(
            table.reserve_up_to(minimum, limit, maximum),
            Err(FdError::InvalidDescriptor)
        ));
    }
    let group = table.reserve_up_to(0, 256, 256).unwrap();
    assert_eq!(group.len(), 256);
    // A receive without ancillary data releases all previously reserved slots.
    table.commit_group(&group, &[], &mut []).unwrap();
    assert_eq!(table.reserve_up_to(0, 256, 256).unwrap().len(), 256);
}

#[test]
fn pending_open_is_not_visible_and_cannot_be_stolen() {
    let mut table = FdTable::new();
    let source = table.install(test_entry(10)).unwrap();
    let reservation = table.reserve_from(0, 2).unwrap();
    let mut handles = FakeHandles::default();
    assert_eq!(table.get(1), None);
    assert_eq!(table.close(1, &mut handles), Err(FdError::BadDescriptor));
    assert_eq!(
        table.install_from(0, 2, test_entry(20)),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(
        table.duplicate_from(source, 0, 2, false, &mut handles),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(
        table.duplicate_to(source, 1, &mut handles),
        Err(FdError::BusyDescriptor)
    );
    assert_eq!(
        table.install_at(1, test_entry(30), &mut handles),
        Err(FdError::BusyDescriptor)
    );
    assert!(handles.cloned.is_empty());
    assert!(handles.closed.is_empty());
    assert_eq!(
        table.commit_reservation(&reservation, test_entry(40)),
        Ok(1)
    );
    assert_eq!(table.get(1), Some(test_entry(40)));
    assert!(!table.cancel_reservation(&reservation));
}

#[test]
fn failed_open_releases_slot_and_stale_token_cannot_cancel_next_open() {
    let mut table = FdTable::<u64>::new();
    let old = table.reserve_from(0, 1).unwrap();
    assert!(table.cancel_reservation(&old));
    let next = table.reserve_from(0, 1).unwrap();
    assert!(!table.cancel_reservation(&old));
    assert_eq!(
        table.commit_reservation(&old, test_entry(10)),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(
        table.install_from(0, 1, test_entry(20)),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.commit_reservation(&next, test_entry(30)), Ok(0));
}

#[test]
fn concurrent_allocation_does_not_consume_pending_open_slot() {
    let table = std::sync::Mutex::new(FdTable::new());
    let reservation = table.lock().unwrap().reserve_from(0, 2).unwrap();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut table = table.lock().unwrap();
                assert_eq!(table.install_from(0, 2, test_entry(20)), Ok(1));
                assert_eq!(
                    table.install_from(0, 2, test_entry(30)),
                    Err(FdError::InvalidDescriptor)
                );
            })
            .join()
            .unwrap();
    });
    let mut table = table.lock().unwrap();
    assert_eq!(
        table.commit_reservation(&reservation, test_entry(10)),
        Ok(0)
    );
    assert_eq!(table.get(0), Some(test_entry(10)));
    assert_eq!(table.get(1), Some(test_entry(20)));
}

#[test]
fn fork_snapshot_inherits_entries_but_not_other_threads_pending_opens() {
    let mut parent = FdTable::new();
    parent.install(test_entry(10)).unwrap();
    let reservation = parent.reserve_from(0, 2).unwrap();
    let mut child = parent.clone();
    assert_eq!(child.get(0), Some(test_entry(10)));
    assert_eq!(child.install_from(0, 2, test_entry(20)), Ok(1));
    assert_eq!(
        parent.install_from(0, 2, test_entry(30)),
        Err(FdError::InvalidDescriptor)
    );
    parent.clear_reservations();
    assert!(!parent.cancel_reservation(&reservation));
    assert_eq!(parent.install_from(0, 2, test_entry(40)), Ok(1));
}

#[test]
fn reservations_reject_invalid_ranges_without_consuming_capacity() {
    let mut table = FdTable::<u64>::new();
    for (minimum, limit) in [(-1, 1), (0, 0), (2, 1), (0, 257), (0, -1)] {
        assert!(matches!(
            table.reserve_from(minimum, limit),
            Err(FdError::InvalidDescriptor)
        ));
    }
    assert_eq!(table.install(test_entry(10)), Ok(0));
}

#[derive(Default)]
struct FakeHandles {
    cloned: Vec<(u64, u64)>,
    closed: Vec<u64>,
    io_handles: Vec<u64>,
    cursor: u64,
}

impl FileOps<u64> for FakeHandles {
    type Error = ();

    fn read(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        self.io_handles.push(handle);
        buffer.fill(0x5a);
        self.cursor += buffer.len() as u64;
        Ok(buffer.len())
    }

    fn write(&mut self, handle: u64, buffer: &[u8]) -> Result<usize, Self::Error> {
        self.io_handles.push(handle);
        self.cursor += buffer.len() as u64;
        Ok(buffer.len())
    }

    fn seek(&mut self, handle: u64, offset: i64, basis: SeekBasis) -> Result<u64, Self::Error> {
        self.io_handles.push(handle);
        let base = match basis {
            SeekBasis::Start => 0,
            SeekBasis::Current => self.cursor as i64,
            SeekBasis::End => 100,
        };
        self.cursor = (base + offset) as u64;
        Ok(self.cursor)
    }
}

impl HandleOps<u64> for FakeHandles {
    type Error = ();

    fn clone_handle(&mut self, handle: u64, rights: u64) -> Result<u64, Self::Error> {
        self.cloned.push((handle, rights));
        Ok(handle)
    }

    fn close_handle(&mut self, handle: u64) {
        self.closed.push(handle);
    }
}

#[test]
fn dup_references_the_same_open_file_description_and_clears_cloexec() {
    let mut table = FdTable::new();
    let source = table
        .install(Entry {
            handle: 88,
            rights: 0x25,
            descriptor_flags: FD_CLOEXEC,
        })
        .unwrap();
    let mut handles = FakeHandles::default();
    let duplicate = table.duplicate(source, &mut handles).unwrap();
    assert_eq!(table.get(duplicate).unwrap().handle, 88);
    assert_eq!(table.get(duplicate).unwrap().rights, 0x25);
    assert_eq!(table.get(duplicate).unwrap().descriptor_flags, 0);
    assert_eq!(handles.cloned, vec![(88, 0x25)]);
}

#[test]
fn minimum_duplication_selects_the_lowest_free_slot_without_replacing() {
    let mut table = FdTable::new();
    let mut handles = FakeHandles::default();
    let source = table
        .install(Entry {
            handle: 88,
            rights: 0x25,
            descriptor_flags: FD_CLOEXEC,
        })
        .unwrap();
    assert_eq!(
        table.duplicate_from(source, 7, 10, false, &mut handles),
        Ok(7)
    );
    assert_eq!(
        table.duplicate_from(source, 7, 10, true, &mut handles),
        Ok(8)
    );
    assert_eq!(table.get(7).unwrap().descriptor_flags, 0);
    assert_eq!(table.get(8).unwrap().descriptor_flags, FD_CLOEXEC);
    assert_eq!(table.get(source).unwrap().descriptor_flags, FD_CLOEXEC);
    assert_eq!(table.get(8).unwrap().rights, 0x25);
    assert_eq!(handles.cloned, vec![(88, 0x25); 2]);
    assert!(handles.closed.is_empty());
    table.close(7, &mut handles).unwrap();
    assert_eq!(
        table.duplicate_from(source, 7, 10, false, &mut handles),
        Ok(7)
    );
}

#[test]
fn failed_duplication_does_not_clone_or_close_handles() {
    let mut table = FdTable::new();
    let mut handles = FakeHandles::default();
    let source = table
        .install(Entry {
            handle: 88,
            rights: 1,
            descriptor_flags: 0,
        })
        .unwrap();
    assert_eq!(
        table.duplicate_from(source, 0, 1, false, &mut handles),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(
        table.duplicate_from(source, -1, 3, false, &mut handles),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(
        table.duplicate_from(source, 3, 3, false, &mut handles),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(
        table.duplicate_from(source, 0, 257, false, &mut handles),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(
        table.duplicate_from(99, 1, 3, false, &mut handles),
        Err(FdError::BadDescriptor)
    );
    assert_eq!(
        table.duplicate_to(source, 256, &mut handles),
        Err(FdError::InvalidDescriptor)
    );
    assert!(handles.cloned.is_empty());
    assert!(handles.closed.is_empty());
    assert_eq!(table.get(source).unwrap().handle, 88);
}

#[test]
fn native_clone_failure_leaves_the_target_free() {
    struct FailingHandles;
    impl HandleOps<u64> for FailingHandles {
        type Error = i32;
        fn clone_handle(&mut self, _: u64, _: u64) -> Result<u64, i32> {
            Err(13)
        }
        fn close_handle(&mut self, _: u64) {
            panic!("no clone was acquired");
        }
    }
    let mut table = FdTable::new();
    table
        .install(Entry {
            handle: 88,
            rights: 1,
            descriptor_flags: 0,
        })
        .unwrap();
    assert_eq!(
        table.duplicate_from(0, 7, 10, true, &mut FailingHandles),
        Err(FdError::Handle(13))
    );
    assert_eq!(table.get(7), None);
}

#[test]
fn exec_closes_only_cloexec_descriptors() {
    let mut table = FdTable::new();
    let keep = table
        .install(Entry {
            handle: 10,
            rights: 1,
            descriptor_flags: 0,
        })
        .unwrap();
    let close = table
        .install(Entry {
            handle: 11,
            rights: 1,
            descriptor_flags: FD_CLOEXEC,
        })
        .unwrap();
    let mut handles = FakeHandles::default();
    table.close_on_exec(&mut handles);
    assert!(table.get(keep).is_some());
    assert!(table.get(close).is_none());
    assert_eq!(handles.closed, vec![11]);
}

#[test]
fn lowering_the_allocation_limit_preserves_existing_high_descriptors() {
    let mut table = FdTable::new();
    let entry = Entry {
        handle: 88,
        rights: 1,
        descriptor_flags: 0,
    };
    let mut handles = FakeHandles::default();
    table.install_at(7, entry, &mut handles).unwrap();
    assert_eq!(table.install_from(0, 1, entry), Ok(0));
    assert_eq!(
        table.install_from(0, 1, entry),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(
        table.duplicate_from(7, 0, 1, false, &mut handles),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.get(7), Some(entry));
    assert_eq!(
        table.install_from(0, 0, entry),
        Err(FdError::InvalidDescriptor)
    );
    assert!(handles.cloned.is_empty());
    table.close(0, &mut handles).unwrap();
    assert_eq!(table.install_from(0, 1, entry), Ok(0));
    assert_eq!(table.get(7), Some(entry));
}

#[test]
fn fast_path_resolves_local_fds_to_handles_before_io() {
    let mut table = FdTable::new();
    let fd = table
        .install(Entry {
            handle: 0xfeed,
            rights: 0x7,
            descriptor_flags: 0,
        })
        .unwrap();
    let mut handles = FakeHandles::default();
    let mut input = [0u8; 3];

    assert_eq!(table.read(fd, &mut input, &mut handles), Ok(3));
    assert_eq!(input, [0x5a; 3]);
    assert_eq!(table.write(fd, b"ok", &mut handles), Ok(2));
    assert_eq!(table.seek(fd, -1, SeekBasis::Current, &mut handles), Ok(4));
    assert_eq!(handles.io_handles, vec![0xfeed, 0xfeed, 0xfeed]);
}

#[test]
fn descriptor_allocation_respects_the_process_local_range() {
    let mut table = FdTable::new();
    let entry = Entry {
        handle: 7,
        rights: 1,
        descriptor_flags: 0,
    };

    assert_eq!(table.install_from(3, 5, entry), Ok(3));
    assert_eq!(table.install_from(3, 5, entry), Ok(4));
    assert_eq!(
        table.install_from(3, 5, entry),
        Err(FdError::InvalidDescriptor)
    );
    assert_eq!(table.get(0), None);
    assert_eq!(table.get(3), Some(entry));
}

#[test]
fn inherited_install_preserves_fd_number_and_closes_replaced_handle() {
    let mut table = FdTable::new();
    let mut handles = FakeHandles::default();
    table
        .install_at(
            7,
            Entry {
                handle: 70,
                rights: 0x15,
                descriptor_flags: 0,
            },
            &mut handles,
        )
        .unwrap();
    assert_eq!(table.get(7).unwrap().handle, 70);
    table
        .install_at(
            7,
            Entry {
                handle: 71,
                rights: 0x05,
                descriptor_flags: 0,
            },
            &mut handles,
        )
        .unwrap();
    assert_eq!(table.get(7).unwrap().handle, 71);
    assert_eq!(handles.closed, vec![70]);
}

#[test]
fn spawn_close_ignores_an_already_closed_descriptor() {
    let mut table = FdTable::<u64>::new();
    let mut handles = FakeHandles::default();

    table.close_for_spawn(19, &mut handles);

    assert!(handles.closed.is_empty());
}

#[test]
fn spawn_dup2_clears_cloexec_even_when_source_equals_target() {
    let mut table = FdTable::new();
    let mut handles = FakeHandles::default();
    table
        .install_at(
            9,
            Entry {
                handle: 90,
                rights: 0x15,
                descriptor_flags: FD_CLOEXEC,
            },
            &mut handles,
        )
        .unwrap();

    assert_eq!(table.duplicate_for_spawn(9, 9, &mut handles), Ok(9));
    assert_eq!(table.get(9).unwrap().descriptor_flags, 0);
    assert!(handles.cloned.is_empty());
    assert!(handles.closed.is_empty());
}
