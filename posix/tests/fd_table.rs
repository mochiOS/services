use mochios_posix_client::fd::{
    Entry, FD_CLOEXEC, FdError, FdTable, FileOps, HandleOps, SeekBasis,
};

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

    fn seek(
        &mut self,
        handle: u64,
        offset: i64,
        basis: SeekBasis,
    ) -> Result<u64, Self::Error> {
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
    assert_eq!(
        table.seek(fd, -1, SeekBasis::Current, &mut handles),
        Ok(4)
    );
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
