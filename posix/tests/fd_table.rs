use mochios_posix_client::fd::{
    Entry, FD_CLOEXEC, FdTable, FileOps, HandleOps, SeekBasis,
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
