use mochios_posix_client::fd::{Entry, FD_CLOEXEC, FdTable, HandleOps};

#[derive(Default)]
struct FakeHandles {
    cloned: Vec<u64>,
    closed: Vec<u64>,
}

impl HandleOps<u64> for FakeHandles {
    type Error = ();

    fn clone_handle(&mut self, handle: u64) -> Result<u64, Self::Error> {
        self.cloned.push(handle);
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
            descriptor_flags: FD_CLOEXEC,
        })
        .unwrap();
    let mut handles = FakeHandles::default();
    let duplicate = table.duplicate(source, &mut handles).unwrap();
    assert_eq!(table.get(duplicate).unwrap().handle, 88);
    assert_eq!(table.get(duplicate).unwrap().descriptor_flags, 0);
    assert_eq!(handles.cloned, vec![88]);
}

#[test]
fn exec_closes_only_cloexec_descriptors() {
    let mut table = FdTable::new();
    let keep = table
        .install(Entry {
            handle: 10,
            descriptor_flags: 0,
        })
        .unwrap();
    let close = table
        .install(Entry {
            handle: 11,
            descriptor_flags: FD_CLOEXEC,
        })
        .unwrap();
    let mut handles = FakeHandles::default();
    table.close_on_exec(&mut handles);
    assert!(table.get(keep).is_some());
    assert!(table.get(close).is_none());
    assert_eq!(handles.closed, vec![11]);
}
