extern crate alloc;
#[path = "../../../core/src/mem/mapping_revocation.rs"]
mod mapping_revocation;
use mapping_revocation::{revoke, virtual_overlap, Backend, Error};

#[derive(Default)]
struct Vm {
    events: Vec<(&'static str, u64)>,
    fail_page: Option<u64>,
    fail_sync: bool,
    completed: bool,
}
impl Backend for Vm {
    type Page = (u64, u64);
    type Error = u8;
    fn suspend(&mut self, table: u64, address: u64) -> Result<Option<Self::Page>, u8> {
        if self.fail_page == Some(address) {
            return Err(5);
        }
        self.events.push(("suspend", address));
        Ok(Some((table, address)))
    }
    fn restore(&mut self, (_, address): Self::Page) {
        self.events.push(("restore", address));
    }
    fn synchronize(&mut self) -> Result<(), u8> {
        self.events.push(("synchronize", 0));
        if self.fail_sync {
            return Err(7);
        }
        self.completed = true;
        Ok(())
    }
    fn release(&mut self, (_, address): Self::Page) {
        assert!(
            self.completed,
            "never free frames before remote acknowledgement"
        );
        self.events.push(("release", address));
    }
}

#[test]
fn successful_revocation_batches_all_tables_before_sync_and_release() {
    let mut vm = Vm::default();
    revoke([(4096, 0x1000, 0x3000), (8192, 0x9000, 0xa000)], &mut vm).unwrap();
    assert_eq!(
        vm.events,
        [
            ("suspend", 0x1000),
            ("suspend", 0x2000),
            ("suspend", 0x9000),
            ("synchronize", 0),
            ("release", 0x1000),
            ("release", 0x2000),
            ("release", 0x9000),
        ]
    );
}
#[test]
fn editing_and_sync_failures_restore_ownership_without_freeing() {
    let ranges = [(4096, 0x1000, 0x4000)];
    let mut vm = Vm {
        fail_page: Some(0x3000),
        ..Default::default()
    };
    assert_eq!(revoke(ranges, &mut vm), Err(Error::Backend(5)));
    assert_eq!(
        vm.events,
        [
            ("suspend", 0x1000),
            ("suspend", 0x2000),
            ("restore", 0x2000),
            ("restore", 0x1000)
        ]
    );
    let mut vm = Vm {
        fail_sync: true,
        ..Default::default()
    };
    assert_eq!(revoke(ranges, &mut vm), Err(Error::Backend(7)));
    assert_eq!(
        &vm.events[3..],
        [
            ("synchronize", 0),
            ("restore", 0x3000),
            ("restore", 0x2000),
            ("restore", 0x1000)
        ]
    );
    assert!(!vm.events.iter().any(|(event, _)| *event == "release"));
}
#[test]
fn all_ranges_are_validated_before_the_first_edit() {
    let mut vm = Vm::default();
    for invalid in [
        (4097, 0x1000, 0x2000),
        (4096, 1, 4096),
        (4096, 4096, 4096),
        (4096, 8192, 4096),
    ] {
        assert_eq!(
            revoke([(4096, 0x1000, 0x2000), invalid], &mut vm),
            Err(Error::InvalidRange)
        );
        assert!(vm.events.is_empty());
    }
    revoke([], &mut vm).unwrap();
    assert!(vm.events.is_empty());
    assert_eq!(
        revoke([(4096, 4096, 12288), (4096, 8192, 16384)], &mut vm),
        Err(Error::InvalidRange)
    );
    assert!(vm.events.is_empty());
}
#[test]
fn backing_offsets_select_only_overlapping_virtual_pages_without_overflow() {
    assert_eq!(
        virtual_overlap(0x10000, 0x4000, 0x8000, 0xa000, 0xd000),
        Ok(Some((0x12000, 0x14000)))
    );
    assert_eq!(
        virtual_overlap(0x10000, 0x4000, 0x8000, 0, 0x8000),
        Ok(None)
    );
    assert_eq!(
        virtual_overlap(0x10000, 0x4000, 0x8000, 0xc000, 0xd000),
        Ok(None)
    );
    assert_eq!(virtual_overlap(u64::MAX, 4096, 0, 0, 4096), Err(()));
    assert_eq!(virtual_overlap(4096, 4096, u64::MAX, 0, 4096), Err(()));
    assert_eq!(virtual_overlap(4096, 4096, 0, 2, 1), Err(()));
}
