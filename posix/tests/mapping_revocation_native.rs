extern crate alloc;
#[path = "../../../core/src/mem/mapping_revocation.rs"]
mod mapping_revocation;
#[path = "../../../core/src/mem/mapping_revocation_native.rs"]
mod mapping_revocation_native;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

mod syscall {
    pub const EFAULT: u64 = (-14i64) as u64;
    pub const EIO: u64 = (-5i64) as u64;
}
mod task {
    pub mod process {
        pub struct Process(pub u64);
        impl Process {
            pub fn page_table(&self) -> Option<u64> {
                Some(self.0)
            }
        }
        pub struct ProcessTable(pub Vec<Process>);
        impl ProcessTable {
            pub fn iter(&self) -> impl Iterator<Item = &Process> {
                self.0.iter()
            }
        }
    }
}
#[derive(Default)]
struct State {
    entries: BTreeMap<(u64, u64), u64>,
    synchronized: bool,
    fail_sync: bool,
    released: usize,
}
fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(Default::default)
}
mod paging {
    pub struct SuspendedUserPage {
        table: u64,
        address: u64,
        flags: u64,
    }
    pub unsafe fn suspend_user_page(
        table: u64,
        address: u64,
    ) -> Result<Option<SuspendedUserPage>, ()> {
        let mut state = super::state().lock().unwrap();
        let Some(flags) = state.entries.get_mut(&(table, address)) else {
            return Ok(None);
        };
        let original = *flags;
        *flags &= !1;
        Ok(Some(SuspendedUserPage {
            table,
            address,
            flags: original,
        }))
    }
    impl SuspendedUserPage {
        pub unsafe fn restore(self) {
            super::state()
                .lock()
                .unwrap()
                .entries
                .insert((self.table, self.address), self.flags);
        }
        pub unsafe fn release(self) {
            let mut state = super::state().lock().unwrap();
            assert!(
                state.synchronized,
                "frame release requires all-CPU acknowledgement"
            );
            assert_eq!(
                state.entries.remove(&(self.table, self.address)),
                Some(self.flags & !1)
            );
            state.released += 1;
        }
    }
}
mod tlb_shootdown {
    pub fn invalidate_all() -> Result<(), ()> {
        let mut state = super::state().lock().unwrap();
        assert!(state.entries.values().all(|flags| flags & 1 == 0));
        if state.fail_sync {
            return Err(());
        }
        state.synchronized = true;
        Ok(())
    }
}

#[test]
fn actual_native_adapter_checks_owned_roots_restores_on_sync_failure_and_releases_only_after_ack() {
    use mapping_revocation::{revoke, Backend, Error};
    use mapping_revocation_native::Native;
    use task::process::{Process, ProcessTable};
    let table = ProcessTable(vec![Process(4096), Process(8192)]);
    // Host owns the entire mock table and PTE map throughout this transaction.
    let mut native = unsafe { Native::new(&table) };
    assert!(matches!(native.suspend(12288, 4096), Err(syscall::EFAULT)));
    assert_eq!(native.suspend(4096, 4096).unwrap().is_none(), true);
    *state().lock().unwrap() = State {
        entries: BTreeMap::from([((4096, 4096), 0x105), ((8192, 8192), 0x205)]),
        fail_sync: true,
        ..Default::default()
    };
    let ranges = [(4096, 4096, 8192), (8192, 8192, 12288)];
    assert_eq!(
        revoke(ranges, &mut native),
        Err(Error::Backend(syscall::EIO))
    );
    {
        let state = state().lock().unwrap();
        assert_eq!(
            state.entries,
            BTreeMap::from([((4096, 4096), 0x105), ((8192, 8192), 0x205)])
        );
        assert_eq!(state.released, 0);
    }
    state().lock().unwrap().fail_sync = false;
    revoke(ranges, &mut native).unwrap();
    let state = state().lock().unwrap();
    assert!(state.entries.is_empty());
    assert_eq!(state.released, 2);
}
