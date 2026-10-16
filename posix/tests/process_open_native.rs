#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn process_acquisition_preserves_capability_gates_and_native_failures() {
    let mut program = probe::program();
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]\npub struct HandleRights",
        "/// Kernel object identity stored behind a process-local handle.",
    ));
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "const PROCESS_HANDLE_RIGHTS:",
        "/// Retain an object created by this caller",
    ));
    program.push_str(
        r#"
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use mnu_abi::status::Error;
struct Object;
enum KernelObject { Process(Arc<Object>) }
struct ObjectHandleEntry { object: KernelObject, rights: HandleRights }
impl ObjectHandleEntry {
    fn new(object: KernelObject, rights: HandleRights) -> Self { Self { object, rights } }
}
struct Handle;
impl Handle { fn raw(&self) -> u32 { 41 } }
thread_local! {
    static INSPECT: Cell<bool> = const { Cell::new(true) };
    static KILL: Cell<bool> = const { Cell::new(true) };
    static TARGET: Cell<bool> = const { Cell::new(true) };
    static CALLER: Cell<bool> = const { Cell::new(true) };
    static CALLER_RECORD: Cell<bool> = const { Cell::new(true) };
    static ENDPOINT: Cell<bool> = const { Cell::new(true) };
    static THREAD: Cell<bool> = const { Cell::new(true) };
    static STORAGE: Cell<bool> = const { Cell::new(true) };
    static INSERTIONS: Cell<usize> = const { Cell::new(0) };
    static OBJECT: Arc<Object> = Arc::new(Object);
    static ENTRIES: RefCell<Vec<ObjectHandleEntry>> = const { RefCell::new(Vec::new()) };
}
struct Table;
impl Table {
    fn insert(&mut self, entry: ObjectHandleEntry) -> Option<Handle> {
        INSERTIONS.set(INSERTIONS.get() + 1);
        if !STORAGE.get() { return None; }
        ENTRIES.with_borrow_mut(|entries| entries.push(entry));
        Some(Handle)
    }
}
struct Process(Table);
impl Process {
    fn process_object(&self) -> Arc<Object> { OBJECT.with(Arc::clone) }
    fn object_handles_mut(&mut self) -> &mut Table { &mut self.0 }
}
"#,
    );
    // The record facade controls lookup/admission only; execute the production
    // acquisition functions, not a replacement implementation of their policy.
    program.push_str(
        r#"
mod capability { pub enum Capability { ProcessInspect, ProcessKill } }
mod syscall {
    pub mod security {
        pub fn current_process_id() -> Option<u64> { crate::CALLER.get().then_some(1) }
        pub fn caller_has_any_capability(capabilities: &[crate::capability::Capability]) -> bool {
            assert_eq!(capabilities.len(), 1);
            match capabilities[0] {
                crate::capability::Capability::ProcessInspect => crate::INSPECT.get(),
                crate::capability::Capability::ProcessKill => crate::KILL.get(),
            }
        }
    }
    pub mod ipc {
        pub fn resolve_endpoint_handle(endpoint: u64) -> Option<u64> {
            assert_eq!(endpoint, 77);
            crate::ENDPOINT.get().then_some(9)
        }
    }
}
mod task {
    pub struct ProcessId;
    impl ProcessId { pub fn from_u64(id: u64) -> u64 { id } }
    pub fn with_process<T>(id: u64, body: impl FnOnce(&crate::Process) -> T) -> Option<T> {
        assert_eq!(id, 7);
        crate::TARGET.get().then(|| body(&crate::Process(crate::Table)))
    }
    pub fn with_process_mut<T>(id: u64, body: impl FnOnce(&mut crate::Process) -> T) -> Option<T> {
        assert_eq!(id, 1);
        crate::CALLER_RECORD.get().then(|| body(&mut crate::Process(crate::Table)))
    }
    pub fn thread_to_process_id(thread: u64) -> Option<u64> {
        assert_eq!(thread, 9);
        crate::THREAD.get().then_some(7)
    }
}
"#,
    );
    // ProcessId is a nominal ID in the kernel; this probe uses its scalar
    // representation while retaining the exact production control flow.
    let source = probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "fn insert_process_handle(",
        "fn process_status_for(",
    );
    program.push_str(&source.replace("target: crate::task::ProcessId", "target: u64"));
    program.push_str(
        r#"
fn retained() -> usize { OBJECT.with(Arc::strong_count) }
fn main() {
    let wait=HandleRights::WAIT.bits();
    let signal=HandleRights::SIGNAL.bits();
    let full=PROCESS_ADMIN_HANDLE_RIGHTS.bits();
    for (operation, identity) in [(process_open as fn(u64,u64)->u64,77), (process_open_by_id,7)] {
        INSERTIONS.set(0);
        INSPECT.set(false);
        assert_eq!(operation(identity,wait),Error::AccessDenied.into_raw());
        INSPECT.set(true);
        for bits in [HandleRights::READ.bits(),HandleRights::RECEIVE.bits(),1<<60,u64::MAX] {
            assert_eq!(operation(identity,bits),Error::InvalidArgument.into_raw());
        }
        KILL.set(false);
        assert_eq!(operation(identity,signal),Error::AccessDenied.into_raw());
        assert_eq!(INSERTIONS.get(),0);
        assert_eq!(operation(identity,wait),41); // Inspect-only needs no kill capability.
        ENTRIES.with_borrow_mut(|entries| entries.clear());
        KILL.set(true);
        TARGET.set(false);
        assert_eq!(operation(identity,full),Error::NotFound.into_raw());
        TARGET.set(true);
        CALLER.set(false);
        assert_eq!(operation(identity,full),Error::NotReady.into_raw());
        CALLER.set(true);
        CALLER_RECORD.set(false);
        assert_eq!(operation(identity,full),Error::NotReady.into_raw());
        CALLER_RECORD.set(true);
        STORAGE.set(false);
        assert_eq!(operation(identity,full),Error::ResourceUnavailable.into_raw());
        assert_eq!(retained(),1);
        STORAGE.set(true);
        for subset in 0..16 {
            let mut bits=0;
            for (index, right) in [wait,signal,HandleRights::DUPLICATE.bits(),HandleRights::TRANSFER.bits()].into_iter().enumerate() {
                if subset & (1<<index) != 0 { bits |= right; }
            }
            assert_eq!(operation(identity,bits),41);
            assert_eq!(retained(),2);
            ENTRIES.with_borrow_mut(|entries| {
                let entry=entries.pop().unwrap();
                assert_eq!(entry.rights,HandleRights(bits));
                let KernelObject::Process(object)=entry.object;
                OBJECT.with(|target| assert!(Arc::ptr_eq(target,&object)));
            });
            assert_eq!(retained(),1);
        }
    }
    assert_eq!(process_open_by_id(0,wait),Error::InvalidArgument.into_raw());
    ENDPOINT.set(false);
    assert_eq!(process_open(77,wait),Error::InvalidArgument.into_raw());
    ENDPOINT.set(true);
    THREAD.set(false);
    assert_eq!(process_open(77,wait),Error::NotFound.into_raw());
    assert_eq!(retained(),1);
}
"#,
    );
    probe::run(&program);
}
