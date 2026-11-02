//! Execute the production RAM extent query and caller-reference lookup.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn retained_ram_extent_requires_read_or_map_without_provider_io() {
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let mut program = probe::program();
    program.push_str("use mnu_abi::status::Error;\n");
    program.push_str("mod task {\n");
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]\npub struct HandleRights",
        "/// Kernel object identity stored behind a process-local handle.",
    ));
    program.push_str(
        r#"
    #[derive(Clone)]
    pub enum KernelObject { VmObject(VmObject), Provider, File }
    #[derive(Clone)]
    pub struct VmObject(pub Option<u64>);
    impl VmObject {
        pub fn memory_length(&self) -> Option<u64> {
            crate::EXTENT_QUERIES.set(crate::EXTENT_QUERIES.get() + 1);
            self.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct ObjectHandle(u32);
    impl ObjectHandle {
        pub fn from_raw(raw: u32) -> Option<Self> { (raw != 0).then_some(Self(raw)) }
    }
    #[derive(Clone)]
    pub struct Entry { pub object: KernelObject, pub rights: HandleRights }
    impl Entry {
        pub fn object(&self) -> &KernelObject { &self.object }
        pub fn rights(&self) -> HandleRights { self.rights }
    }
    pub struct Process { pub entry: Entry }
    impl Process {
        pub fn object_handles(&self) -> &Self { self }
        pub fn get(&self, handle: ObjectHandle) -> Option<&Entry> {
            (handle.0 == 19).then_some(&self.entry)
        }
    }
    pub fn with_process<T>(pid: u64, operation: impl FnOnce(&Process) -> T) -> Option<T> {
        assert_eq!(pid, 7);
        crate::LOOKUPS.set(crate::LOOKUPS.get() + 1);
        crate::PROCESS.with_borrow(|process| process.as_ref().map(operation))
    }
}
mod syscall {
    pub mod security {
        pub fn current_process_id() -> Option<u64> { crate::CALLER.get() }
    }
}
use task::{HandleRights, KernelObject, ObjectHandle};
use std::cell::{Cell, RefCell};
thread_local! {
    static CALLER: Cell<Option<u64>> = const { Cell::new(Some(7)) };
    static PROCESS: RefCell<Option<task::Process>> = const { RefCell::new(None) };
    static LOOKUPS: Cell<usize> = const { Cell::new(0) };
    static EXTENT_QUERIES: Cell<usize> = const { Cell::new(0) };
}
fn install(object: KernelObject, rights: HandleRights) {
    CALLER.set(Some(7));
    LOOKUPS.set(0);
    EXTENT_QUERIES.set(0);
    PROCESS.with_borrow_mut(|process| *process = Some(task::Process { entry: task::Entry { object, rights } }));
}
"#,
    );
    program.push_str(probe::between(
        source,
        "pub fn memory_object_length(",
        "pub fn memory_object_resize(",
    ));
    program.push_str(probe::between(
        source,
        "pub(crate) fn object_native(",
        "pub fn read(",
    ));
    program.push_str(
        r#"
fn main() {
    let permissions = [HandleRights::READ, HandleRights::WRITE, HandleRights::MAP,
        HandleRights::SEND, HandleRights::RECEIVE, HandleRights::WAIT,
        HandleRights::SIGNAL, HandleRights::SEEK, HandleRights::CONTROL,
        HandleRights::DUPLICATE, HandleRights::TRANSFER];
    for mask in 0..(1 << permissions.len()) {
        let rights = permissions.iter().enumerate().fold(HandleRights::empty(), |rights, (bit, permission)| {
            if mask & (1 << bit) != 0 { rights.union(*permission) } else { rights }
        });
        let allowed = mask & 0b101 != 0;
        for (object, value, queries) in [
            (KernelObject::VmObject(task::VmObject(Some(12345))), 12345, 1),
            (KernelObject::VmObject(task::VmObject(Some(0))), 0, 1),
            (KernelObject::VmObject(task::VmObject(None)), Error::InvalidArgument.into_raw(), 1),
            (KernelObject::Provider, Error::InvalidArgument.into_raw(), 0),
            (KernelObject::File, Error::InvalidArgument.into_raw(), 0),
        ] {
            install(object, rights);
            assert_eq!(memory_object_length(19), if allowed { value } else { Error::AccessDenied.into_raw() });
            assert_eq!(LOOKUPS.get(), 1);
            assert_eq!(EXTENT_QUERIES.get(), if allowed { queries } else { 0 });
        }
    }
    for selector in [0, 20, u64::MAX] {
        install(KernelObject::VmObject(task::VmObject(Some(4096))), HandleRights::READ);
        assert_eq!(memory_object_length(selector), Error::InvalidArgument.into_raw());
        assert_eq!(EXTENT_QUERIES.get(), 0);
    }
    install(KernelObject::VmObject(task::VmObject(Some(4096))), HandleRights::READ);
    CALLER.set(None);
    assert_eq!(memory_object_length(19), Error::NotReady.into_raw());
    assert_eq!(LOOKUPS.get(), 0);
    CALLER.set(Some(7));
    PROCESS.with_borrow_mut(|process| *process = None);
    assert_eq!(memory_object_length(19), Error::NotReady.into_raw());
    assert_eq!(EXTENT_QUERIES.get(), 0);
}
"#,
    );
    probe::run(&program);
}
