use std::io::Write;
use std::process::{Command, Stdio};

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_resize_checks_control_and_propagates_type_and_backend_errors() {
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{cell::{Cell,RefCell},sync::Arc,collections::BTreeMap};
use mnu_abi::status::Error;
const SUCCESS:u64=0;
#[derive(Clone)]enum KernelObject {VmObject(Arc<Memory>),Other}
struct Memory {ram:bool,length:Cell<u64>}
thread_local! {
    static CALLS:Cell<u64>=const {Cell::new(0)};
    static LOCKED:Cell<bool>=const {Cell::new(false)};
    static CONTEXT:Cell<Option<u64>>=const {Cell::new(Some(7))};
    static FAILURE:Cell<Option<Error>>=const {Cell::new(None)};
    static CLOSE_ON_RESIZE:Cell<bool>=const {Cell::new(false)};
    static PROCESS:RefCell<task::Process>=RefCell::new(task::Process(task::Table(BTreeMap::new())));
}
impl Memory {
    fn memory_length(&self)->Option<u64> {
        assert!(!LOCKED.get());self.ram.then(||self.length.get())
    }
    fn resize_memory(&self,length:u64)->Result<(),Error> {
        assert!(!LOCKED.get());CALLS.set(CALLS.get()+1);
        if !self.ram {return Err(Error::InvalidArgument);}
        if let Some(error)=FAILURE.get(){return Err(error);}
        if CLOSE_ON_RESIZE.get(){PROCESS.with_borrow_mut(|p|p.0.0.clear());}
        self.length.set(length);Ok(())
    }
}
mod syscall {pub mod security {
    pub fn current_process_id()->Option<u64>{crate::CONTEXT.get()}
}}
mod task {
    pub struct Entry(pub crate::KernelObject,pub crate::HandleRights);
    impl Entry {
        pub fn rights(&self)->crate::HandleRights{self.1}
        pub fn object(&self)->&crate::KernelObject{&self.0}
    }
    pub struct Table(pub crate::BTreeMap<u32,Entry>);
    impl Table {pub fn get(&self,h:crate::ObjectHandle)->Option<&Entry>{self.0.get(&h.raw())}}
    pub struct Process(pub Table);
    impl Process {pub fn object_handles(&self)->&Table{&self.0}}
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T>{
        if id!=7{return None;}
        assert!(!crate::LOCKED.replace(true));
        let result=crate::PROCESS.with_borrow(body);
        crate::LOCKED.set(false);Some(result)
    }
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]\npub struct ObjectHandle",
        "/// Kernel object identity",
    ));
    program.push_str(probe::between(
        source,
        "pub fn memory_object_length(",
        "pub(crate) fn object_with_rights(",
    ));
    program.push_str(
        r#"
fn main() {
    let memory=Arc::new(Memory{ram:true,length:Cell::new(8192)});
    let both=HandleRights::MAP.union(HandleRights::CONTROL);
    PROCESS.with_borrow_mut(|p| {
        for (handle,object,rights) in [
            (7,KernelObject::VmObject(memory.clone()),both),
            (8,KernelObject::VmObject(memory.clone()),HandleRights::MAP),
            (9,KernelObject::Other,both),
            (10,KernelObject::VmObject(memory.clone()),HandleRights::CONTROL),
            (11,KernelObject::VmObject(Arc::new(Memory{ram:false,length:Cell::new(0)})),both),
        ] {p.0.0.insert(handle,task::Entry(object,rights));}
    });
    assert_eq!(memory_object_length(7),8192);
    assert_eq!(memory_object_resize(7,0),0);assert_eq!(memory_object_resize(7,4097),0);
    assert_eq!(memory_object_length(7),4097);
    for error in [Error::ResourceUnavailable,Error::NotReady,Error::BackingFailure,Error::AccessDenied] {
        FAILURE.set(Some(error));
        assert_eq!(memory_object_resize(7,u64::MAX),error.into_raw());
        assert_eq!(memory_object_length(7),4097);
    }
    FAILURE.set(None);
    let before=CALLS.get();
    for raw in [0,12,u32::MAX as u64,u64::MAX,(1u64<<32)|7] {
        assert_eq!(memory_object_resize(raw,0),Error::InvalidArgument.into_raw());
        assert_eq!(memory_object_length(raw),Error::InvalidArgument.into_raw());
    }
    assert_eq!(memory_object_resize(8,4097),Error::AccessDenied.into_raw());
    assert_eq!(memory_object_length(8),4097);
    assert_eq!(memory_object_length(10),Error::AccessDenied.into_raw());
    assert_eq!(memory_object_resize(9,0),Error::InvalidArgument.into_raw());
    assert_eq!(memory_object_length(9),Error::InvalidArgument.into_raw());
    assert_eq!(CALLS.get(),before,"denied/invalid references must not reach backend");
    assert_eq!(memory_object_resize(11,0),Error::InvalidArgument.into_raw());
    assert_eq!(memory_object_length(11),Error::InvalidArgument.into_raw());
    for context in [None,Some(99)] {
        CONTEXT.set(context);
        assert_eq!(memory_object_resize(7,0),Error::NotReady.into_raw());
        assert_eq!(memory_object_length(7),Error::NotReady.into_raw());
    }
    CONTEXT.set(Some(7));
    // Backend work is outside the caller-table guard. Closing all source
    // Handles during resize cannot invalidate the retained resource.
    CLOSE_ON_RESIZE.set(true);
    assert_eq!(memory_object_resize(7,5000),0);
    assert_eq!(memory.length.get(),5000);
    assert_eq!(Arc::strong_count(&memory),1);
    assert_eq!(memory_object_length(7),Error::InvalidArgument.into_raw());
    assert_eq!(memory_object_resize(7,0),Error::InvalidArgument.into_raw());
    assert!(!LOCKED.get());
}
"#,
    );
    program.push_str("\nextern crate self as mnu_abi;\npub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("\n}\n");
    probe::run(&program);
}

#[test]
fn native_resize_probe_matches_mechanism_abi() {
    use mnu_abi::SyscallNumber as Number;
    let source = include_str!("native_memory_object_resize.c");
    for (name, number) in [
        ("CREATE", Number::MemoryObjectCreate),
        ("LENGTH", Number::MemoryObjectLength),
        ("RESIZE", Number::MemoryObjectResize),
        ("READ_AT", Number::HandleReadAt),
        ("WRITE_AT", Number::HandleWriteAt),
        ("MAP", Number::MemoryMap),
        ("UNMAP", Number::MemoryUnmap),
        ("CLOSE", Number::HandleClose),
        ("DUPLICATE", Number::HandleDuplicate),
        ("RIGHTS", Number::HandleRightsGet),
        ("IMAGE_CLONE", Number::AddressSpaceClone),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
    assert_eq!(mnu_abi::MEMORY_OBJECT_RESIZABLE, 1);
    assert_eq!(mnu_abi::HANDLE_RIGHT_CONTROL, 256);
}

#[test]
fn production_ram_dirty_admission_includes_partial_last_pages_without_overflow() {
    let source = include_str!("../../../core/src/mem/vm_object.rs");
    let dirty = source.split("pub fn mark_page_dirty(").nth(1).unwrap();
    let predicate = dirty
        .split("return if ")
        .nth(1)
        .unwrap()
        .split("\n            {")
        .next()
        .unwrap();
    let program = format!(
        r#"
const PAGE_BYTES:usize=4096;
struct Memory(u64);impl Memory {{fn length(&self)->u64 {{self.0}}}}
fn permits(page_index:u64,length:u64)->bool {{let memory=Memory(length);{predicate}}}
fn main() {{
    for length in [0u64,1,4095,4096,4097,8191,8192,8193,u64::MAX] {{
        for index in [0u64,1,2,3,u64::MAX/4096,u64::MAX] {{
            let expected=(index as u128)*4096 < length as u128;
            assert_eq!(permits(index,length),expected,"index={{index}} length={{length}}");
        }}
    }}
}}
"#
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mochios-partial-dirty-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=partial_dirty", "-", "-o"])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compile
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let output = compile.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
