//! Compose real launch queries, raw-status decoding and runtime absence policy.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn initial_process_probe_uses_the_current_native_abi() {
    use mnu_abi::{SyscallNumber as N, status::Error};
    let source = include_str!("native_launch_lookup.c");
    for (name, call) in [
        ("HANDLE_CLOSE", N::HandleClose),
        ("LAUNCH_HANDLE_GET", N::LaunchHandleGet),
        ("THREAD_YIELD", N::ThreadYield),
        ("LAUNCH_VALUE_GET", N::LaunchValueGet),
        ("CONTEXT_HANDLE_SET", N::ContextHandleSet),
        ("CONTEXT_HANDLE_REMOVE", N::ContextHandleRemove),
        ("CONTEXT_VALUE_SET", N::ContextValueSet),
        ("CONTEXT_VALUE_REMOVE", N::ContextValueRemove),
        ("HANDLE_RIGHTS_GET", N::HandleRightsGet),
        ("MEMORY_OBJECT_CREATE", N::MemoryObjectCreate),
    ] {
        assert!(source.contains(&format!("{name} = {}", call as u64)));
    }
    for (name, error) in [
        ("NATIVE_NOT_FOUND", Error::NotFound),
        ("NATIVE_INVALID_ARGUMENT", Error::InvalidArgument),
        ("NATIVE_INVALID_ADDRESS", Error::InvalidAddress),
    ] {
        assert!(source.contains(&format!(
            "#define {name} INT64_C({})",
            error.into_raw() as i64
        )));
    }
    assert!(source.contains(&format!(
        "control = UINT64_C({:#x})",
        mochios_posix_protocol::CONTROL_HANDLE_KEY
    )));
}

#[test]
fn only_native_missing_keys_are_absent_and_other_lookup_failures_survive() {
    let kernel = include_str!("../../../core/src/syscall/handle.rs");
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let context = include_str!("../../../core/src/task/launch_context.rs");
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{cell::{Cell,RefCell},collections::BTreeMap,sync::{Arc,atomic::{AtomicBool,Ordering}}};
static DENY:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if DENY.load(Ordering::Relaxed) {return std::ptr::null_mut();}
        unsafe {std::alloc::System.alloc(layout)}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout) {
        unsafe {std::alloc::System.dealloc(p,layout)}
    }
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
mod mnu_abi {pub mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}}\nuse mnu_abi::status::Error;\nmod posix_protocol {\n");
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["CONTROL_HANDLE_KEY", "STATUS_EIO", "STATUS_EAGAIN"],
    );
    program.push_str("pub mod status {use crate::{mnu_abi,posix_protocol as protocol};\n");
    // normalize_failure uses its crate's wire constants.
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n")
            .replace("crate::STATUS_", "protocol::STATUS_"),
    );
    program
        .push_str("}}\nmod newlib_errno {use crate::posix_protocol as mochios_posix_protocol;\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-client/src/newlib_errno.rs")
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    program.push_str("}\n");
    program.push_str(probe::between(
        table,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]",
        "#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]",
    ));
    program.push_str("type ObjectHandleEntry=Arc<()>;\nstruct Table {entries:BTreeMap<ObjectHandle,ObjectHandleEntry>}\nimpl Table {\n");
    program.push_str(probe::between(
        table,
        "    pub fn get(",
        "    /// Captures transferable references",
    ));
    program.push_str("}\nstruct Launch {inherited_handles:BTreeMap<u64,ObjectHandle>,inherited_values:BTreeMap<u64,u64>}\nimpl Launch {\n");
    program.push_str(probe::between(
        context,
        "    pub fn get(",
        "    pub fn install(",
    ));
    program.push_str(probe::between(
        context,
        "    pub fn value(",
        "    pub fn install_value(",
    ));
    program.push_str(
        r#"
}
thread_local! {
    static CONTEXT:Cell<Option<u64>>=const {Cell::new(Some(19))};
    static PRESENT:Cell<bool>=const {Cell::new(true)};
    static LOCKED:Cell<bool>=const {Cell::new(false)};
    static COPY_ERROR:Cell<Option<Error>>=const {Cell::new(None)};
    static RAW_ERROR:Cell<Option<u64>>=const {Cell::new(None)};
    static COPIES:Cell<usize>=const {Cell::new(0)};
    static VALID_OUTPUT:Cell<u64>=const {Cell::new(0)};
    static FIRST:RefCell<task::Process>=const {RefCell::new(task::Process::new())};
    static SECOND:RefCell<task::Process>=const {RefCell::new(task::Process::new())};
}
mod task {
    use super::*;
    pub struct Process {pub table:Table,pub launch:Launch}
    impl Process {
        pub const fn new()->Self {Self{table:Table{entries:BTreeMap::new()},launch:Launch{inherited_handles:BTreeMap::new(),inherited_values:BTreeMap::new()}}}
        pub fn object_handles(&self)->&Table {assert!(LOCKED.get());&self.table}
        pub fn launch_context(&self)->&Launch {assert!(LOCKED.get());&self.launch}
    }
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T> {
        if !PRESENT.get() {return None;}
        assert!(!LOCKED.replace(true));
        let result=match id {19=>FIRST.with_borrow(body),20=>SECOND.with_borrow(body),_=>panic!("foreign table")};
        assert!(LOCKED.replace(false));Some(result)
    }
}
mod syscall {
    use crate::{mnu_abi,Error};
    use mnu_abi::status::Error as NativeError;
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "#[inline(always)]\n#[allow(unsafe_op_in_unsafe_fn)]\npub unsafe fn syscall0(",
    ));
    program.push_str(
        r#"
    pub mod security {pub fn current_process_id()->Option<u64> {crate::CONTEXT.get()}}
    pub fn copy_to_user_native(output:u64,bytes:&[u8])->Result<(),Error> {
        assert!(!crate::LOCKED.get());assert_eq!(bytes.len(),8);
        crate::COPIES.set(crate::COPIES.get()+1);
        if let Some(error)=crate::COPY_ERROR.get() {return Err(error);}
        if output==0 || output!=crate::VALID_OUTPUT.get() {return Err(Error::InvalidAddress);}
        unsafe {std::ptr::copy_nonoverlapping(bytes.as_ptr(),output as *mut u8,bytes.len());}
        Ok(())
    }
    pub enum SyscallNumber {LaunchHandleGet,LaunchValueGet}
    pub fn raw_syscall1(number:SyscallNumber,key:u64)->RawSyscallResult {
        assert!(matches!(number,SyscallNumber::LaunchHandleGet));
        RawSyscallResult::new(crate::RAW_ERROR.get().unwrap_or_else(||crate::production::launch_get(key)))
    }
    pub fn raw_syscall2(number:SyscallNumber,key:u64,output:u64)->RawSyscallResult {
        assert!(matches!(number,SyscallNumber::LaunchValueGet));crate::VALID_OUTPUT.set(output);
        RawSyscallResult::new(crate::RAW_ERROR.get().unwrap_or_else(||crate::production::launch_value_get(key,output)))
    }
}
mod production {use crate::{mnu_abi,ObjectHandle};const SUCCESS:u64=0;
"#,
    );
    program.push_str(probe::between(
        kernel,
        "pub fn launch_get(",
        "/// Associates one of the caller's existing object handles",
    ));
    program.push_str(&kernel[kernel.find("pub fn launch_value_get(").unwrap()..]);
    program.push_str(
        r#"
}
type c_int=i32;
fn map_kernel_errno(raw:i64)->c_int {newlib_errno::from_status(raw)}
#[derive(Debug,PartialEq,Eq)]enum FdKind {Unused}
#[derive(Debug,PartialEq,Eq)]struct FdObject {lower_handle:u64,kind:FdKind,open_flags:i32,close_owned:bool}
trait LaunchContextOps<T> {
    type Error;
    fn get_value(&mut self,key:u64)->Result<Option<u64>,Self::Error>;
    fn get_handle(&mut self,key:u64)->Result<Option<T>,Self::Error>;
}
"#,
    );
    program.push_str(probe::between(
        runtime,
        "fn has_posix_environment(",
        "fn native_process_id(",
    ));
    program.push_str(probe::between(
        runtime,
        "struct RuntimeLaunchContext;",
        "    fn get_handle_rights(",
    ));
    program.push_str(
        r#"
}
fn check<T:std::fmt::Debug+PartialEq>(operation:impl FnOnce()->T,expected:T) {
    DENY.store(true,Ordering::Relaxed);let result=operation();DENY.store(false,Ordering::Relaxed);
    assert_eq!(result,expected);assert!(!LOCKED.get());
}
fn main() {
    let resource=Arc::new(());let control=posix_protocol::CONTROL_HANDLE_KEY;
    FIRST.with_borrow_mut(|p|{
        p.table.entries.insert(ObjectHandle(7),resource.clone());
        p.launch.inherited_handles.extend([(control,ObjectHandle(7)),(u64::MAX,ObjectHandle(7)),(1,ObjectHandle(99))]);
        p.launch.inherited_values.extend([(0,0),(u64::MAX,u64::MAX),(1,Error::NotFound.into_raw())]);
    });
    SECOND.with_borrow_mut(|p|{p.launch.inherited_values.insert(0,42);});
    check(||production::launch_get(control),7);check(||production::launch_get(u64::MAX),7);
    check(has_posix_environment,Ok(true));
    check(||RuntimeLaunchContext.get_handle(control),Ok(Some(FdObject{lower_handle:7,kind:FdKind::Unused,open_flags:0,close_owned:true})));
    for (key,value) in [(0,0),(u64::MAX,u64::MAX),(1,Error::NotFound.into_raw())] {
        check(||RuntimeLaunchContext.get_value(key),Ok(Some(value)));
    }
    let copies=COPIES.get();
    check(||production::launch_get(55),Error::NotFound.into_raw());
    check(||production::launch_value_get(55,0),Error::NotFound.into_raw());
    check(||RuntimeLaunchContext.get_handle(55),Ok(None));
    check(||RuntimeLaunchContext.get_value(55),Ok(None));assert_eq!(COPIES.get(),copies);
    check(||production::launch_get(1),Error::InvalidArgument.into_raw());
    check(||RuntimeLaunchContext.get_handle(1),Err(newlib_errno::EINVAL));
    FIRST.with_borrow_mut(|p|{p.launch.inherited_handles.remove(&control);});
    check(has_posix_environment,Ok(false));
    FIRST.with_borrow_mut(|p|{p.launch.inherited_handles.insert(control,ObjectHandle(99));});
    check(has_posix_environment,Err(newlib_errno::EINVAL));
    for absent in [false,true] {
        if absent {PRESENT.set(false);} else {CONTEXT.set(None);}
        let copies=COPIES.get();
        check(||production::launch_get(control),Error::NotReady.into_raw());
        check(||production::launch_value_get(0,0),Error::NotReady.into_raw());
        check(has_posix_environment,Err(newlib_errno::EAGAIN));
        check(||RuntimeLaunchContext.get_handle(control),Err(newlib_errno::EAGAIN));
        check(||RuntimeLaunchContext.get_value(0),Err(newlib_errno::EAGAIN));
        assert_eq!(COPIES.get(),copies);PRESENT.set(true);CONTEXT.set(Some(19));
    }
    let mut output=123u64;VALID_OUTPUT.set((&mut output as *mut u64) as u64);
    check(||production::launch_value_get(0,0),Error::InvalidAddress.into_raw());assert_eq!(output,123);
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure,Error::AccessDenied,Error::NotReady] {
        COPY_ERROR.set(Some(error));
        check(||production::launch_value_get(0,VALID_OUTPUT.get()),error.into_raw());assert_eq!(output,123);
        check(||RuntimeLaunchContext.get_value(0),Err(newlib_errno::from_status(error.into_raw() as i64)));
    }
    COPY_ERROR.set(None);
    // Neither old EBADF/ENOENT nor an unknown native error means absence.
    for raw in [(-9i64) as u64,(-2i64) as u64,Error::NotFound.into_raw()|0xffff] {
        RAW_ERROR.set(Some(raw));let expected=newlib_errno::from_status(raw as i64);
        check(has_posix_environment,Err(expected));
        check(||RuntimeLaunchContext.get_handle(control),Err(expected));
        check(||RuntimeLaunchContext.get_value(0),Err(expected));
    }
    RAW_ERROR.set(None);CONTEXT.set(Some(20));
    check(||RuntimeLaunchContext.get_value(0),Ok(Some(42)));
    check(||RuntimeLaunchContext.get_handle(u64::MAX),Ok(None));CONTEXT.set(Some(19));
    assert_eq!(Arc::strong_count(&resource),2);
}
"#,
    );
    probe::run(&program);
}
