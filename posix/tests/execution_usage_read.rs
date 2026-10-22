use std::io::Write;
use std::process::{Command, Stdio};

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod native_probe;

#[test]
fn low_level_accounting_wrapper_uses_native_errors_without_issuing_invalid_handles() {
    let mut program = native_probe::program().replace(
        "mod mnu_abi {pub mod status {",
        "mod mnu_abi {pub const SUCCESS:u64=0;pub mod status {",
    );
    program.push_str(r#"
use std::cell::Cell;
use mnu_abi::status::Error;
#[repr(C)]#[derive(Default,Debug,PartialEq)]struct ProcessExecutionUsage{user_ticks:u64,kernel_ticks:u64,ticks_per_second:u64,reserved:u64}
enum SyscallNumber{ProcessExecutionRead}
thread_local!{
    static CALLS:Cell<usize>=const{Cell::new(0)};
    static RAW:Cell<Option<Error>>=const{Cell::new(None)};
    static RATE:Cell<u64>=const{Cell::new(500)};
    static RESERVED:Cell<u64>=const{Cell::new(0)};
    static STATUS:Cell<u64>=const{Cell::new(0)};
}
fn call3(_:SyscallNumber,handle:u64,output:u64,length:u64)->SysResult<u64>{
    assert!([0,42].contains(&handle));assert_eq!(length,32);CALLS.set(CALLS.get()+1);
    if let Some(error)=RAW.get(){return Err(SysError::from_raw(error.into_raw()as i64));}
    unsafe{*(output as *mut ProcessExecutionUsage)=ProcessExecutionUsage{user_ticks:u64::MAX,kernel_ticks:7,ticks_per_second:RATE.get(),reserved:RESERVED.get()};}
    Ok(STATUS.get())
}
mod actual{use crate::{mnu_abi,ProcessExecutionUsage,SysError,SysResult,SyscallNumber,Error};
"#);
    program.push_str(native_probe::between(
        include_str!("../../../user/crates/syscall/src/execution.rs"),
        "pub fn usage(",
        "pub fn identity(",
    ));
    program.push_str(r#"
}
fn main(){
    assert_eq!(actual::usage(Some(0)).unwrap_err().native_error(),Some(Error::InvalidArgument));assert_eq!(CALLS.get(),0);
    for handle in [None,Some(42)]{let result=actual::usage(handle).unwrap();assert_eq!((result.user_ticks,result.kernel_ticks),(u64::MAX,7));}
    for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady,Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        RAW.set(Some(error));let result=actual::usage(Some(42)).unwrap_err();assert_eq!(result.native_error(),Some(error));assert_eq!(result.errno(),None);
    }
    RAW.set(None);
    for field in 0..3{
        if field==0{RATE.set(0)}else if field==1{RESERVED.set(1)}else{STATUS.set(1)}
        assert_eq!(actual::usage(None).unwrap_err().native_error(),Some(Error::BackingFailure));
        RATE.set(500);RESERVED.set(0);STATUS.set(0);
    }
}
"#);
    native_probe::run(&program);
}

#[test]
fn native_accounting_layout_has_only_execution_domains_and_sampling_rate() {
    assert_eq!(mnu_abi::SyscallNumber::ProcessExecutionRead as u64, 683);
    assert_eq!(std::mem::size_of::<mnu_abi::ProcessExecutionUsage>(), 32);
    assert_eq!(std::mem::align_of::<mnu_abi::ProcessExecutionUsage>(), 8);
    assert_eq!(mnu_abi::ProcessExecutionUsage::default().reserved, 0);
    assert_eq!(std::mem::size_of::<mnu_abi::ProcessStatus>(), 32);
}

#[test]
fn production_reader_requires_an_observable_process_object_and_validates_output() {
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let start = source.find("fn process_status_for(").unwrap();
    let end = source[start..]
        .find("/// Waits until the process exits.")
        .unwrap()
        + start;
    let mut program = String::from(
        r#"
use std::sync::Arc;
const SUCCESS: u64 = 0;
use mnu_abi::status::Error;
const EBADF: u64 = Error::InvalidArgument.into_raw();
const EACCES: u64 = Error::AccessDenied.into_raw();
const EINVAL: u64 = Error::InvalidArgument.into_raw();
const EFAULT: u64 = Error::InvalidAddress.into_raw();
thread_local!{
    static PRESENT:std::cell::Cell<bool>=const{std::cell::Cell::new(true)};
    static CALLER:std::cell::Cell<bool>=const{std::cell::Cell::new(true)};
    static RATE:std::cell::Cell<u64>=const{std::cell::Cell::new(500)};
    static COPY_ERROR:std::cell::Cell<Option<Error>>=const{std::cell::Cell::new(None)};
    static COPIES:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};
}
mod mnu_abi {
    #[repr(C)] #[derive(Default, Debug, PartialEq)]
    pub struct ProcessExecutionUsage {
        pub user_ticks: u64, pub kernel_ticks: u64, pub ticks_per_second: u64, pub reserved: u64,
    }
}
use lifecycle::ProcessObject as Counter;
#[derive(Debug,Clone,Copy)]struct ProcessId(u64);impl ProcessId{fn as_u64(self)->u64{self.0}}
fn remote()->Arc<Counter>{
    static OBJECT:std::sync::OnceLock<Arc<Counter>>=std::sync::OnceLock::new();
    OBJECT.get_or_init(||lifecycle::create(42,13,17)).clone()
}
struct Process { object: Arc<Counter> }
impl Process { fn process_object(&self) -> Arc<Counter> { Arc::clone(&self.object) } }
enum KernelObject { Process(Arc<Counter>), File }
#[derive(PartialEq, Debug)] struct HandleRights;
impl HandleRights { const WAIT: Self = Self; }
fn object_native(raw: u64, right: HandleRights) -> Result<KernelObject, Error> {
    assert_eq!(right, HandleRights::WAIT);
    if !CALLER.with(|v|v.get()) || !PRESENT.with(|v|v.get()){return Err(Error::NotReady);}
    match raw {
        42 => Ok(KernelObject::Process(remote())),
        43 => Err(Error::AccessDenied), // Explicit handle exists but does not grant WAIT.
        9 => Ok(KernelObject::File),
        _ => Err(Error::InvalidArgument),
    }
}
mod task {
    use super::*;
    pub mod process {pub use crate::lifecycle::ProcessObject;}
    pub fn with_process<R>(id: u64, read: impl FnOnce(&Process) -> R) -> Option<R> {
        // The remote process has already left the process table. Its retained
        // native object is still observable through the explicit handle.
        (id == 1 && PRESENT.with(|v|v.get())).then(|| read(&Process { object: lifecycle::create(1,7,11) }))
    }
    pub mod thread {
        use super::*;
        pub fn process_execution_ticks(counter: &Counter) -> (u64, u64) { (counter.user_cpu_ticks(), counter.kernel_cpu_ticks()) }
    }
}
mod interrupt { pub mod timer { pub fn ticks_per_second() -> u64 { crate::RATE.with(|v|v.get()) } } }
mod syscall {
    use super::*;
    pub mod security {pub fn current_process_id()->Option<u64>{crate::CALLER.with(|v|v.get()).then_some(1)}}
    pub fn copy_to_user_native(output: u64, bytes: &[u8]) -> Result<(), Error> {
        COPIES.with(|v|v.set(v.get()+1));
        if let Some(error)=COPY_ERROR.with(|v|v.get()){return Err(error);}
        if output < 4096 { return Err(Error::InvalidAddress); }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output as *mut u8, bytes.len()); }
        Ok(())
    }
}
"#,
    );
    let status = include_str!("../../../core/crates/abi/src/status.rs");
    program = program.replace("mod mnu_abi {", &format!("mod mnu_abi {{pub mod status {{\n{status}\n}}\n\
        pub const PROCESS_STATE_RUNNING:u32=1;pub const PROCESS_STATE_EXITED:u32=2;\n\
        #[repr(C)]#[derive(Default,Debug,PartialEq,Clone,Copy)]pub struct ProcessStatus {{pub process_id:u64,pub state:u32,pub reserved:u32,pub exit_code:u64,pub image_revision:u64}}\n"));
    let process = include_str!("../../../core/src/task/process.rs");
    let object = &process[process
        .find("#[derive(Debug)]\npub struct ProcessObject")
        .unwrap()..];
    let object = &object[..object
        .find("#[derive(Clone, Copy, Debug, PartialEq, Eq)]")
        .unwrap()];
    program.push_str("mod lifecycle {use crate::{mnu_abi,ProcessId};use std::sync::{Arc,atomic::{AtomicU8,AtomicU64,Ordering}};\n");
    program.push_str(object);
    program.push_str(r#"
pub fn create(id:u64,user:u64,kernel:u64)->Arc<ProcessObject>{
    let object=ProcessObject::new(ProcessId(id));object.user_cpu_ticks.store(user,Ordering::Relaxed);
    object.kernel_cpu_ticks.store(kernel,Ordering::Relaxed);Arc::new(object)
}
pub fn exit(object:&ProcessObject){object.mark_exited(u64::MAX);}
}
"#);
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() {
    let mut usage = mnu_abi::ProcessExecutionUsage::default();
    let output = (&mut usage as *mut mnu_abi::ProcessExecutionUsage) as u64;
    assert_eq!(process_execution_read(0, output, 32), SUCCESS);
    assert_eq!((usage.user_ticks, usage.kernel_ticks, usage.ticks_per_second, usage.reserved), (7, 11, 500, 0));
    assert_eq!(process_execution_read(42, output, 32), SUCCESS);
    assert_eq!((usage.user_ticks, usage.kernel_ticks), (13, 17));
    for (handle, expected) in [(43, EACCES), (9, EBADF), (99, EBADF)] {
        assert_eq!(process_execution_read(handle, output, 32), expected);
        assert_eq!((usage.user_ticks, usage.kernel_ticks), (13, 17));
    }
    for length in [0, 31, 33, u64::MAX] {
        assert_eq!(process_execution_read(0, output, length), EINVAL);
    }
    assert_eq!(process_execution_read(0, 0, 32), EFAULT);
    assert_eq!(process_execution_read(0, 1, 32), EFAULT);
    let mut state=mnu_abi::ProcessStatus::default();let state_output=&mut state as *mut _ as u64;
    assert_eq!(process_status(42,state_output),0);assert_eq!((state.process_id,state.state,state.reserved,state.exit_code),(42,1,0,0));
    lifecycle::exit(&remote());assert_eq!(process_status(42,state_output),0);
    assert_eq!((state.process_id,state.state,state.reserved,state.exit_code),(42,2,0,u64::MAX));
    assert_eq!(process_execution_read(42,output,32),0);assert_eq!((usage.user_ticks,usage.kernel_ticks),(13,17));
    for (handle,error) in [(43,EACCES),(9,EBADF),(99,EBADF)]{assert_eq!(process_status(handle,state_output),error);}
    assert_eq!(process_status(42,0),EFAULT);
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        COPY_ERROR.with(|v|v.set(Some(error)));let before=(usage.user_ticks,usage.kernel_ticks);
        assert_eq!(process_execution_read(42,output,32),error.into_raw());assert_eq!(process_status(42,state_output),error.into_raw());
        assert_eq!((usage.user_ticks,usage.kernel_ticks),before);assert_eq!(state.exit_code,u64::MAX);
    }
    COPY_ERROR.with(|v|v.set(None));
    for missing_caller in [false,true]{
        if missing_caller{CALLER.with(|v|v.set(false))}else{PRESENT.with(|v|v.set(false))}
        let copies=COPIES.with(|v|v.get());assert_eq!(process_execution_read(0,output,32),Error::NotReady.into_raw());
        assert_eq!(process_status(42,state_output),Error::NotReady.into_raw());
        assert_eq!(COPIES.with(|v|v.get()),copies);PRESENT.with(|v|v.set(true));CALLER.with(|v|v.set(true));
    }
    RATE.with(|v|v.set(0));let copies=COPIES.with(|v|v.get());
    assert_eq!(process_execution_read(42,output,32),Error::NotReady.into_raw());assert_eq!(COPIES.with(|v|v.get()),copies);
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-execution-read-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings", "-"])
        .arg("-o")
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed = Command::new(&executable).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}

#[test]
fn snapshot_is_coherent_and_platform_wrapper_rejects_invalid_optional_handles() {
    let thread = include_str!("../../../core/src/task/thread.rs");
    let snapshot = thread
        .split("fn process_execution_ticks(")
        .nth(1)
        .unwrap()
        .split("fn mark_thread_terminated(")
        .next()
        .unwrap();
    assert!(
        snapshot.find("THREAD_QUEUE.lock()").unwrap()
            < snapshot.find("process.user_cpu_ticks()").unwrap()
    );
    assert!(snapshot.contains("process.kernel_cpu_ticks()"));
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    let wrapper = platform
        .split("fn execution_usage(")
        .nth(1)
        .unwrap()
        .split("fn wait_handle(")
        .next()
        .unwrap();
    assert!(wrapper.contains("syscall::execution::usage(handle)"));
    let low = include_str!("../../../user/crates/syscall/src/execution.rs");
    assert!(low.contains("Some(0) => return Err"));
    assert!(low.contains("ProcessExecutionRead"));
    assert!(low.contains("usage.ticks_per_second == 0 || usage.reserved != 0"));
    assert!(!wrapper.contains("process_id"));
}
