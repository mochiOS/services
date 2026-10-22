use mnu_abi::SyscallNumber;

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn self_suspension_requires_context_and_observed_resumption() {
    let mut program = probe::program();
    program.push_str(
        r#"
use std::cell::Cell;
use mnu_abi::status::Error;
const SUCCESS:u64=0;
thread_local! {
    static PROCESS:Cell<bool>=const{Cell::new(true)};
    static THREAD:Cell<bool>=const{Cell::new(true)};
    static PRESENT:Cell<bool>=const{Cell::new(true)};
    static ELIGIBLE:Cell<usize>=const{Cell::new(1)};
    static SUSPENDED:Cell<bool>=const{Cell::new(true)};
    static CALLS:Cell<usize>=const{Cell::new(0)};
    static YIELDS:Cell<usize>=const{Cell::new(0)};
    static RETIRE:Cell<bool>=const{Cell::new(false)};
}
mod syscall{pub mod security{
    pub fn current_process_id()->Option<u64>{crate::PROCESS.get().then_some(7)}
}}
mod task {
    pub struct Thread;
    impl Thread{pub fn is_scheduling_suspended(&self)->bool{crate::SUSPENDED.get()}}
    pub fn current_thread_id()->Option<u64>{crate::THREAD.get().then_some(9)}
    pub fn with_thread<T>(id:u64,body:impl FnOnce(&Thread)->T)->Option<T>{
        assert_eq!(id,9);crate::PRESENT.get().then(||body(&Thread))
    }
    pub fn suspend_process_threads(id:u64)->usize{
        assert_eq!(id,7);crate::CALLS.set(crate::CALLS.get()+1);crate::ELIGIBLE.get()
    }
    pub fn yield_now(){
        let count=crate::YIELDS.get()+1;crate::YIELDS.set(count);
        if crate::RETIRE.get(){crate::PRESENT.set(false);}
        else if count==3{crate::SUSPENDED.set(false);}
        assert!(count<=3,"self-suspension failed to observe resumption");
    }
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/process.rs"),
        "pub fn suspend_current_process()",
        "/// Sleepシステムコール",
    ));
    program.push_str(r#"
fn main(){
    PROCESS.set(false);assert_eq!(suspend_current_process(),Error::NotReady.into_raw());assert_eq!(CALLS.get(),0);
    PROCESS.set(true);THREAD.set(false);assert_eq!(suspend_current_process(),Error::NotReady.into_raw());assert_eq!(CALLS.get(),0);
    THREAD.set(true);ELIGIBLE.set(0);assert_eq!(suspend_current_process(),Error::NotReady.into_raw());assert_eq!(CALLS.get(),1);
    ELIGIBLE.set(1);PRESENT.set(false);assert_eq!(suspend_current_process(),Error::NotReady.into_raw());assert_eq!(YIELDS.get(),0);
    PRESENT.set(true);CALLS.set(0);assert_eq!(suspend_current_process(),0);assert_eq!(CALLS.get(),1);assert_eq!(YIELDS.get(),3);
    // An immediate resume between suspension and the first read is success.
    CALLS.set(0);YIELDS.set(0);assert_eq!(suspend_current_process(),0);assert_eq!(CALLS.get(),1);assert_eq!(YIELDS.get(),0);
    SUSPENDED.set(true);RETIRE.set(true);CALLS.set(0);
    assert_eq!(suspend_current_process(),Error::NotReady.into_raw());assert_eq!(CALLS.get(),1);assert_eq!(YIELDS.get(),1);
}
"#);
    probe::run(&program);
}

#[test]
fn control_entries_require_signal_authority_and_preserve_native_failures() {
    let mut program = probe::program();
    program.push_str(r#"
use std::cell::Cell;
use mnu_abi::status::Error;
const SUCCESS:u64=0;
thread_local!{
    static FAILURE:Cell<Option<Error>>=const{Cell::new(None)};
    static EXITED:Cell<bool>=const{Cell::new(false)};
    static PRESENT:Cell<bool>=const{Cell::new(true)};
    static RESUMED:Cell<Option<usize>>=const{Cell::new(Some(1))};
    static SUSPENDED:Cell<usize>=const{Cell::new(1)};
    static CALLS:Cell<usize>=const{Cell::new(0)};
}
struct HandleRights;impl HandleRights{const SIGNAL:Self=Self;}
struct Process;impl Process{fn id(&self)->u64{7}fn is_exited(&self)->bool{EXITED.get()}}
enum KernelObject{Process(Process),Other}
fn object_native(raw:u64,_:HandleRights)->Result<KernelObject,Error>{
    if let Some(error)=FAILURE.get(){return Err(error);}
    Ok(if raw==1{KernelObject::Process(Process)}else{KernelObject::Other})
}
mod task{
    pub fn with_process<T>(id:u64,body:impl FnOnce(())->T)->Option<T>{assert_eq!(id,7);crate::PRESENT.get().then(||body(()))}
    pub fn resume_process_threads(id:u64)->Option<usize>{assert_eq!(id,7);crate::CALLS.set(crate::CALLS.get()+1);crate::RESUMED.get()}
    pub fn suspend_process_threads(id:u64)->usize{assert_eq!(id,7);crate::CALLS.set(crate::CALLS.get()+1);crate::SUSPENDED.get()}
}
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn process_resume(",
        "pub fn process_terminate(",
    ));
    program.push_str(r#"
fn main(){
    for operation in [process_resume as fn(u64)->u64,process_suspend as fn(u64)->u64]{
        CALLS.set(0);
        for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady]{
            FAILURE.set(Some(error));assert_eq!(operation(1),error.into_raw());assert_eq!(CALLS.get(),0);
        }
        FAILURE.set(None);assert_eq!(operation(2),Error::InvalidArgument.into_raw());assert_eq!(CALLS.get(),0);
        EXITED.set(true);assert_eq!(operation(1),Error::NotFound.into_raw());assert_eq!(CALLS.get(),0);EXITED.set(false);
        PRESENT.set(false);assert_eq!(operation(1),Error::NotFound.into_raw());assert_eq!(CALLS.get(),0);PRESENT.set(true);
        assert_eq!(operation(1),0);assert_eq!(CALLS.get(),1);
    }
    RESUMED.set(None);assert_eq!(process_resume(1),Error::NotFound.into_raw());
    RESUMED.set(Some(0));assert_eq!(process_resume(1),0);
    SUSPENDED.set(0);assert_eq!(process_suspend(1),Error::NotReady.into_raw());
}
"#);
    probe::run(&program);
}

#[test]
fn native_process_suspension_is_generic_and_outside_the_posix_protocol() {
    assert_eq!(SyscallNumber::ProcessSuspendCurrent as u64, 669);
    assert_eq!(SyscallNumber::ProcessHandleSuspend as u64, 670);

    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let implementation = include_str!("../../../core/src/syscall/process.rs");
    assert!(dispatch.contains("SyscallNumber::ProcessSuspendCurrent"));
    assert!(dispatch.contains("SyscallNumber::ProcessHandleSuspend"));
    assert!(implementation.contains("pub fn suspend_current_process()"));
    assert!(!implementation.contains("SIGTSTP"));
    assert!(!implementation.contains("SIGTTIN"));
    assert!(!implementation.contains("SIGTTOU"));

    let protocol = include_str!("../../../user/crates/posix-protocol/src/lib.rs");
    assert!(!protocol.contains("OP_PROCESS_SUSPEND"));

    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("posix_protocol::SIGNAL_TSTP"));
    assert!(runtime.contains("posix_protocol::SIGNAL_TTIN"));
    assert!(runtime.contains("posix_protocol::SIGNAL_TTOU"));
    let report = runtime
        .find(".report_process_stopped(delivery)")
        .expect("default stop action must report authenticated process state");
    assert!(runtime.contains("PosixClientError::Remote(posix_protocol::STATUS_EAGAIN)"));
    assert!(
        !runtime[report..report + 256.min(runtime.len() - report)]
            .contains("ProcessSuspendCurrent")
    );
    assert!(runtime.contains(".report_process_signaled(delivery)"));
    assert!(runtime.contains(".complete_signal_delivery(delivery)"));

    let service = include_str!("../src/main.rs");
    assert!(service.contains("platform::process::suspend_handle(process)"));
    assert!(service.contains("platform::process::terminate_handle(process, exit_code)"));

    let native_process_control = include_str!("../../../core/src/syscall/handle.rs");
    assert!(!native_process_control.contains("WTERMSIG"));
    assert!(!native_process_control.contains("SIGCHLD"));
}

#[test]
fn suspension_preserves_wait_state_and_resume_does_not_wake_blocked_threads() {
    let thread = include_str!("../../../core/src/task/thread.rs");
    let handle = include_str!("../../../core/src/syscall/handle.rs");
    assert!(thread.contains("scheduling_suspended: bool"));
    assert!(thread.contains("thread.state() == ThreadState::Ready"));
    assert!(thread.contains("&& !thread.is_scheduling_suspended()"));
    assert!(thread.contains("THREAD_QUEUE.lock().resume_process(process_id)"));
    assert!(handle.contains("crate::task::resume_process_threads(process_id)"));
    assert!(!handle.contains("for thread in threads {\n        crate::task::wake_thread(thread);"));
    assert!(!thread.contains("ThreadState::Suspended"));

    let service = include_str!("../src/main.rs");
    assert!(service.contains("mochi_user_platform::process::resume_handle(process)"));
    assert!(service.contains("service.apply_process_resume(process_id, processes)"));

    let native_handles = include_str!("../../../core/src/syscall/handle.rs");
    assert!(native_handles.contains("crate::capability::Capability::ProcessKill"));
    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("\"process.kill\""));
}

#[test]
fn child_exit_notification_waits_on_generic_process_handles() {
    let service = include_str!("../src/main.rs");
    assert!(service.contains("service.refresh_child_exit_notifications(&mut processes)"));
    assert!(service.contains("let lifecycle_handles = service.child_lifecycle_handles();"));
    assert!(service.contains("for handle in lifecycle_handles"));
    assert!(service.contains("interests: syscall::HANDLE_SIGNAL_TERMINATED"));

    let kernel = include_str!("../../../core/src/syscall/handle.rs");
    assert!(!kernel.contains("SIGNAL_CHLD"));
    assert!(!kernel.contains("SIGCHLD"));
}
