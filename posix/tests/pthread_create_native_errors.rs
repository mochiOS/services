//! Execute the native-creation tail of pthread_create, including the production
//! status conversion and reclamation of a child that exits before creation
//! returns. Earlier stack/reent preparation has separate tests.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn pthread_create_maps_resource_failure_and_releases_control_before_returning() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = probe::program();
    probe::constants(
        &mut program,
        runtime,
        &[
            "THREAD_FREE",
            "THREAD_REAPING",
            "THREAD_EXITED",
            "THREAD_DETACHED",
            "THREAD_REAP_CLAIMED",
            "THREAD_RUNNING",
        ],
    );
    program.push_str(
        runtime
            .lines()
            .find(|line| line.starts_with("type Pthread ="))
            .unwrap(),
    );
    program.push('\n');
    program.push_str("const STATUS_EIO:i32=-5; const STATUS_EAGAIN:i32=-11;\n");
    program.push_str("mod wire_status {use crate::mnu_abi;\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs").replace("//!", "//"),
    );
    program.push_str("}\nmod newlib_errno {use crate::wire_status as mochios_posix_protocol;\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-client/src/newlib_errno.rs")
            .replace("//!", "//")
            .replace(
                "mochios_posix_protocol::status::",
                "mochios_posix_protocol::",
            ),
    );
    program.push_str("}\n");
    program.push_str(
        r#"
use std::sync::atomic::{AtomicU32,AtomicU64,Ordering};
use std::cell::Cell;
use newlib_errno::{ENOMEM,EAGAIN};
type c_int=i32;
struct ThreadControl {state:AtomicU32,native_id:AtomicU64,creation_pending:AtomicU32,joinability:JoinState}
static THREADS:[ThreadControl;1]=[ThreadControl{state:AtomicU32::new(2),native_id:AtomicU64::new(0),creation_pending:AtomicU32::new(1),joinability:JoinState(AtomicU32::new(1))}];
thread_local! {
    static RESPONSE:Cell<u64>=const{Cell::new(0)};
    static RELEASES:Cell<usize>=const{Cell::new(0)};
    static CALLS:Cell<usize>=const{Cell::new(0)};
    static COPY_ERROR:Cell<Option<i32>>=const{Cell::new(None)};
    static COPIES:Cell<usize>=const{Cell::new(0)};
    static FAST_EXIT:Cell<bool>=const{Cell::new(false)};
    static REUSE_ON_CLAIM:Cell<bool>=const{Cell::new(false)};
}
fn release_thread_control(control:&ThreadControl){
    assert_eq!(control.state.load(Ordering::Relaxed),THREAD_REAPING);
    RELEASES.set(RELEASES.get()+1);
    control.creation_pending.store(0,Ordering::Release);
    control.state.store(0,Ordering::Release);
}
struct JoinState(AtomicU32);
impl JoinState {
    fn store(&self,value:u32,order:Ordering){self.0.store(value,order)}
    fn compare_exchange(&self,old:u32,new:u32,success:Ordering,failure:Ordering)->Result<u32,u32>{
        if REUSE_ON_CLAIM.replace(false) {
            // Another reaper completes and a new fast child exits between
            // this reaper's initial observation and its claim operation.
            let control=&THREADS[0];control.native_id.store(29,Ordering::Release);
            control.creation_pending.store(1,Ordering::Release);
            control.state.store(THREAD_EXITED,Ordering::Release);
            self.0.store(THREAD_DETACHED,Ordering::Release);
        }
        self.0.compare_exchange(old,new,success,failure)
    }
}
fn native_thread_retired(control: &ThreadControl)->Result<bool,i32>{
    assert_eq!(control.creation_pending.load(Ordering::Acquire),0);Ok(true)
}
mod user_copy {
    pub fn write(destination:*mut u8, bytes:&[u8])->Result<(),i32>{
        assert_eq!(bytes.len(),size_of::<crate::Pthread>());
        assert_eq!(crate::CALLS.get(),0);crate::COPIES.set(crate::COPIES.get()+1);
        if let Some(error)=crate::COPY_ERROR.get(){return Err(error)}
        unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),destination,bytes.len())};Ok(())
    }
}
fn map_kernel_errno(raw:i64)->i32{newlib_errno::from_status(raw)}
mod syscall {
    use crate::mnu_abi;
    pub use crate::mochi_user_syscall::*;
    pub enum SyscallNumber{ThreadCreate}
    #[repr(C)] pub struct ThreadCreateContext([u64;22]);
    impl Default for ThreadCreateContext {fn default()->Self{Self([0;22])}}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct RawSyscallResult",
        "#[inline(always)]",
    ));
    program.push_str(
        r#"
    pub fn raw_syscall2(number:SyscallNumber,pointer:u64,length:u64)->RawSyscallResult{
        assert!(matches!(number,SyscallNumber::ThreadCreate));
        assert_ne!(pointer,0);assert_eq!(length,176);
        assert_eq!(crate::COPIES.get(),1);
        assert_eq!(crate::THREADS[0].creation_pending.load(crate::Ordering::Acquire),1);
        crate::CALLS.set(crate::CALLS.get()+1);
        if crate::FAST_EXIT.get(){
            let control=&crate::THREADS[0];
            control.native_id.store(19,crate::Ordering::Release);
            control.state.store(crate::THREAD_EXITED,crate::Ordering::Release);
            crate::reap_detached_threads();
            assert_eq!(crate::RELEASES.get(),0,"reaped while creator still uses TCB");
            assert_eq!(control.state.load(crate::Ordering::Acquire),crate::THREAD_EXITED);
        }
        RawSyscallResult::new(crate::RESPONSE.get())
    }
}
"#,
    );
    program.push_str(probe::between(
        runtime,
        "fn syscall_errno(",
        "fn result_with_errno",
    ));
    program.push_str(probe::between(
        runtime,
        "fn reap_detached_threads()",
        "fn current_thread_control()",
    ));
    program.push_str("unsafe fn finish(thread:*mut Pthread,control:&ThreadControl,token:Pthread,context:syscall::ThreadCreateContext)->i32{\n");
    let create = probe::between(
        runtime,
        "pub unsafe extern \"C\" fn pthread_create(",
        "pub unsafe extern \"C\" fn pthread_join(",
    );
    let tail = &create[create
        .find("    // Complete the only faultable publication")
        .unwrap()..];
    program.push_str(&tail[..tail.find("\n#[unsafe(no_mangle)]").unwrap()]);
    program.push_str(
        r#"
fn main(){
    use mnu_abi::status::Error;
    for (error,expected) in [
        (Error::ResourceUnavailable,EAGAIN),(Error::NotReady,EAGAIN),
        (Error::InvalidArgument,newlib_errno::EINVAL),
        (Error::InvalidAddress,newlib_errno::EFAULT),
        (Error::AccessDenied,newlib_errno::EACCES),
        (Error::BackingFailure,newlib_errno::EIO),
    ] {
        RESPONSE.set(error.into_raw());RELEASES.set(0);CALLS.set(0);COPIES.set(0);
        let control=&THREADS[0];control.state.store(2,Ordering::Release);
        control.native_id.store(0,Ordering::Release);control.creation_pending.store(1,Ordering::Release);
        let mut output=0xdead;
        assert_eq!(unsafe{finish(&mut output,&control,41,Default::default())},expected);
        assert_eq!(RELEASES.get(),1);assert_eq!(CALLS.get(),1);
        assert_eq!(output,41);assert_eq!(control.native_id.load(Ordering::Relaxed),0);
    }
    // A child may publish its native identity before the parent resumes.
    for existing in [0,19] {
        RESPONSE.set(19);RELEASES.set(0);CALLS.set(0);COPIES.set(0);
        let control=&THREADS[0];control.state.store(2,Ordering::Release);
        control.native_id.store(existing,Ordering::Release);control.creation_pending.store(1,Ordering::Release);
        let mut output=0xdead;
        assert_eq!(unsafe{finish(&mut output,&control,41,Default::default())},0);
        assert_eq!(output,41);assert_eq!(control.native_id.load(Ordering::Relaxed),19);
        assert_eq!(control.state.load(Ordering::Relaxed),2);
        assert_eq!(RELEASES.get(),0);assert_eq!(CALLS.get(),1);
        assert_eq!(control.creation_pending.load(Ordering::Acquire),0);
    }
    // A failed checked output never admits a native child, and releases the
    // same prepared resources as native admission failure.
    for error in [14,5,12] {
        RELEASES.set(0);CALLS.set(0);COPIES.set(0);COPY_ERROR.set(Some(error));
        let control=&THREADS[0];control.state.store(2,Ordering::Release);
        control.native_id.store(0,Ordering::Release);control.creation_pending.store(1,Ordering::Release);
        let mut output=0xdead;
        assert_eq!(unsafe{finish(&mut output,control,41,Default::default())},error);
        assert_eq!(output,0xdead);assert_eq!(CALLS.get(),0);assert_eq!(COPIES.get(),1);
        assert_eq!(RELEASES.get(),1);assert_eq!(control.creation_pending.load(Ordering::Acquire),0);
    }
    COPY_ERROR.set(None);RESPONSE.set(19);FAST_EXIT.set(true);
    RELEASES.set(0);CALLS.set(0);COPIES.set(0);
    let control=&THREADS[0];control.state.store(2,Ordering::Release);
    control.native_id.store(0,Ordering::Release);control.creation_pending.store(1,Ordering::Release);
    control.joinability.store(THREAD_DETACHED,Ordering::Release);
    let mut output=0xdead;
    assert_eq!(unsafe{finish(&mut output,control,41,Default::default())},0);
    assert_eq!(output,41);assert_eq!(RELEASES.get(),0);
    assert_eq!(control.creation_pending.load(Ordering::Acquire),0);
    assert_eq!(control.native_id.load(Ordering::Acquire),19);
    reap_detached_threads();assert_eq!(RELEASES.get(),1);
    reap_detached_threads();assert_eq!(RELEASES.get(),1);
    RELEASES.set(0);control.state.store(THREAD_EXITED,Ordering::Release);
    control.creation_pending.store(0,Ordering::Release);
    control.joinability.store(THREAD_DETACHED,Ordering::Release);
    REUSE_ON_CLAIM.set(true);reap_detached_threads();
    assert_eq!(RELEASES.get(),0);assert_eq!(control.native_id.load(Ordering::Acquire),29);
    assert_eq!(control.creation_pending.load(Ordering::Acquire),1);
    control.creation_pending.store(0,Ordering::Release);
    reap_detached_threads();assert_eq!(RELEASES.get(),1);
}
"#,
    );
    probe::run(&program);
}
