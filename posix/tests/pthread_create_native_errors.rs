//! Execute the native-creation tail of pthread_create, including the production
//! status conversion. Earlier stack/reent preparation has separate tests.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn pthread_create_maps_resource_failure_and_releases_control_before_returning() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = probe::program();
    program.push_str("const STATUS_EIO:i32=-5; const STATUS_EAGAIN:i32=-11;\n");
    program.push_str("mod wire_status {use crate::mnu_abi;\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs").replace("//!", "//"),
    );
    program.push_str("}\nmod newlib_errno {use crate::wire_status as mochios_posix_protocol;\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-client/src/newlib_errno.rs")
            .replace("//!", "//")
            .replace("mochios_posix_protocol::status::", "mochios_posix_protocol::"),
    );
    program.push_str("}\n");
    program.push_str(
        r#"
use std::sync::atomic::{AtomicU32,AtomicU64,Ordering};
use std::cell::Cell;
use newlib_errno::{ENOMEM,EAGAIN};
type c_int=i32;
const THREAD_REAPING:u32=5;
struct ThreadControl {state:AtomicU32,native_id:AtomicU64}
thread_local! {
    static RESPONSE:Cell<u64>=const{Cell::new(0)};
    static RELEASES:Cell<usize>=const{Cell::new(0)};
    static CALLS:Cell<usize>=const{Cell::new(0)};
}
fn release_thread_control(control:&ThreadControl){
    assert_eq!(control.state.load(Ordering::Relaxed),THREAD_REAPING);
    RELEASES.set(RELEASES.get()+1);
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
        crate::CALLS.set(crate::CALLS.get()+1);RawSyscallResult::new(crate::RESPONSE.get())
    }
}
"#,
    );
    program.push_str(probe::between(
        runtime,
        "fn syscall_errno(",
        "fn result_with_errno",
    ));
    program.push_str("unsafe fn finish(thread:*mut usize,control:&ThreadControl,token:usize,context:syscall::ThreadCreateContext)->i32{\n");
    let create = probe::between(
        runtime,
        "pub unsafe extern \"C\" fn pthread_create(",
        "pub unsafe extern \"C\" fn pthread_join(",
    );
    let tail = &create[create
        .find("    let native_id = match syscall_errno(")
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
        RESPONSE.set(error.into_raw());RELEASES.set(0);CALLS.set(0);
        let control=ThreadControl{state:AtomicU32::new(2),native_id:AtomicU64::new(0)};
        let mut output=0xdead;
        assert_eq!(unsafe{finish(&mut output,&control,41,Default::default())},expected);
        assert_eq!(RELEASES.get(),1);assert_eq!(CALLS.get(),1);
        assert_eq!(output,0xdead);assert_eq!(control.native_id.load(Ordering::Relaxed),0);
    }
    // A child may publish its native identity before the parent resumes.
    for existing in [0,19] {
        RESPONSE.set(19);RELEASES.set(0);CALLS.set(0);
        let control=ThreadControl{state:AtomicU32::new(2),native_id:AtomicU64::new(existing)};
        let mut output=0xdead;
        assert_eq!(unsafe{finish(&mut output,&control,41,Default::default())},0);
        assert_eq!(output,41);assert_eq!(control.native_id.load(Ordering::Relaxed),19);
        assert_eq!(control.state.load(Ordering::Relaxed),2);
        assert_eq!(RELEASES.get(),0);assert_eq!(CALLS.get(),1);
    }
}
"#,
    );
    probe::run(&program);
}
