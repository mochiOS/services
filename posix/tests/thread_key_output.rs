#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;
#[path = "support/thread_key_lifecycle.rs"]
mod lifecycle;

#[test]
fn failed_key_output_releases_reservation_without_publishing_destructor() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code,non_camel_case_types)]
use std::ffi::{{c_int,c_void}};
use std::sync::atomic::{{AtomicU32,AtomicUsize,Ordering}};
extern crate self as mochios_posix_client;
#[path={:?}]pub mod thread;
#[path={:?}]pub mod upcall_guard;
type PthreadKey=u32;
type PthreadKeyDestructor=unsafe extern "C" fn(*mut c_void);
const EINVAL:i32=22;const EAGAIN:i32=11;const EFAULT:i32=14;const EIO:i32=5;
const THREAD_KEY_FREE:u32=0;const THREAD_KEY_INITIALIZING:u32=1;const THREAD_KEY_ALLOCATED:u32=2;
static DEFER:AtomicU32=AtomicU32::new(0);
static ERROR:AtomicU32=AtomicU32::new(0);
static COPIES:AtomicUsize=AtomicUsize::new(0);
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{
 Some(upcall_guard::Guard::enter(&DEFER).unwrap())
}}
mod user_copy{{pub fn write(output:*mut u8,bytes:&[u8])->Result<(),i32>{{
 use super::*;
 assert_eq!(DEFER.load(Ordering::Acquire),1);
 assert_eq!(THREAD_KEYS[0].allocated.load(Ordering::Acquire),THREAD_KEY_INITIALIZING);
 assert!(matches!(lifecycle_runtime::capture(),Err(EAGAIN)),"reserved key must exclude fork capture");
 COPIES.fetch_add(1,Ordering::Relaxed);
 let error=ERROR.load(Ordering::Acquire) as i32;
 if error!=0{{return Err(error)}}
 unsafe{{std::ptr::copy_nonoverlapping(bytes.as_ptr(),output,bytes.len())}};Ok(())
}}}}
"#,
        root.join("user/crates/posix-client/src/thread.rs"),
        root.join("user/crates/posix-client/src/upcall_guard.rs"),
    );
    lifecycle::append(&mut program);
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    program.push_str(probe::between(
        source,
        "struct ThreadKeyControl {",
        "#[repr(C)]",
    ));
    program.push_str("static THREAD_KEYS:[ThreadKeyControl;1]=[ThreadKeyControl::new()];");
    program.push_str(probe::between(
        source,
        "fn thread_key_control(",
        "fn run_thread_specific_destructors(",
    ));
    program.push_str(probe::between(
        source,
        "pub unsafe extern \"C\" fn pthread_key_create(",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn pthread_setspecific(",
    ));
    program.push_str(
        r#"
unsafe extern "C" fn destructor(_: *mut c_void){panic!("callback must not execute")}
fn main(){
 assert_eq!(unsafe{pthread_key_create(std::ptr::null_mut(),None)},EINVAL);
 assert_eq!(COPIES.load(Ordering::Acquire),0);
 for error in [EFAULT,EIO] {
  ERROR.store(error as u32,Ordering::Release);
  for _ in 0..100 {
   assert_eq!(unsafe{pthread_key_create(1usize as *mut PthreadKey,Some(destructor))},error);
   assert_eq!(THREAD_KEYS[0].allocated.load(Ordering::Acquire),THREAD_KEY_FREE);
   assert_eq!(THREAD_KEYS[0].destructor.load(Ordering::Acquire),0);
   assert_eq!(DEFER.load(Ordering::Acquire),0);
   assert!(lifecycle_runtime::capture().is_ok(),"failed output must release snapshot exclusion");
  }
 }
 ERROR.store(0,Ordering::Release);
 let mut output=[0xa5u8;8];
 let pointer=unsafe{output.as_mut_ptr().add(1)}.cast::<PthreadKey>();
 assert_eq!(unsafe{pthread_key_create(pointer,Some(destructor))},0);
 let key=u32::from_ne_bytes(output[1..5].try_into().unwrap());
 assert!(thread_key_control(key).is_some());
 assert_eq!(THREAD_KEYS[0].destructor.load(Ordering::Acquire),destructor as *const () as usize);
 assert_eq!((output[0],output[5],output[6],output[7]),(0xa5,0xa5,0xa5,0xa5));
 let copies=COPIES.load(Ordering::Acquire);
 assert_eq!(unsafe{pthread_key_create(pointer,None)},EAGAIN);
 assert_eq!(COPIES.load(Ordering::Acquire),copies);
 assert_eq!(pthread_key_delete(key),0);
 assert_eq!(DEFER.load(Ordering::Acquire),0);
 assert!(lifecycle_runtime::capture().is_ok());
}
"#,
    );
    probe::run(&program);
}
