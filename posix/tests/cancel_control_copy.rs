#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn cancellation_settings_commit_only_after_checked_output_and_preserve_pending_cancellation() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code,non_camel_case_types)]
use std::ffi::c_int;
use std::sync::atomic::{{AtomicU32,Ordering}};
extern crate self as mochios_posix_client;
#[path={:?}]pub mod upcall_guard;
const EINVAL:i32=22;const EAGAIN:i32=11;const ENOSYS:i32=88;const ENOTSUP:i32=134;
const EFAULT:i32=14;const EIO:i32=5;const EOVERFLOW:i32=139;
const PTHREAD_CANCEL_ENABLE:u32=0;const PTHREAD_CANCEL_DISABLE:u32=1;
const PTHREAD_CANCEL_DEFERRED:u32=0;const PTHREAD_CANCEL_ASYNCHRONOUS:u32=1;
struct ThreadControl{{
 cancel_state:AtomicU32,cancel_type:AtomicU32,cancel_pending:AtomicU32,
 native_delivery_defer:AtomicU32,
 signal_upcall_stack:AtomicU32,
}}
static CONTROL:ThreadControl=ThreadControl{{
 cancel_state:AtomicU32::new(0),cancel_type:AtomicU32::new(0),
 cancel_pending:AtomicU32::new(1),native_delivery_defer:AtomicU32::new(0),
 signal_upcall_stack:AtomicU32::new(4096),
}};
mod cancellation {{ pub fn test_async() {{}} }}
static REGISTER:AtomicU32=AtomicU32::new(1);
static COPY_ERROR:AtomicU32=AtomicU32::new(0);
static COPIES:AtomicU32=AtomicU32::new(0);
static EXPECTED_STATE:AtomicU32=AtomicU32::new(0);
static EXPECTED_TYPE:AtomicU32=AtomicU32::new(0);
static EXPECTED_DEPTH:AtomicU32=AtomicU32::new(1);
fn register_current_thread()->Option<((),&'static ThreadControl)>{{
 (REGISTER.load(Ordering::Acquire)!=0).then_some(((),&CONTROL))
}}
mod user_copy{{pub fn write(output:*mut u8,bytes:&[u8])->Result<(),i32>{{
 use super::*;
 assert_eq!(CONTROL.cancel_state.load(Ordering::Acquire),EXPECTED_STATE.load(Ordering::Acquire));
 assert_eq!(CONTROL.cancel_type.load(Ordering::Acquire),EXPECTED_TYPE.load(Ordering::Acquire));
 assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),EXPECTED_DEPTH.load(Ordering::Acquire));
 COPIES.fetch_add(1,Ordering::AcqRel);
 let error=COPY_ERROR.load(Ordering::Acquire) as i32;
 if error!=0{{return Err(error)}}
 // Native MemoryCopy is controlled here. Only test-owned writable storage
 // reaches this copy; a fault is returned without dereferencing its pointer.
 unsafe{{std::ptr::copy_nonoverlapping(bytes.as_ptr(),output,bytes.len())}};Ok(())
}}}}
"#,
        root.join("user/crates/posix-client/src/upcall_guard.rs"),
    );
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    program.push_str(probe::between(
        source,
        "fn update_cancel_control(",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn pthread_cancel(",
    ));
    program.push_str(
        r#"
fn reset(state:u32,kind:u32,depth:u32){
 CONTROL.cancel_state.store(state,Ordering::Release);
 CONTROL.cancel_type.store(kind,Ordering::Release);
 CONTROL.cancel_pending.store(1,Ordering::Release);
 CONTROL.native_delivery_defer.store(depth,Ordering::Release);
 EXPECTED_STATE.store(state,Ordering::Release);EXPECTED_TYPE.store(kind,Ordering::Release);
 EXPECTED_DEPTH.store(depth.saturating_add(1),Ordering::Release);
 REGISTER.store(1,Ordering::Release);COPY_ERROR.store(0,Ordering::Release);COPIES.store(0,Ordering::Release);
}
fn main(){
 for depth in [0,1,7] {
  for state in [0,1] {
   for change_type in [false,true] {
    reset(state,0,depth);
    let mut output=[0xa5;8]; // Deliberately unaligned C output.
    let pointer=unsafe{output.as_mut_ptr().add(1)}.cast::<c_int>();
    let result=unsafe{if change_type{pthread_setcanceltype(0,pointer)}else{pthread_setcancelstate((1-state) as i32,pointer)}};
    assert_eq!(result,0);assert_eq!(COPIES.load(Ordering::Acquire),1);
    assert_eq!(&output[1..5],&(if change_type{0i32}else{state as i32}).to_ne_bytes());
    assert_eq!((output[0],output[5],output[6],output[7]),(0xa5,0xa5,0xa5,0xa5));
    assert_eq!(CONTROL.cancel_state.load(Ordering::Acquire),if change_type{state}else{1-state});
    assert_eq!(CONTROL.cancel_type.load(Ordering::Acquire),0);
    assert_eq!(CONTROL.cancel_pending.load(Ordering::Acquire),1);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),depth);
    for error in [EFAULT,EIO] {
     reset(state,0,depth);COPY_ERROR.store(error as u32,Ordering::Release);
     let result=unsafe{if change_type{pthread_setcanceltype(0,1usize as *mut c_int)}else{pthread_setcancelstate((1-state) as i32,1usize as *mut c_int)}};
     assert_eq!(result,error);
     assert_eq!(CONTROL.cancel_state.load(Ordering::Acquire),state);
     assert_eq!(CONTROL.cancel_type.load(Ordering::Acquire),0);
     assert_eq!(CONTROL.cancel_pending.load(Ordering::Acquire),1);
     assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),depth);
    }
   }
  }
 }
 reset(1,0,0);COPY_ERROR.store(EFAULT as u32,Ordering::Release);
 assert_eq!(unsafe{pthread_setcancelstate(0,std::ptr::null_mut())},0);
 assert_eq!(unsafe{pthread_setcanceltype(0,std::ptr::null_mut())},0);
 assert_eq!(COPIES.load(Ordering::Acquire),0);
 assert_eq!(CONTROL.cancel_pending.load(Ordering::Acquire),1);
 reset(1,0,0);let mut previous=77;
 assert_eq!(unsafe{pthread_setcancelstate(99,&mut previous)},EINVAL);
 assert_eq!(unsafe{pthread_setcanceltype(99,&mut previous)},EINVAL);
 CONTROL.signal_upcall_stack.store(0,Ordering::Release);
 assert_eq!(unsafe{pthread_setcanceltype(1,&mut previous)},ENOTSUP);
 CONTROL.signal_upcall_stack.store(4096,Ordering::Release);
 REGISTER.store(0,Ordering::Release);
 assert_eq!(unsafe{pthread_setcancelstate(0,&mut previous)},EAGAIN);
 assert_eq!(unsafe{pthread_setcanceltype(0,&mut previous)},EAGAIN);
 assert_eq!(previous,77);assert_eq!(COPIES.load(Ordering::Acquire),0);
 assert_eq!(CONTROL.cancel_state.load(Ordering::Acquire),1);
 reset(1,0,u32::MAX);
 assert_eq!(unsafe{pthread_setcancelstate(0,&mut previous)},EOVERFLOW);
 assert_eq!(unsafe{pthread_setcanceltype(0,&mut previous)},EOVERFLOW);
 assert_eq!(previous,77);assert_eq!(COPIES.load(Ordering::Acquire),0);
 assert_eq!(CONTROL.cancel_state.load(Ordering::Acquire),1);
 assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),u32::MAX);
}
"#,
    );
    probe::run(&program);
}
