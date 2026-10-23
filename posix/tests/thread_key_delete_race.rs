#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn key_deletion_cannot_clear_a_destructor_installed_by_concurrent_slot_reuse() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = format!(
        r#"
#![allow(dead_code,non_camel_case_types)]
use std::ffi::{{c_int,c_void}};
use std::sync::{{OnceLock,Barrier,Arc}};
use std::sync::atomic::{{AtomicU32 as RealAtomicU32,AtomicUsize,Ordering}};
extern crate self as mochios_posix_client;
#[path={:?}]pub mod thread;
#[path={:?}]pub mod upcall_guard;
static DEFER:RealAtomicU32=RealAtomicU32::new(0);
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{
 Some(upcall_guard::Guard::enter(&DEFER).unwrap())
}}
type PthreadKey=u32;
type PthreadKeyDestructor=unsafe extern "C" fn(*mut c_void);
const EINVAL:i32=22;const EAGAIN:i32=11;
const THREAD_KEY_FREE:u32=0;const THREAD_KEY_INITIALIZING:u32=1;const THREAD_KEY_ALLOCATED:u32=2;
static PAUSED:OnceLock<Arc<Barrier>>=OnceLock::new();
static RESUME:OnceLock<Arc<Barrier>>=OnceLock::new();
thread_local!{{static ARMED:std::cell::Cell<bool>=const{{std::cell::Cell::new(false)}};}}
// These delegate to real atomics and pause only after the production deletion
// successfully claims a slot, making the reuse window deterministic.
struct AtomicU32(RealAtomicU32);
impl AtomicU32{{
 const fn new(value:u32)->Self{{Self(RealAtomicU32::new(value))}}
 fn load(&self,order:Ordering)->u32{{self.0.load(order)}}
 fn store(&self,value:u32,order:Ordering){{self.0.store(value,order)}}
 fn compare_exchange(&self,old:u32,new:u32,success:Ordering,failure:Ordering)->Result<u32,u32>{{
  let result=self.0.compare_exchange(old,new,success,failure);
  if result.is_ok() && old==THREAD_KEY_ALLOCATED && ARMED.replace(false){{
   assert_eq!(DEFER.load(Ordering::Acquire),1);
   PAUSED.get().unwrap().wait();RESUME.get().unwrap().wait();
  }}
  result
 }}
}}
"#,
        root.join("user/crates/posix-client/src/thread.rs"),
        root.join("user/crates/posix-client/src/upcall_guard.rs"),
    );
    program.push_str(probe::between(
        runtime,
        "struct ThreadKeyControl {",
        "#[repr(C)]",
    ));
    // One available slot is sufficient to isolate deletion/creation overlap.
    // The token codec and all lifecycle functions are production code.
    program.push_str("static THREAD_KEYS:[ThreadKeyControl;1]=[ThreadKeyControl::new()];\n");
    program.push_str(probe::between(
        runtime,
        "fn thread_key_control(",
        "fn run_thread_specific_destructors(",
    ));
    program.push_str(probe::between(
        runtime,
        "pub unsafe extern \"C\" fn pthread_key_create(",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn pthread_key_delete(",
    ));
    program.push_str(probe::between(
        runtime,
        "pub extern \"C\" fn pthread_key_delete(",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn pthread_setspecific(",
    ));
    program.push_str(
        r#"
static DESTRUCTORS:AtomicUsize=AtomicUsize::new(0);
unsafe extern "C" fn old_destructor(_: *mut c_void){panic!("old callback survived deletion")}
unsafe extern "C" fn new_destructor(value:*mut c_void){
 assert_eq!(value as usize,17);DESTRUCTORS.fetch_add(1,Ordering::AcqRel);
}
fn main(){
 PAUSED.set(Arc::new(Barrier::new(2))).unwrap();
 RESUME.set(Arc::new(Barrier::new(2))).unwrap();
 assert_eq!(pthread_key_delete(0),EINVAL);
 assert_eq!(DEFER.load(Ordering::Acquire),0);
 for iteration in 0..100 {
  let mut old=0;
  assert_eq!(unsafe{pthread_key_create(&mut old,Some(old_destructor))},0);
  let deleting=std::thread::spawn(move||{
   ARMED.set(true);assert_eq!(pthread_key_delete(old),0);
  });
  PAUSED.get().unwrap().wait();
  assert!(thread_key_control(old).is_none(),"key remains published while retiring");
  let mut unpublished=0xabcdef;
  let overlapping=unsafe{pthread_key_create(&mut unpublished,Some(new_destructor))};
  // Always resume/join, even when testing a regressed FREE-before-clear build.
  RESUME.get().unwrap().wait();deleting.join().unwrap();
  assert_eq!(DEFER.load(Ordering::Acquire),0);
  // Either overlap is rejected until retirement completes, or an implementation
  // may safely reuse a slot whose old callback has already been cleared.
  let new=if overlapping==0 {
   unpublished
  } else {
   assert_eq!(overlapping,EAGAIN);
   assert_eq!(unpublished,0xabcdef);
   let mut key=0;
   assert_eq!(unsafe{pthread_key_create(&mut key,Some(new_destructor))},0);
   key
  };
  assert_ne!(old,new);
  assert!(thread_key_control(old).is_none());
  let (_,control)=thread_key_control(new).unwrap();
  let callback=control.destructor.load(Ordering::Acquire);
  if cfg!(replay_prior_order) {
   assert_eq!(overlapping,0);
   assert_eq!(callback,0,"prior order did not reproduce the lost destructor");
   return;
  }
  assert_eq!(callback,new_destructor as *const () as usize);
  let callback:PthreadKeyDestructor=unsafe{std::mem::transmute(callback)};
  unsafe{callback(17usize as *mut c_void)};
  assert_eq!(DESTRUCTORS.load(Ordering::Acquire),iteration+1);
  assert_eq!(pthread_key_delete(new),0);
  assert_eq!(THREAD_KEYS[0].allocated.load(Ordering::Acquire),THREAD_KEY_FREE);
  assert_eq!(THREAD_KEYS[0].destructor.load(Ordering::Acquire),0);
 }
}
"#,
    );
    probe::run(&program);
    // Counterexample: replay only the previous FREE-before-clear ordering.
    // This must actually erase the replacement callback under the same
    // controlled interleaving, rather than merely asserting a source pattern.
    let prior = program.replacen(
        "THREAD_KEY_ALLOCATED,\n            THREAD_KEY_INITIALIZING,",
        "THREAD_KEY_ALLOCATED,\n            THREAD_KEY_FREE,",
        1,
    );
    assert_ne!(prior, program);
    let replay = prior.replacen(
        "    control.allocated.store(THREAD_KEY_FREE, Ordering::Release);\n    0\n}",
        "    0\n}",
        1,
    );
    assert_ne!(replay, prior);
    probe::run_with_cfg(&replay, "replay_prior_order");
}
