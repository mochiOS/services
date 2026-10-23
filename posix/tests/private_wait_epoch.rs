#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_native_wait_bridge_rejects_retired_lifetimes_before_and_after_errors() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let bridge = probe::between(runtime, "fn wait_for_multiplex(\n", "fn select_deadline(");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../user/crates/posix-client/src/multiplex.rs");
    let mut program = format!(
        r#"
use std::cell::Cell;
use std::sync::atomic::{{AtomicU32,AtomicU64,Ordering}};
type c_int=i32;
const EINTR:i32=4;const EAGAIN:i32=11;const EIO:i32=5;
const PTHREAD_CANCEL_ENABLE:u32=0;
thread_local!{{
static VALID:Cell<bool>=const{{Cell::new(true)}};
static MODE:Cell<u32>=const{{Cell::new(0)}};
static CALLS:Cell<u32>=const{{Cell::new(0)}};
}}
struct ThreadControl{{cancel_state:AtomicU32,cancel_pending:AtomicU32,
caught_signal_generation:AtomicU64,multiplex_generation:AtomicU64}}
mod mochios_posix_client{{#[path="{}"]pub mod multiplex;}}
mod syscall{{
pub const HANDLE_WAIT_POLL:u64=0;pub const HANDLE_WAIT_INFINITE:u64=u64::MAX;
pub struct HandleWaitItem{{pub handle:u32}}
#[repr(C)]pub struct HandleWaitGuard{{pub address:u64,pub expected:u64}}
pub enum SyscallNumber{{HandleWaitManyGuarded}}
pub fn raw_syscall4(_:SyscallNumber,_:u64,count:u64,deadline:u64,guard:u64)->Result<u64,i32>{{
 use super::*;
 assert_eq!(count,1);assert_eq!(deadline,u64::MAX);
 assert_eq!(CALLS.replace(CALLS.get()+1),0,"stale reference reentered native wait");
 let guard=unsafe{{&*(guard as *const HandleWaitGuard)}};
 assert_ne!(guard.address,0);assert_eq!(guard.expected,0);
 match MODE.get(){{
 1=>{{VALID.set(false);Ok(0)}},
 2=>{{VALID.set(false);Err(EIO)}},
 3=>Err(EIO),4=>Ok(0),_=>panic!("retired lifetime entered kernel")
 }}
}}
}}
fn syscall_errno(result:Result<u64,i32>)->Result<u64,i32>{{result}}
fn monotonic_nanoseconds()->Result<u64,i32>{{panic!("infinite wait polled wall clock")}}
"#,
        path.display()
    );
    program.push_str(bridge);
    program.push_str(
        r#"
fn main(){
 let control=ThreadControl{cancel_state:AtomicU32::new(0),cancel_pending:AtomicU32::new(0),
 caught_signal_generation:AtomicU64::new(0),multiplex_generation:AtomicU64::new(0)};
 for mode in 0..=4 {
  MODE.set(mode);VALID.set(mode!=0);CALLS.set(0);
  let mut items=[syscall::HandleWaitItem{handle:7}];
  let result=wait_for_multiplex_while(&mut items,u64::MAX,&control,0,||VALID.get());
  assert_eq!(result,match mode{0|1|2=>Err(EINTR),3=>Err(EIO),_=>Ok(())});
  assert_eq!(CALLS.get(),u32::from(mode!=0));
 }
}
"#,
    );
    probe::run(&program);
}
