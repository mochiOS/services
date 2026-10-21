//! Execute the actual wrapper and alternate-stack state; inject boundary I/O.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn sigaltstack_faults_restore_masks_and_never_borrow_application_pointers() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/signal_stack.rs");
    let context = include_str!("../../../user/crates/posix-client/src/signal_context.rs");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let declaration = probe::between(context, "pub struct Stack {", "\n}\n");
    let mut program = String::from(
        r#"#![allow(dead_code,non_camel_case_types)]
use core::ffi::c_int;
use std::sync::atomic::{AtomicBool,AtomicI32,AtomicU64,AtomicUsize,Ordering};
const EINVAL:i32=22;const EFAULT:i32=14;const EIO:i32=5;
const EAGAIN:i32=11;const EPERM:i32=1;const ENOMEM:i32=12;
pub mod signal_context {
#[repr(C)] #[derive(Clone,Copy,Debug,PartialEq,Eq)]
"#,
    );
    program.push_str(declaration);
    program.push_str("\n}\n}\nuse signal_context::Stack;\n");
    program.push_str(&format!(
        "#[path={:?}] mod stack;\n",
        root.join("user/crates/posix-client/src/signal_stack.rs")
    ));
    program.push_str("mod posix_protocol {\n");
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["SIGNAL_MASK_BLOCK", "SIGNAL_MASK_SET"],
    );
    program.push_str(r#"
}
struct ThreadControl{alternate_stack:stack::AlternateStack}
static CONTROL:ThreadControl=ThreadControl{alternate_stack:stack::AlternateStack::new()};
static NO_THREAD:AtomicBool=AtomicBool::new(false);
static MASK:AtomicU64=AtomicU64::new(0x24);
static CALLS:AtomicUsize=AtomicUsize::new(0);
static FAILURE:AtomicUsize=AtomicUsize::new(0);
static ERRNO:AtomicI32=AtomicI32::new(123);
fn register_current_thread()->Option<(u64,&'static ThreadControl)>{
if NO_THREAD.load(Ordering::SeqCst){None}else{Some((1,&CONTROL))}}
fn service_signal_mask(_:&ThreadControl,operation:u32,value:u64)->Result<u64,i32>{
CALLS.fetch_add(1,Ordering::SeqCst);
if operation==posix_protocol::SIGNAL_MASK_BLOCK {
assert_eq!(value,u64::MAX);
if FAILURE.load(Ordering::SeqCst)==1{return Err(EIO)}
Ok(MASK.fetch_or(value,Ordering::SeqCst))
}else{
assert_eq!(operation,posix_protocol::SIGNAL_MASK_SET);
if FAILURE.load(Ordering::SeqCst)==2{return Err(EIO)}
Ok(MASK.swap(value,Ordering::SeqCst))
}}
fn result_with_errno(value:Result<i32,i32>,failure:i32)->i32{
match value{Ok(value)=>value,Err(error)=>{ERRNO.store(error,Ordering::SeqCst);failure}}}
mod signal_memory{
use super::*;
pub fn read_stack(source:*const Stack)->Result<Stack,i32>{
if source.addr()<4096||source.addr().checked_add(core::mem::size_of::<Stack>()).is_none(){return Err(EFAULT)}
// Only known, valid test-owned buffers reach the controlled copy transport.
Ok(unsafe{source.read_unaligned()})
}
pub fn write_stack(destination:*mut Stack,value:Stack)->Result<(),i32>{
assert_eq!(MASK.load(Ordering::SeqCst),u64::MAX,"copyout must precede mask restore");
if destination.addr()<4096||destination.addr().checked_add(core::mem::size_of::<Stack>()).is_none(){return Err(EFAULT)}
unsafe{destination.write_unaligned(value)};Ok(())
}}
fn reset(){CONTROL.alternate_stack.reset();MASK.store(0x24,Ordering::SeqCst);
CALLS.store(0,Ordering::SeqCst);FAILURE.store(0,Ordering::SeqCst);NO_THREAD.store(false,Ordering::SeqCst);ERRNO.store(123,Ordering::SeqCst);}
"#);
    program.push_str(probe::between(runtime, "fn error(", "#[unsafe(no_mangle)]"));
    program.push_str(probe::between(
        runtime,
        "pub unsafe extern \"C\" fn sigaltstack(",
        "\nstruct Invocation",
    ));
    program.push_str(r#"
fn main(){unsafe{
let disabled=Stack{ss_sp:0,ss_flags:stack::SS_DISABLE,ss_size:0};
let first=Stack{ss_sp:0x10000,ss_flags:0,ss_size:8192};
let second=Stack{ss_sp:0x20000,ss_flags:0,ss_size:16384};
for invalid in [1usize,usize::MAX] {
 reset();let mut previous=first;
 assert_eq!(sigaltstack(invalid as *const Stack,&mut previous),-1);
 assert_eq!(ERRNO.load(Ordering::SeqCst),EFAULT);assert_eq!(previous,first);
 assert_eq!(CALLS.load(Ordering::SeqCst),0);assert_eq!(MASK.load(Ordering::SeqCst),0x24);
 assert_eq!(CONTROL.alternate_stack.snapshot(0),disabled);
 assert_eq!(sigaltstack(core::ptr::null(),invalid as *mut Stack),-1);
 assert_eq!(ERRNO.load(Ordering::SeqCst),EFAULT);assert_eq!(MASK.load(Ordering::SeqCst),0x24);
 assert_eq!(CALLS.load(Ordering::SeqCst),2);
 // Commit of the replacement precedes optional old-value copyout failure.
 assert_eq!(sigaltstack(&first,invalid as *mut Stack),-1);
 assert_eq!(CONTROL.alternate_stack.snapshot(0),first);
 assert_eq!(MASK.load(Ordering::SeqCst),0x24);
}
reset();let mut previous=first;
assert_eq!(sigaltstack(&first,&mut previous),0);assert_eq!(previous,disabled);
assert_eq!(ERRNO.load(Ordering::SeqCst),123);assert_eq!(MASK.load(Ordering::SeqCst),0x24);
let mut aliased=second;let pointer=&mut aliased as *mut Stack;
assert_eq!(sigaltstack(pointer,pointer),0);assert_eq!(aliased,first);
assert_eq!(CONTROL.alternate_stack.snapshot(0),second);
for (request,error) in [(Stack{ss_flags:8,..first},EINVAL),(Stack{ss_size:stack::MIN_SIZE-1,..first},ENOMEM)]{
 previous=disabled;assert_eq!(sigaltstack(&request,&mut previous),-1);
 assert_eq!(ERRNO.load(Ordering::SeqCst),error);assert_eq!(previous,disabled);
 assert_eq!(CONTROL.alternate_stack.snapshot(0),second);assert_eq!(MASK.load(Ordering::SeqCst),0x24);
}
reset();NO_THREAD.store(true,Ordering::SeqCst);
assert_eq!(sigaltstack(&first,core::ptr::null_mut()),-1);
assert_eq!(ERRNO.load(Ordering::SeqCst),EAGAIN);assert_eq!(CALLS.load(Ordering::SeqCst),0);
reset();let here=stack::current_pointer();
CONTROL.alternate_stack.replace(Stack{ss_sp:here-1_048_576,ss_flags:0,ss_size:1_048_576},0).unwrap();
let before=CONTROL.alternate_stack.snapshot(0);previous=disabled;
assert_eq!(sigaltstack(&first,&mut previous),-1);
assert_eq!(ERRNO.load(Ordering::SeqCst),EPERM);assert_eq!(previous,disabled);
assert_eq!(CONTROL.alternate_stack.snapshot(0),before);assert_eq!(MASK.load(Ordering::SeqCst),0x24);
reset();FAILURE.store(1,Ordering::SeqCst);
assert_eq!(sigaltstack(&first,core::ptr::null_mut()),-1);
assert_eq!(ERRNO.load(Ordering::SeqCst),EIO);assert_eq!(CONTROL.alternate_stack.snapshot(0),disabled);
assert_eq!(MASK.load(Ordering::SeqCst),0x24);
reset();FAILURE.store(2,Ordering::SeqCst);
assert_eq!(sigaltstack(&first,core::ptr::null_mut()),-1);
assert_eq!(ERRNO.load(Ordering::SeqCst),EIO);assert_eq!(CONTROL.alternate_stack.snapshot(0),first);
assert_eq!(CALLS.load(Ordering::SeqCst),2);
}}
"#);
    probe::run(&program);
}
