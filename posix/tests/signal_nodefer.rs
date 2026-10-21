use mochios_posix_client::signal::{self, SA_NODEFER, handler_mask, signal_bit};

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn nodefer_suppresses_only_automatic_self_blocking() {
    for number in 1..=31 {
        let own = signal_bit(number).unwrap();
        assert_eq!(handler_mask(number, 0, 0), Some(signal::sanitize_mask(own)));
        assert_eq!(handler_mask(number, 0, SA_NODEFER), Some(0));
        assert_eq!(
            handler_mask(number, own, SA_NODEFER),
            Some(signal::sanitize_mask(own))
        );
        assert_eq!(
            handler_mask(number, u64::MAX, SA_NODEFER),
            Some(signal::sanitize_mask(u64::MAX))
        );
    }
    for number in [0, 65, u32::MAX] {
        assert_eq!(handler_mask(number, 0, SA_NODEFER), None);
    }
}

#[test]
fn nested_handler_masks_restore_the_enclosing_mask_and_keep_explicit_self_blocks() {
    let own = signal_bit(30).unwrap();
    let other = signal_bit(31).unwrap();
    let before = signal_bit(2).unwrap();
    let mask = before | handler_mask(30, other, SA_NODEFER).unwrap();
    assert_eq!(mask & own, 0);
    assert_eq!(mask & other, other);
    let nested = mask | handler_mask(30, own, SA_NODEFER).unwrap();
    assert_eq!(nested & own, own);
    assert_eq!(
        signal::update_mask(nested, signal::SIGNAL_SET_MASK, mask),
        Some(mask)
    );
    assert_eq!(
        signal::update_mask(mask, signal::SIGNAL_SET_MASK, before),
        Some(before)
    );
}

#[test]
fn runtime_accepts_nodefer_without_accepting_unknown_or_misplaced_child_flags() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let gate = probe::between(
        runtime,
        "    if replacement.sa_flags",
        "    replacement.sa_mask =",
    );
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicI32,Ordering};
const EINVAL:i32=22;
const SA_NODEFER:i32=0x40000000;const SA_RESTART:i32=0x10000000;
const SA_RESETHAND:i32=i32::MIN;
const SA_SIGINFO:i32=4;const SA_ONSTACK:i32=8;
const SA_NOCLDSTOP:i32=1;const SA_NOCLDWAIT:i32=2;
mod posix_protocol{pub const SIGNAL_CHLD:u32=20;}
use core::ffi::c_int;
static ERRNO:AtomicI32=AtomicI32::new(0);
fn set_errno(value:i32){ERRNO.store(value,Ordering::Relaxed);}
struct Action{sa_flags:i32}
fn valid(signal:i32,flags:i32)->i32{let replacement=Action{sa_flags:flags};
"#,
    );
    program.push_str(gate);
    program.push_str(r#"
0}
fn main(){
for signal in [1,20,30] {
 for flags in [SA_NODEFER,SA_RESETHAND,SA_RESETHAND|SA_NODEFER,SA_NODEFER|SA_RESTART|SA_SIGINFO|SA_ONSTACK] {assert_eq!(valid(signal,flags),0);}
 assert_eq!(valid(signal,SA_NODEFER|0x20000000),-1);
 assert_eq!(ERRNO.load(Ordering::Relaxed),EINVAL);
 assert_eq!(valid(signal,SA_NODEFER|SA_NOCLDWAIT),if signal==20{0}else{-1});
}}
"#);
    probe::run(&program);
    let dispatch = probe::between(
        runtime,
        "fn dispatch_signal(",
        "fn apply_default_signal_action(",
    );
    assert!(dispatch.contains("mochios_posix_client::signal::handler_mask("));
    assert!(!dispatch.contains("action.sa_mask | current_signal"));
}

#[test]
fn c_header_exports_the_same_nodefer_bit_without_a_generated_sdk() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let header = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../user/libc-port/include/sys/_mochios_sigaction.h");
    let source = format!(
        "typedef void (*_sig_func_ptr)(int);\ntypedef unsigned long sigset_t;\n#include {:?}\n_Static_assert(SA_NODEFER == {}, \"SA_NODEFER ABI\");\n_Static_assert(SA_RESETHAND == {}, \"SA_RESETHAND ABI\");\n_Static_assert(sizeof(SA_RESETHAND) == sizeof(int), \"signed flag ABI\");\n",
        header, SA_NODEFER, signal::SA_RESETHAND
    );
    let mut compiler = Command::new("cc")
        .args(["-std=c11", "-x", "c", "-fsyntax-only", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rust_libc = include_str!("../../../libraries/libc/newlib/mochios.rs");
    assert!(rust_libc.contains("pub const SA_NODEFER: c_int = 0x4000_0000;"));
    assert!(rust_libc.contains("pub const SA_RESETHAND: c_int = c_int::MIN;"));
}

#[test]
fn real_dispatch_applies_and_restores_nodefer_masks_through_nested_handlers_and_errors() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let dispatch = probe::between(
        runtime,
        "fn dispatch_signal(",
        "fn apply_default_signal_action(",
    );
    let mut program = String::from(
        r#"
extern crate self as mochios_posix_client;
use std::{ffi::c_int,pin::Pin,sync::atomic::{AtomicU64,Ordering}};
const EINVAL:i32=22;const EOVERFLOW:i32=75;const EIO:i32=5;
const SA_SIGINFO:i32=4;const SA_RESTART:i32=0x10000000;
const SA_RESETHAND:i32=i32::MIN;
const SA_NOCLDSTOP:i32=1;const SA_NOCLDWAIT:i32=2;
mod posix_protocol {
pub const SIGNAL_MAX:u32=64;pub const SIGNAL_KILL:u32=9;pub const SIGNAL_STOP:u32=17;
pub const SIGNAL_MASK_BLOCK:u32=2;pub const SIGNAL_MASK_SET:u32=1;
pub const SIGNAL_ILL:u32=4;pub const SIGNAL_TRAP:u32=5;
pub const SIGNAL_CHLD:u32=20;
pub const SIGNAL_CHILD_OPTION_NOCLDSTOP:u32=1;pub const SIGNAL_CHILD_OPTION_NOCLDWAIT:u32=2;
pub const SIGNAL_DISPOSITION_DEFAULT:u32=0;
pub struct SignalDisposition{pub signal:u32,pub kind:u32,pub child_options:u32}
#[derive(Clone,Copy)]pub struct SignalDelivery{pub signal:u32}
}
extern crate self as mochios_posix_protocol;
pub use posix_protocol::{SIGNAL_KILL,SIGNAL_MAX,SIGNAL_STOP};
pub mod newlib_errno{pub const EINTR:i32=4;}
pub mod signal {
"#,
    );
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/signal.rs"
    ));
    program.push_str(r#"
}
mod signal_context{pub enum InfoError{Overflow,Other}}
#[derive(Clone,Copy)]struct Action{handler:usize,sa_flags:i32,sa_mask:u64}
type SignalAction=Action;
impl Action{fn default_action()->Self{Self{handler:0,sa_flags:0,sa_mask:0}}}
struct Actions(std::sync::Mutex<[Action;64]>);
impl Actions{fn lock(&self)->std::sync::MutexGuard<'_,[Action;64]>{self.0.lock().unwrap()}}
static SIGNAL_ACTIONS:Actions=Actions(std::sync::Mutex::new([Action{handler:2,sa_flags:0,sa_mask:0};64]));
struct Update(std::sync::Mutex<()>);
impl Update{fn lock(&self)->std::sync::MutexGuard<'_,()>{self.0.lock().unwrap()}}
static SIGNAL_ACTION_UPDATE:Update=Update(std::sync::Mutex::new(()));
static REMOTE_DISPOSITION:AtomicU64=AtomicU64::new(2);
struct ThreadControl{caught_signal_generation:AtomicU64,restart_signal_generation:AtomicU64,nonrestart_signal_generation:AtomicU64}
static CONTROL:ThreadControl=ThreadControl{caught_signal_generation:AtomicU64::new(0),restart_signal_generation:AtomicU64::new(0),nonrestart_signal_generation:AtomicU64::new(0)};
struct Preparation{control:&'static ThreadControl}
mod signal_scope{pub struct Scope;}
struct SigInfo;
impl SigInfo {fn from_origin(_:u32,_:())->Result<Self,signal_context::InfoError>{Ok(Self)}}
struct Client;
fn posix_client()->Result<Client,i32>{Ok(Client)}
impl Client{fn signal_delivery_origin(&self,_:posix_protocol::SignalDelivery)->Result<(),i32>{Ok(())}}
impl Client{fn set_signal_disposition(&self,action:posix_protocol::SignalDisposition)->Result<(),i32>{
assert_eq!(action.signal,30);assert_eq!(action.child_options,0);
REMOTE_DISPOSITION.store(action.kind as u64,Ordering::SeqCst);Ok(())}}
fn map_posix_client_error(value:i32)->i32{value}
#[derive(Clone,Copy,Default)]struct Machine;
impl Machine{fn checked_return(&self,_:&Self)->Option<Self>{Some(*self)}}
#[derive(Default)]struct UContext{uc_sigmask:u64,uc_mcontext:Machine}
static MASK:AtomicU64=AtomicU64::new(0);
static DEPTH:AtomicU64=AtomicU64::new(0);
static MAX_DEPTH:AtomicU64=AtomicU64::new(0);
static EXPECT_BLOCKED:AtomicU64=AtomicU64::new(0);
static FAIL:AtomicU64=AtomicU64::new(0);
const OWN:u64=1<<29;const OTHER:u64=1<<30;const ORIGINAL:u64=2;
fn service_signal_mask(_:&ThreadControl,operation:u32,requested:u64)->Result<u64,i32>{
Ok(if operation==2{MASK.fetch_or(requested,Ordering::SeqCst)}else{MASK.swap(requested,Ordering::SeqCst)})}
fn notify_thread_waiter(_:&ThreadControl){}
static mut ERRNO:i32=0;
fn __errno()->*mut i32{&raw mut ERRNO}
fn set_errno(value:i32){unsafe{ERRNO=value;}}
mod signal_stack{
use super::*;
pub fn invoke(_:&ThreadControl,action:Action,signal:i32,_:Option<&mut SigInfo>,context:&mut UContext,_:bool,_:&mut Preparation,_:Pin<&mut signal_scope::Scope>)->Result<(),i32>{
assert_eq!(context.uc_sigmask,if DEPTH.load(Ordering::SeqCst)==0{ORIGINAL}else{ORIGINAL|OTHER});
assert_eq!(MASK.load(Ordering::SeqCst)&OWN,EXPECT_BLOCKED.load(Ordering::SeqCst));
assert_eq!(MASK.load(Ordering::SeqCst)&OTHER,OTHER);
if FAIL.load(Ordering::SeqCst)!=0{return Err(EIO)}
let depth=DEPTH.fetch_add(1,Ordering::SeqCst)+1;
MAX_DEPTH.fetch_max(depth,Ordering::SeqCst);
if depth==1&&MASK.load(Ordering::SeqCst)&OWN==0{
let mut nested=UContext::default();let mut prep=Preparation{control:&CONTROL};let mut scope=std::pin::pin!(signal_scope::Scope);
let expected=if action.sa_flags&SA_RESETHAND!=0{1}else{0};
assert_eq!(dispatch_signal(posix_protocol::SignalDelivery{signal:signal as u32},None,&mut nested,false,&mut prep,scope.as_mut()),Ok(expected));
assert_eq!(MASK.load(Ordering::SeqCst),ORIGINAL|OTHER);
}
if action.sa_flags&SA_RESETHAND!=0{
assert_eq!(SIGNAL_ACTIONS.lock()[signal as usize-1].handler,0);
assert_eq!(SIGNAL_ACTIONS.lock()[signal as usize-1].sa_flags,action.sa_flags&!SA_SIGINFO);
assert_eq!(REMOTE_DISPOSITION.load(Ordering::SeqCst),0);
assert!(SIGNAL_ACTION_UPDATE.0.try_lock().is_ok(),"handler entered under update lock");
}
DEPTH.fetch_sub(1,Ordering::SeqCst);let _=action;Ok(())
}}
"#);
    program.push_str("mod signal_action {\n");
    program.push_str(include_str!("../../../user/crates/newlib-runtime/src/signal_action.rs"));
    program.push_str("}\n");
    program.push_str(dispatch);
    program.push_str(r#"
fn main(){
for flags in [0,signal::SA_NODEFER,signal::SA_NODEFER|SA_RESTART]{
 for explicit in [false,true]{for fail in [false,true]{
let blocked=flags&signal::SA_NODEFER==0||explicit;
SIGNAL_ACTIONS.lock()[29]=Action{handler:2,sa_flags:flags,sa_mask:OTHER|if explicit{OWN}else{0}};
MASK.store(ORIGINAL,Ordering::SeqCst);MAX_DEPTH.store(0,Ordering::SeqCst);DEPTH.store(0,Ordering::SeqCst);FAIL.store(fail as u64,Ordering::SeqCst);EXPECT_BLOCKED.store(if blocked{OWN}else{0},Ordering::SeqCst);
let mut context=UContext::default();let mut prep=Preparation{control:&CONTROL};let mut scope=std::pin::pin!(signal_scope::Scope);
assert_eq!(dispatch_signal(posix_protocol::SignalDelivery{signal:30},None,&mut context,false,&mut prep,scope.as_mut()),if fail{Err(EIO)}else{Ok(0)});
assert_eq!(MASK.load(Ordering::SeqCst),ORIGINAL);
assert_eq!(MAX_DEPTH.load(Ordering::SeqCst),if fail{0}else if blocked{1}else{2});
}}}
for explicit in [false,true]{
SIGNAL_ACTIONS.lock()[29]=Action{handler:2,sa_flags:SA_RESETHAND|SA_SIGINFO|SA_RESTART,sa_mask:OTHER|if explicit{OWN}else{0}};
MASK.store(ORIGINAL,Ordering::SeqCst);MAX_DEPTH.store(0,Ordering::SeqCst);DEPTH.store(0,Ordering::SeqCst);
FAIL.store(0,Ordering::SeqCst);EXPECT_BLOCKED.store(if explicit{OWN}else{0},Ordering::SeqCst);
let mut context=UContext::default();let mut prep=Preparation{control:&CONTROL};let mut scope=std::pin::pin!(signal_scope::Scope);
assert_eq!(dispatch_signal(posix_protocol::SignalDelivery{signal:30},None,&mut context,false,&mut prep,scope.as_mut()),Ok(0));
assert_eq!(MASK.load(Ordering::SeqCst),ORIGINAL);assert_eq!(MAX_DEPTH.load(Ordering::SeqCst),1);
assert_eq!(SIGNAL_ACTIONS.lock()[29].handler,0);
}
}
"#);
    probe::run(&program);
}
