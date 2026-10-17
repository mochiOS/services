#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn refresh_waits_without_masking_native_delivery_and_always_retires_receipt() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code,non_camel_case_types)]
extern crate self as mnu_abi;
extern crate self as mochios_posix_client;
extern crate self as mochios_posix_protocol;
#[path={native_status:?}]pub mod native_status;
pub mod status{{pub use crate::native_status::*;#[path={wire:?}]mod wire;pub use wire::normalize_failure;}}
pub const STATUS_EIO:i32=-5;pub const STATUS_EAGAIN:i32=-11;
#[path={errno:?}]pub mod newlib_errno;
#[path={memory:?}]pub mod memory;
#[path={completion:?}]pub mod completion;
#[path={upcall:?}]pub mod upcall_guard;
#[path={callbacks:?}]mod callback_resources;
#[path={resources:?}]mod io_resources;
#[path={refresh:?}]mod memory_refresh;
use std::cell::Cell;
use core::sync::atomic::{{AtomicU32,AtomicU64,Ordering}};
use newlib_errno::{{EAGAIN,EIO,EINTR}};
type c_int=i32;
struct ThreadControl{{
    native_delivery_defer:AtomicU32,
    callback_resources:callback_resources::Chain,
    active_signal_scope_id:AtomicU64,
    nonrestart_signal_generation:AtomicU64,
    multiplex_generation:AtomicU64,
}}
static CONTROL:ThreadControl=ThreadControl{{
    native_delivery_defer:AtomicU32::new(0),callback_resources:callback_resources::Chain::new(),
    active_signal_scope_id:AtomicU64::new(0),nonrestart_signal_generation:AtomicU64::new(0),
    multiplex_generation:AtomicU64::new(0),
}};
fn current_thread_control()->Option<(u64,&'static ThreadControl)>{{Some((7,&CONTROL))}}
fn register_current_thread()->Option<(u64,&'static ThreadControl)>{{current_thread_control()}}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{
    upcall_guard::Guard::enter(&CONTROL.native_delivery_defer)
}}
fn guarded()->bool{{CONTROL.native_delivery_defer.load(Ordering::Acquire)!=0}}
thread_local!{{
    static MODE:Cell<u32>=const{{Cell::new(0)}};
    static READS:Cell<u32>=const{{Cell::new(0)}};
    static WAITS:Cell<u32>=const{{Cell::new(0)}};
    static CLOSED:Cell<u32>=const{{Cell::new(0)}};
    static SUBMIT_ERROR:Cell<u64>=const{{Cell::new(0)}};
}}
fn close_object_handle(handle:u32){{assert!(guarded());assert_eq!(handle,19);CLOSED.set(CLOSED.get()+1);}}
fn io_cancellation_requested(_: &ThreadControl)->bool{{MODE.get()==10}}
fn drain_pending_signals()->Result<(),i32>{{
    assert!(!guarded());assert!(!CONTROL.callback_resources.is_empty());
    if MODE.get()==14{{
        MODE.set(0);CONTROL.active_signal_scope_id.store(1,Ordering::Release);
        assert_eq!(memory_refresh::synchronize(4096,4097),Ok(()));
        CONTROL.active_signal_scope_id.store(0,Ordering::Release);MODE.set(14);
        assert!(!CONTROL.callback_resources.is_empty());assert_eq!(CLOSED.get(),1);
    }}
    if MODE.get()==9{{CONTROL.nonrestart_signal_generation.fetch_add(1,Ordering::AcqRel);}}
    Ok(())
}}
fn syscall_errno(result:syscall::RawSyscallResult)->Result<u64,i32>{{
    result.into_result().map_err(|error|newlib_errno::from_status(error.raw()))
}}
mod syscall{{
use crate::*;
pub use native_status::Error as NativeError;
"#,
        native_status = root.join("core/crates/abi/src/status.rs"),
        wire = root.join("user/crates/posix-protocol/src/status.rs"),
        errno = root.join("user/crates/posix-client/src/newlib_errno.rs"),
        memory = root.join("user/crates/posix-client/src/memory.rs"),
        completion = root.join("core/crates/abi/src/completion.rs"),
        upcall = root.join("user/crates/posix-client/src/upcall_guard.rs"),
        callbacks = root.join("user/crates/newlib-runtime/src/callback_resources.rs"),
        resources = root.join("user/crates/newlib-runtime/src/io_resources.rs"),
        refresh = root.join("user/crates/newlib-runtime/src/memory_refresh.rs"),
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct SysError",
        "#[inline(always)]",
    ));
    program.push_str(r#"
#[derive(PartialEq,Debug)]pub enum SyscallNumber{MemorySync,HandleReadAt,HandleWaitManyGuarded}
pub const HANDLE_SIGNAL_READABLE:u64=1;
pub const HANDLE_WAIT_INFINITE:u64=u64::MAX;
#[derive(Default)]pub struct HandleWaitItem{pub handle:u32,pub minimum_write_bytes:u32,pub interests:u64,pub observed:u64}
pub struct HandleWaitGuard{pub address:u64,pub expected:u64}
pub fn raw_syscall3(number:SyscallNumber,address:u64,length:u64,options:u64)->RawSyscallResult{
    assert_eq!(number,SyscallNumber::MemorySync);assert_eq!((address,length,options),(4096,4097,3));
    assert!(guarded());let error=SUBMIT_ERROR.get();RawSyscallResult::new(if error!=0{error}else{19})
}
pub fn raw_syscall4(number:SyscallNumber,a:u64,b:u64,c:u64,d:u64)->RawSyscallResult{
    assert!(!guarded());assert!(!CONTROL.callback_resources.is_empty());
    let mode=MODE.get();
    if number==SyscallNumber::HandleReadAt{
        assert_eq!((a,c,d),(19,16,0));let reads=READS.get();READS.set(reads+1);
        if mode==7{return RawSyscallResult::new(NativeError::PeerClosed.into_raw());}
        let result=match mode{
            0 if reads==0=>None,
            1=>Some(Err((-28i64)as u64)),2=>Some(Err(0)),
            3=>Some(Err(NativeError::InvalidAddress.into_raw())),
            4|5|6|8 if reads==0=>None,
            _=>Some(Ok(())),
        };
        let mut bytes=completion::encode(result);
        if mode==11{bytes[..8].copy_from_slice(&99u64.to_le_bytes());}
        if mode==12{bytes[8..].copy_from_slice(&1u64.to_le_bytes());}
        unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),b as *mut u8,16)};
        return RawSyscallResult::new(if mode==13{8}else{16});
    }
    assert_eq!(number,SyscallNumber::HandleWaitManyGuarded);
    assert_eq!((b,c),(1,u64::MAX));WAITS.set(WAITS.get()+1);
    let item=unsafe{&mut*(a as *mut HandleWaitItem)};
    let guard=unsafe{&*(d as *const HandleWaitGuard)};
    assert_eq!((item.handle,item.interests),(19,HANDLE_SIGNAL_READABLE));
    assert_eq!(guard.address,&CONTROL.multiplex_generation as *const AtomicU64 as u64);
    assert_eq!(guard.expected,CONTROL.multiplex_generation.load(Ordering::Acquire));
    if mode==4{CONTROL.multiplex_generation.fetch_add(1,Ordering::AcqRel);
        return RawSyscallResult::new(NativeError::NotReady.into_raw());}
    if mode==5{return RawSyscallResult::new(NativeError::PeerClosed.into_raw());}
    if mode!=6{item.observed=HANDLE_SIGNAL_READABLE;}
    RawSyscallResult::new(1)
}
}
fn main(){
    for (mode,expected) in [(0,Ok(())),(1,Err(28)),(2,Err(5)),(3,Err(12)),
        (4,Ok(())),(5,Err(32)),(6,Err(5)),(7,Err(32)),(8,Ok(())),
        (9,Err(4)),(10,Err(4)),(11,Err(5)),(12,Err(5)),(13,Err(5)),(14,Ok(()))]{
        MODE.set(mode);READS.set(0);WAITS.set(0);CLOSED.set(0);
        assert_eq!(memory_refresh::synchronize(4096,4097),expected,"mode {mode}");
        assert_eq!(CLOSED.get(),if mode==14{2}else{1});
        assert!(CONTROL.callback_resources.is_empty());assert!(!guarded());
        if mode==0||mode==4{assert_eq!(WAITS.get(),1);assert_eq!(READS.get(),2);}
    }
    SUBMIT_ERROR.set(native_status::Error::AccessDenied.into_raw());CLOSED.set(0);
    assert_eq!(memory_refresh::synchronize(4096,4097),Err(13));
    assert_eq!(CLOSED.get(),0);assert!(CONTROL.callback_resources.is_empty());assert!(!guarded());
}
"#);
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let constants: String = abi
        .lines()
        .filter(|line| {
            line.starts_with("pub const MEMORY_ACCESS_")
                || line.starts_with("pub const MEMORY_MAP_")
                || line.starts_with("pub const MEMORY_SYNC_")
        })
        .map(|line| format!("{line}\n"))
        .collect();
    program.push_str(&constants);
    probe::run(&program);
}
