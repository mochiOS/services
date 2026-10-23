//! Run the actual metadata/exec entry wrappers and resource owner. Only inner
//! preparation/transport is controlled; this is not a native test.
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn operation_preparation_has_a_published_owner_on_success_error_and_handoff_failure() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let source = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    let mut wrappers = [
        ("pub(super) fn ftruncate(", "fn ftruncate_prepared("),
        ("pub(super) fn truncate(", "fn truncate_prepared("),
        ("fn open_in_slot(", "fn open_prepared("),
    ]
    .map(|(start, end)| probe::between(source, start, end).replace("pub(super) ", ""))
    .join("\n");
    wrappers.push_str(&probe::between(
        include_str!("../../../user/crates/newlib-runtime/src/lib.rs"),
        "fn execve_with_launch_context(",
        "fn execve_with_launch_context_owned(",
    ));
    let program = format!(
        r#"
#![allow(dead_code)]
use std::ffi::{{c_int,c_char}};
use std::sync::atomic::{{AtomicBool,AtomicU32,AtomicU64,Ordering}};
extern crate self as mochios_posix_client;
#[path={guard:?}]pub mod upcall_guard;
#[path={resources:?}]mod callback_resources;
#[path={io:?}]mod io_resources;
const EAGAIN:c_int=11;
struct ThreadControl{{callback_resources:callback_resources::Chain,active_signal_scope_id:AtomicU64,native:AtomicU32}}
static CONTROL:ThreadControl=ThreadControl{{callback_resources:callback_resources::Chain::new(),active_signal_scope_id:AtomicU64::new(0),native:AtomicU32::new(0)}};
static REGISTER:AtomicBool=AtomicBool::new(true);
static CALLS:AtomicU32=AtomicU32::new(0);
fn register_current_thread()->Option<(u32,&'static ThreadControl)>{{REGISTER.load(Ordering::Acquire).then_some((64,&CONTROL))}}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{upcall_guard::Guard::enter(&CONTROL.native)}}
fn check_preparation(){{
    assert!(!CONTROL.callback_resources.is_empty(),"preparation is not published");
    assert!(CONTROL.callback_resources.capture_empty().is_none());
    assert_eq!(CONTROL.native.load(Ordering::Acquire),0);
    CALLS.fetch_add(1,Ordering::AcqRel);
}}
fn idle(){{
    assert!(CONTROL.callback_resources.is_empty());
    assert!(CONTROL.callback_resources.capture_empty().is_some());
    assert_eq!(CONTROL.native.load(Ordering::Acquire),0);
}}
fn ftruncate_prepared(fd:c_int,length:u64)->Result<c_int,c_int>{{
    check_preparation();
    if fd<0{{return Err(9)}}
    assert_eq!((fd,length),(7,19));
    // The enclosing preparation and the real replay owner nest normally.
    let value=io_resources::with(||Ok(17),|resource|{{assert_eq!(*resource,17);Ok(0)}})?;
    assert!(!CONTROL.callback_resources.is_empty());
    Ok(value)
}}
fn truncate_prepared(path:*const c_char,length:u64)->Result<c_int,c_int>{{
    check_preparation();assert_eq!(length,20);
    if path.is_null(){{Err(14)}}else{{Ok(0)}}
}}
fn open_prepared(dirfd:c_int,path:*const c_char,flags:c_int,mode:c_int,target:Option<c_int>,mut handoff:Option<&mut dyn FnMut(c_int)->Result<(),c_int>>)->Result<c_int,c_int>{{
    check_preparation();assert_eq!((dirfd,flags,mode),(-2,3,0o600));
    if path.is_null(){{return Err(14)}}
    let fd=target.unwrap_or(8);
    if let Some(handoff)=handoff.as_mut(){{handoff(fd)?;}}
    Ok(fd)
}}
fn execve_with_launch_context_owned(path:*const c_char,argv:*const *const c_char,envp:*const *const c_char)->Result<(),c_int>{{
    check_preparation();assert!(!path.is_null());assert!(argv.is_null()&&envp.is_null());Err(8)
}}
{wrappers}
fn main(){{
    let path=c"/tmp/resource-preparation".as_ptr();
    assert_eq!(ftruncate(7,19),Ok(0));idle();
    assert_eq!(ftruncate(-1,19),Err(9));idle();
    assert_eq!(truncate(path,20),Ok(0));idle();
    assert_eq!(truncate(std::ptr::null(),20),Err(14));idle();
    assert_eq!(open_in_slot(-2,path,3,0o600,None,None),Ok(8));idle();
    assert_eq!(open_in_slot(-2,path,3,0o600,Some(12),None),Ok(12));idle();
    let mut handed=0;
    let mut handoff=|fd|{{assert!(!CONTROL.callback_resources.is_empty());handed=fd;Err(22)}};
    assert_eq!(open_in_slot(-2,path,3,0o600,Some(13),Some(&mut handoff)),Err(22));
    assert_eq!(handed,13);idle();
    assert_eq!(open_in_slot(-2,std::ptr::null(),3,0o600,None,None),Err(14));idle();
    assert_eq!(execve_with_launch_context(path,std::ptr::null(),std::ptr::null()),Err(8));idle();
    let calls=CALLS.load(Ordering::Acquire);
    REGISTER.store(false,Ordering::Release);
    assert_eq!(ftruncate(7,19),Err(EAGAIN));idle();
    assert_eq!(truncate(path,20),Err(EAGAIN));idle();
    assert_eq!(open_in_slot(-2,path,3,0o600,None,None),Err(EAGAIN));idle();
    assert_eq!(execve_with_launch_context(path,std::ptr::null(),std::ptr::null()),Err(EAGAIN));idle();
    assert_eq!(CALLS.load(Ordering::Acquire),calls);
}}
"#,
        guard = root.join("user/crates/posix-client/src/upcall_guard.rs"),
        resources = root.join("user/crates/newlib-runtime/src/callback_resources.rs"),
        io = root.join("user/crates/newlib-runtime/src/io_resources.rs"),
    );
    probe::run(&program);
}
