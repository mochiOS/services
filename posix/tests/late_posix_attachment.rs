#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn an_existing_native_thread_attaches_after_endpoint_handoff_without_libc_recursion() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let register = probe::between(
        runtime,
        "fn register_current_thread()",
        "fn register_thread_control()",
    );
    let reent = probe::between(runtime, "pub extern \"C\" fn __getreent()", "fn set_errno(");
    probe::run(&format!(
        r#"
use core::ffi::c_void;
use core::sync::atomic::{{AtomicU32,AtomicUsize,Ordering}};
type Pthread=u32;
struct ThreadControl {{signal_upcall_stack:AtomicUsize,reent:AtomicUsize}}
static CONTROL:ThreadControl=ThreadControl{{signal_upcall_stack:AtomicUsize::new(0),reent:AtomicUsize::new(0x1000)}};
static ENDPOINT:AtomicU32=AtomicU32::new(0);
static QUERIES:AtomicU32=AtomicU32::new(0);
static SETUPS:AtomicU32=AtomicU32::new(0);
static MODE:AtomicU32=AtomicU32::new(0);
fn register_thread_control()->Option<(Pthread,&'static ThreadControl)>{{
    (MODE.load(Ordering::Relaxed)!=3).then_some((64,&CONTROL))
}}
fn has_posix_environment()->Result<bool,i32>{{
    QUERIES.fetch_add(1,Ordering::Relaxed);
    if MODE.load(Ordering::Relaxed)==1 {{Err(13)}} else {{Ok(ENDPOINT.load(Ordering::Relaxed)!=0)}}
}}
fn setup_signal_delivery(control:&ThreadControl,stack:Option<usize>)->Result<(),i32>{{
    assert!(core::ptr::eq(control,&CONTROL));assert_eq!(stack,None);
    SETUPS.fetch_add(1,Ordering::Relaxed);
    // Attachment may allocate inside libc. The actual reent entry point must
    // not re-enter endpoint discovery or start another attachment.
    let queries=QUERIES.load(Ordering::Relaxed);
    assert_eq!(__getreent() as usize,0x1000);
    assert_eq!(QUERIES.load(Ordering::Relaxed),queries);
    if MODE.load(Ordering::Relaxed)==2 {{return Err(13)}}
    control.signal_upcall_stack.store(0x2000,Ordering::Release);Ok(())
}}
fn process_exit(code:i32)->!{{panic!("unexpected exit {{code}}")}}
{register}
{reent}
fn main(){{
    for _ in 0..1000 {{assert_eq!(__getreent() as usize,0x1000)}}
    assert_eq!(QUERIES.load(Ordering::Relaxed),0);
    assert_eq!(register_current_thread().unwrap().0,64);
    assert_eq!(SETUPS.load(Ordering::Relaxed),0);
    ENDPOINT.store(1,Ordering::Relaxed);
    assert_eq!(register_current_thread().unwrap().0,64);
    assert_eq!(SETUPS.load(Ordering::Relaxed),1);
    let queries=QUERIES.load(Ordering::Relaxed);
    for _ in 0..1000 {{assert_eq!(register_current_thread().unwrap().0,64)}}
    assert_eq!(QUERIES.load(Ordering::Relaxed),queries);
    assert_eq!(SETUPS.load(Ordering::Relaxed),1);
    CONTROL.signal_upcall_stack.store(0,Ordering::Release);
    MODE.store(1,Ordering::Relaxed);
    assert!(register_current_thread().is_none());
    assert_eq!(SETUPS.load(Ordering::Relaxed),1);
    MODE.store(2,Ordering::Relaxed);
    assert!(register_current_thread().is_none());
    assert_eq!(CONTROL.signal_upcall_stack.load(Ordering::Acquire),0);
    MODE.store(0,Ordering::Relaxed);
    assert!(register_current_thread().is_some());
    assert_eq!(SETUPS.load(Ordering::Relaxed),3);
    MODE.store(3,Ordering::Relaxed);
    assert!(register_current_thread().is_none());
}}
"#
    ));
}
