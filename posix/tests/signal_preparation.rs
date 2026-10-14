use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_preparation_and_callback_handoff_defer_only_until_the_handler_frame_commits() {
    let preparation = include_str!("../../../user/crates/newlib-runtime/src/signal_preparation.rs");
    let guard = include_str!("../../../user/crates/posix-client/src/upcall_guard.rs");
    let stack = include_str!("../../../user/crates/newlib-runtime/src/signal_stack.rs");
    let begin = stack.find("struct Invocation<'a>").unwrap();
    let end = stack.find("pub(super) fn invoke(").unwrap();
    let mut program = String::from(
        r#"
extern crate self as mochios_posix_client;
use core::{ffi::c_void,sync::atomic::{AtomicU32,AtomicU64,Ordering}};
#[allow(non_camel_case_types)]type c_int=i32;
const EOVERFLOW:i32=75;
static FORK_EPOCH:AtomicU64=AtomicU64::new(0);
static MODE:AtomicU32=AtomicU32::new(0);
static MASKS:AtomicU32=AtomicU32::new(0);
static HANDLERS:AtomicU32=AtomicU32::new(0);
struct ThreadControl{native_delivery_defer:AtomicU32}
static CONTROL:ThreadControl=ThreadControl{native_delivery_defer:AtomicU32::new(0)};
struct SignalAction{handler:usize}
struct SigInfo{value:i32}
struct UContext{value:i32}
mod posix_protocol{pub const SIGNAL_MASK_SET:u32=0;}
fn service_signal_mask(control:&ThreadControl,operation:u32,mask:u64)->Result<u64,i32>{
    assert_eq!(operation,0);assert_eq!(mask,0x1234);
    assert_eq!(control.native_delivery_defer.load(Ordering::Acquire),0,"unmask before releasing preparation");
    let call=MASKS.fetch_add(1,Ordering::AcqRel);
    match MODE.load(Ordering::Acquire) {
        2 if call==0=>{FORK_EPOCH.fetch_add(1,Ordering::AcqRel);return Err(5)}
        3=>return Err(5),
        4 if call<3=>{FORK_EPOCH.fetch_add(1,Ordering::AcqRel);return Err(5)}
        _=>{}
    }
    Ok(0)
}
pub mod upcall_guard {
"#,
    );
    program.push_str(guard);
    program.push_str("\n}\nmod actual_preparation {\n");
    program.push_str(preparation);
    program.push_str("\n}\nuse actual_preparation::Preparation;\n");
    program.push_str(&stack[begin..end]);
    program.push_str(r#"
unsafe extern "C" fn legacy(signal:i32){
    assert_eq!(signal,11);assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    let nested=Preparation::new(&CONTROL).unwrap();
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),1);
    drop(nested);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    HANDLERS.fetch_add(1,Ordering::AcqRel);
    if MODE.load(Ordering::Acquire)==6 {FORK_EPOCH.fetch_add(1,Ordering::AcqRel);}
}
unsafe extern "C" fn typed(signal:i32,info:*mut SigInfo,context:*mut c_void){
    assert_eq!(unsafe{(*info).value},37);
    assert_eq!(unsafe{(*context.cast::<UContext>()).value},42);
    unsafe{legacy(signal)}
}
fn reset(mode:u32){MODE.store(mode,Ordering::Release);FORK_EPOCH.store(0,Ordering::Release);
    MASKS.store(0,Ordering::Release);HANDLERS.store(0,Ordering::Release);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
}
fn main(){
    let outer=Preparation::new(&CONTROL).unwrap();
    let mut inner=Preparation::new(&CONTROL).unwrap();
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),2);
    assert!(inner.begin());assert!(inner.started());
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),1);
    drop(inner);drop(outer);assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    for mode in 0..=6 {
        reset(mode);
        let mut prepared=Preparation::new(&CONTROL).unwrap();
        assert!(!prepared.started());
        let mut info=SigInfo{value:37};let mut context=UContext{value:42};
        if mode==1 {FORK_EPOCH.fetch_add(1,Ordering::AcqRel);}
        let typed_mode=mode!=5;
        let action=SignalAction{handler:if typed_mode {typed as *const () as usize}else{legacy as *const () as usize}};
        let mut invocation=Invocation{control:&CONTROL,action,signal:11,info:if typed_mode {Some(&mut info)}else{None},
            context:&mut context,mask:0x1234,result:Ok(()),preparation:&mut prepared};
        unsafe{call((&mut invocation as *mut Invocation<'_>).cast())}
        assert_eq!(invocation.result,if mode==3{Err(5)}else{Ok(())},"mode {mode}");
        assert_eq!(HANDLERS.load(Ordering::Acquire),if matches!(mode,1|3){0}else{1},"mode {mode}");
        assert_eq!(MASKS.load(Ordering::Acquire),match mode{1=>0,2=>2,4=>4,_=>1},"mode {mode}");
        assert_eq!(prepared.started(),mode!=1);
        assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),if mode==1{1}else{0});
        drop(prepared);assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    }
    CONTROL.native_delivery_defer.store(u32::MAX,Ordering::Release);
    assert!(matches!(Preparation::new(&CONTROL),Err(EOVERFLOW)));
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),u32::MAX);
}
"#);
    let directory =
        std::env::temp_dir().join(format!("mochios-signal-preparation-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let run = |program: &str| {
        let mut compiler = Command::new("rustc")
            .args(["--edition=2024", "-Awarnings", "-", "-o"])
            .arg(&binary)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(program.as_bytes())
            .unwrap();
        let output = compiler.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Command::new(&binary).output().unwrap()
    };
    let output = run(&program);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for condition in [
        "FORK_EPOCH.load(Ordering::Acquire) != self.epoch",
        "FORK_EPOCH.load(Ordering::Acquire) != epoch",
    ] {
        let broken = program.replace(condition, "false");
        assert_ne!(broken, program);
        let output = run(&broken);
        assert!(
            !output.status.success(),
            "missing fork boundary check was not detected"
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}
