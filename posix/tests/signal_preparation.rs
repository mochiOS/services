use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_preparation_and_callback_handoff_defer_only_until_the_handler_frame_commits() {
    let preparation = include_str!("../../../user/crates/newlib-runtime/src/signal_preparation.rs");
    let guard = include_str!("../../../user/crates/posix-client/src/upcall_guard.rs");
    let scope = include_str!("../../../user/crates/newlib-runtime/src/signal_scope.rs");
    let stack = include_str!("../../../user/crates/newlib-runtime/src/signal_stack.rs");
    let begin = stack.find("struct Invocation<'a>").unwrap();
    let end = stack.find("pub(super) fn invoke(").unwrap();
    let mut program = String::from(
        r#"
extern crate self as mochios_posix_client;
use core::{ffi::c_void,sync::atomic::{AtomicU32,AtomicU64,Ordering}};
#[allow(non_camel_case_types)]type c_int=i32;
const EOVERFLOW:i32=75;const EINVAL:i32=22;
static FORK_EPOCH:AtomicU64=AtomicU64::new(0);
static MODE:AtomicU32=AtomicU32::new(0);
static MASKS:AtomicU32=AtomicU32::new(0);
static HANDLERS:AtomicU32=AtomicU32::new(0);
static COMPLETIONS:AtomicU32=AtomicU32::new(0);
static COMPLETE_ERROR:AtomicU32=AtomicU32::new(0);
struct ThreadControl{native_delivery_defer:AtomicU32,active_signal_scope:core::sync::atomic::AtomicUsize,
    active_signal_scope_id:AtomicU64,next_signal_scope_id:AtomicU64}
static CONTROL:ThreadControl=ThreadControl{native_delivery_defer:AtomicU32::new(0),
    active_signal_scope:core::sync::atomic::AtomicUsize::new(0),active_signal_scope_id:AtomicU64::new(0),next_signal_scope_id:AtomicU64::new(1)};
struct SignalAction{handler:usize}
struct SigInfo{value:i32}
struct UContext{value:i32}
mod posix_protocol{pub const SIGNAL_MASK_SET:u32=0;#[derive(Clone,Copy)]pub struct SignalDelivery{pub signal:u32,pub token:u64}}
struct Client;static CLIENT:Client=Client;
fn posix_client()->Result<&'static Client,i32>{Ok(&CLIENT)}
fn map_posix_client_error(error:i32)->i32{error}
fn process_exit(code:i32)->!{std::process::exit(code)}
impl Client{fn complete_signal_delivery(&self,delivery:posix_protocol::SignalDelivery)->Result<(),i32>{
    assert_eq!(delivery.signal,11);assert_eq!(delivery.token,37);
    assert!(CONTROL.native_delivery_defer.load(Ordering::Acquire)>0);
    COMPLETIONS.fetch_add(1,Ordering::AcqRel);
    if COMPLETE_ERROR.load(Ordering::Acquire)!=0{Err(5)}else{Ok(())}
}}
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
    program.push_str("mod signal_scope {\n");
    program.push_str(scope);
    program.push_str("\n}\n");
    program.push_str(&stack[begin..end]);
    program.push_str(r#"
unsafe extern "C" fn legacy(signal:i32){
    assert_eq!(signal,11);assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    assert_ne!(CONTROL.active_signal_scope.load(Ordering::Acquire),0);
    assert_ne!(CONTROL.active_signal_scope_id.load(Ordering::Acquire),0);
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
    COMPLETIONS.store(0,Ordering::Release);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
}
fn main(){
    let outer=Preparation::new(&CONTROL).unwrap();
    let mut inner=Preparation::new(&CONTROL).unwrap();
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),2);
    assert_eq!(inner.begin_with(||Ok(())),Ok(true));assert!(inner.started());
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),1);
    drop(inner);drop(outer);assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    for mode in 0..=6 {
        reset(mode);
        let mut prepared=Preparation::new(&CONTROL).unwrap();
        let mut scope=Box::pin(signal_scope::Scope::new(&CONTROL,posix_protocol::SignalDelivery{signal:11,token:37},prepared.epoch).unwrap());
        assert!(!prepared.started());
        let mut info=SigInfo{value:37};let mut context=UContext{value:42};
        if mode==1 {FORK_EPOCH.fetch_add(1,Ordering::AcqRel);}
        let typed_mode=mode!=5;
        let action=SignalAction{handler:if typed_mode {typed as *const () as usize}else{legacy as *const () as usize}};
        let mut invocation=Invocation{control:&CONTROL,action,signal:11,info:if typed_mode {Some(&mut info)}else{None},
            context:&mut context,mask:0x1234,result:Ok(()),preparation:&mut prepared,scope:scope.as_mut()};
        unsafe{call((&mut invocation as *mut Invocation<'_>).cast())}
        assert_eq!(invocation.result,if mode==3{Err(5)}else{Ok(())},"mode {mode}");
        assert_eq!(HANDLERS.load(Ordering::Acquire),if matches!(mode,1|3){0}else{1},"mode {mode}");
        assert_eq!(MASKS.load(Ordering::Acquire),match mode{1=>0,2=>2,4=>4,_=>1},"mode {mode}");
        assert_eq!(prepared.started(),mode!=1);
        assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),1);
        assert_eq!(scope.as_mut().complete(),Ok(()));
        assert_eq!(COMPLETIONS.load(Ordering::Acquire),if matches!(mode,1|2|4|6){0}else{1});
        assert_eq!(scope.as_mut().complete(),Err(EINVAL));
        drop(scope);
        assert_eq!(CONTROL.active_signal_scope.load(Ordering::Acquire),0);
        assert_eq!(CONTROL.active_signal_scope_id.load(Ordering::Acquire),0);
        drop(prepared);assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    }
    // Records nest across distinct stacks and fork images. A fresh child's
    // own delivery completes, while both copied ancestor tokens are skipped.
    for forked in [false,true] {
        reset(0);
        let mut outer_prepared=Preparation::new(&CONTROL).unwrap();
        let mut outer=Box::pin(signal_scope::Scope::new(&CONTROL,posix_protocol::SignalDelivery{signal:11,token:37},outer_prepared.epoch).unwrap());
        assert_eq!(outer_prepared.begin_with(||outer.as_mut().activate()),Ok(true));
        let outer_id=CONTROL.active_signal_scope_id.load(Ordering::Acquire);
        assert_eq!(outer.as_mut().complete(),Err(EINVAL));
        let mut inner_prepared=Preparation::new(&CONTROL).unwrap();
        let mut inner=Box::pin(signal_scope::Scope::new(&CONTROL,posix_protocol::SignalDelivery{signal:11,token:37},inner_prepared.epoch).unwrap());
        assert_eq!(inner_prepared.begin_with(||inner.as_mut().activate()),Ok(true));
        let inner_id=CONTROL.active_signal_scope_id.load(Ordering::Acquire);
        assert!(inner_id>outer_id);
        if forked {
            FORK_EPOCH.fetch_add(1,Ordering::AcqRel);
            let mut child_prepared=Preparation::new(&CONTROL).unwrap();
            let mut child=Box::pin(signal_scope::Scope::new(&CONTROL,posix_protocol::SignalDelivery{signal:11,token:37},child_prepared.epoch).unwrap());
            assert_eq!(child_prepared.begin_with(||child.as_mut().activate()),Ok(true));
            child_prepared.finish().unwrap();child.as_mut().complete().unwrap();
            drop(child);drop(child_prepared);
            assert_eq!(CONTROL.active_signal_scope_id.load(Ordering::Acquire),inner_id);
        }
        inner_prepared.finish().unwrap();
        assert_eq!(inner.as_mut().activate(),Err(EINVAL));
        inner.as_mut().complete().unwrap();drop(inner);drop(inner_prepared);
        assert_eq!(CONTROL.active_signal_scope_id.load(Ordering::Acquire),outer_id);
        outer_prepared.finish().unwrap();outer.as_mut().complete().unwrap();
        drop(outer);drop(outer_prepared);
        assert_eq!(CONTROL.active_signal_scope.load(Ordering::Acquire),0);
        assert_eq!(CONTROL.active_signal_scope_id.load(Ordering::Acquire),0);
        assert_eq!(COMPLETIONS.load(Ordering::Acquire),if forked{1}else{2});
    }
    reset(0);
    for forked in [false,true] {
        reset(0);COMPLETE_ERROR.store(0,Ordering::Release);
        assert_eq!(unsafe{signal_scope::validate_target(&CONTROL,0)},Err(EINVAL));
        let prepared=Preparation::new(&CONTROL).unwrap();
        let mut records=Vec::new();let mut target=0;
        for index in 0..100 {
            let mut record=Box::pin(signal_scope::Scope::new(&CONTROL,posix_protocol::SignalDelivery{signal:11,token:37},0).unwrap());
            record.as_mut().activate().unwrap();records.push(record);
            if index==49 {target=CONTROL.active_signal_scope_id.load(Ordering::Acquire);}
        }
        let top=CONTROL.active_signal_scope.load(Ordering::Acquire);
        let top_id=CONTROL.active_signal_scope_id.load(Ordering::Acquire);
        assert_eq!(unsafe{signal_scope::unwind_to(&CONTROL,u64::MAX)},Err(EINVAL));
        assert_eq!(COMPLETIONS.load(Ordering::Acquire),0);
        assert_eq!(CONTROL.active_signal_scope.load(Ordering::Acquire),top);
        CONTROL.active_signal_scope_id.store(top_id+1,Ordering::Release);
        assert_eq!(unsafe{signal_scope::unwind_to(&CONTROL,top_id+1)},Err(EINVAL));
        CONTROL.active_signal_scope_id.store(top_id,Ordering::Release);
        if forked {FORK_EPOCH.fetch_add(1,Ordering::AcqRel);}
        unsafe{signal_scope::unwind_to(&CONTROL,target)}.unwrap();
        assert_eq!(CONTROL.active_signal_scope_id.load(Ordering::Acquire),target);
        assert_eq!(records[99].as_mut().activate(),Err(EINVAL));
        assert_eq!(COMPLETIONS.load(Ordering::Acquire),if forked{0}else{50});
        unsafe{signal_scope::unwind_to(&CONTROL,target)}.unwrap();
        assert_eq!(COMPLETIONS.load(Ordering::Acquire),if forked{0}else{50});
        if forked {
            let mut fresh=Box::pin(signal_scope::Scope::new(&CONTROL,posix_protocol::SignalDelivery{signal:11,token:37},1).unwrap());
            fresh.as_mut().activate().unwrap();
            unsafe{signal_scope::unwind_to(&CONTROL,target)}.unwrap();drop(fresh);
            assert_eq!(COMPLETIONS.load(Ordering::Acquire),1);
        }
        unsafe{signal_scope::unwind_to(&CONTROL,0)}.unwrap();
        assert_eq!(COMPLETIONS.load(Ordering::Acquire),if forked{1}else{100});
        assert_eq!(CONTROL.active_signal_scope.load(Ordering::Acquire),0);
        assert_eq!(CONTROL.active_signal_scope_id.load(Ordering::Acquire),0);
        // Retired records have no remaining link/destructor side effects.
        drop(records);drop(prepared);
        assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    }
    reset(0);
    assert!(matches!(signal_scope::Scope::new(&CONTROL,posix_protocol::SignalDelivery{signal:11,token:37},0),Err(EINVAL)));
    let prepared=Preparation::new(&CONTROL).unwrap();
    let mut scope=Box::pin(signal_scope::Scope::new(&CONTROL,posix_protocol::SignalDelivery{signal:11,token:37},0).unwrap());
    scope.as_mut().activate().unwrap();
    let active=CONTROL.active_signal_scope.load(Ordering::Acquire);
    COMPLETE_ERROR.store(1,Ordering::Release);
    assert_eq!(unsafe{signal_scope::unwind_to(&CONTROL,0)},Err(5));
    assert_eq!(CONTROL.active_signal_scope.load(Ordering::Acquire),active);
    assert_eq!(scope.as_mut().complete(),Err(EINVAL));
    assert_eq!(COMPLETIONS.load(Ordering::Acquire),1);
    drop(scope);drop(prepared);
    let prepared=Preparation::new(&CONTROL).unwrap();
    CONTROL.next_signal_scope_id.store(u64::MAX,Ordering::Release);
    assert!(matches!(signal_scope::Scope::new(&CONTROL,posix_protocol::SignalDelivery{signal:11,token:37},0),Err(EOVERFLOW)));
    assert_eq!(CONTROL.next_signal_scope_id.load(Ordering::Acquire),u64::MAX);
    drop(prepared);
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
