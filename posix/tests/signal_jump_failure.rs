use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn nonreturning_jump_failures_keep_delivery_deferred_until_process_exit() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/signal_jump.rs");
    let start = source.find("unsafe extern \"C\" fn siglongjmp(").unwrap();
    let guard = include_str!("../../../user/crates/posix-client/src/upcall_guard.rs");
    let mut program = String::from(
        r#"
use core::{ffi::c_void,sync::atomic::{AtomicU32,AtomicUsize,Ordering}};
#[allow(non_camel_case_types)]type c_int=i32;
const EINVAL:i32=22;const EAGAIN:i32=11;const EOVERFLOW:i32=75;const MAGIC:u64=37;
static MODE:AtomicU32=AtomicU32::new(0);
static BASE:AtomicU32=AtomicU32::new(0);
struct ThreadControl{native_delivery_defer:AtomicU32,signal_upcall_stack:AtomicUsize}
static CONTROL:ThreadControl=ThreadControl{native_delivery_defer:AtomicU32::new(0),signal_upcall_stack:AtomicUsize::new(0x30000)};
#[derive(Clone,Copy)]struct JumpBuffer{registers:[u64;8],mask:u64,thread:u64,scope:u64,native:u64,save_mask:u64,defer_depth:u64,magic:u64}
struct Transition{buffer:JumpBuffer,value:i32,depth:u32,defer:*const AtomicU32,chain:u64}
enum NativeDestination<'a>{Direct{buffer:&'a JumpBuffer,value:i32,defer:*const AtomicU32,depth:u32},Cleanup{transition:*mut Transition}}
fn current_thread_control()->Option<(u32,&'static ThreadControl)>{Some((1,&CONTROL))}
struct NativeError;impl NativeError{fn raw(self)->i64{-5}}
fn native_process_id()->Result<u64,NativeError>{if MODE.load(Ordering::Acquire)==1{Err(NativeError)}else{Ok(37)}}
fn map_kernel_errno(_:i64)->i32{5}
fn process_exit(code:i32)->!{
    let depth=CONTROL.native_delivery_defer.load(Ordering::Acquire);
    let base=BASE.load(Ordering::Acquire);
    let safe=if base==u32::MAX{code==EOVERFLOW && depth==u32::MAX}else{code==5 && depth==base+1};
    std::process::exit(if safe {0}else{99})
}
mod signal_scope{use super::*;pub unsafe fn validate_target(_:&ThreadControl,_:u64)->Result<(),i32>{
    if MODE.load(Ordering::Acquire)==0{Err(5)}else{Ok(())}
}}
mod signal_delivery{use super::*;
    pub struct Frame{pub owner:u64,pub token:u64,pub stack:usize,pub size:usize}
    pub unsafe fn visit_abandoned(_:&ThreadControl,_:u64,mut visit:impl FnMut(Frame)->Result<(),i32>)->Result<(),i32>{
        let mode=MODE.load(Ordering::Acquire);if mode==2{return Err(5)}
        visit(Frame{owner:if mode>=4{11}else{37},token:9,stack:0x20000,size:4096})
    }
    pub unsafe fn stage_jump(_:&'static ThreadControl,_:u64,_:u64,make:impl FnOnce(u64)->Transition)->Result<*mut Transition,i32>{
        if MODE.load(Ordering::Acquire)==4{return Err(5)}
        let _=make(0);Ok(core::ptr::null_mut())
    }
}
unsafe fn prepare_jump(_:&ThreadControl,_:&JumpBuffer)->Result<(),i32>{Err(5)}
fn leave_native(_:u64,_:usize,_:NativeDestination<'_>)->!{panic!("unexpected native return")}
unsafe fn __mochios_sigjump_restore(_:*const JumpBuffer,_:i32,_:*const AtomicU32,_:u32)->!{panic!("unexpected restore")}
unsafe extern "C" fn finish_jump(_:*mut c_void)->!{panic!("unexpected cleanup")}
mod mochios_posix_client{pub mod signal_stack{
    pub unsafe fn enter_on(_:usize,_:unsafe extern "C" fn(*mut core::ffi::c_void)->!,_:*mut core::ffi::c_void)->!{panic!("unexpected stack switch")}
}}
mod upcall_guard {
"#,
    );
    program.push_str(guard);
    program.push_str("\n}\nuse upcall_guard::Guard;\n");
    program.push_str(&source[start..]);
    program.push_str(
        r#"
fn main(){
    MODE.store(std::env::args().nth(1).unwrap().parse().unwrap(),Ordering::Release);
    let base=std::env::args().nth(2).unwrap_or_else(||"0".into()).parse().unwrap();
    BASE.store(base,Ordering::Release);CONTROL.native_delivery_defer.store(base,Ordering::Release);
    let mut registers=[0;8];registers[6]=0x8000;registers[7]=0x4000;
    let buffer=JumpBuffer{registers,mask:0,thread:1,scope:0,native:0,save_mask:0,defer_depth:0,magic:MAGIC};
    unsafe{siglongjmp(&buffer,37)}
}
"#,
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-jump-failure-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let compile = |program: &str| {
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
    };
    compile(&program);
    // Failures before completion, in direct completion, during orphan staging,
    // and after staging must all reach exit with the same live guard depth.
    for depth in [0, 2] {
        for mode in 0..6 {
            let output = Command::new(&binary)
                .arg(mode.to_string())
                .arg(depth.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "mode {mode}, depth {depth}: {:?}",
                output.status.code()
            );
        }
    }
    assert!(Command::new(&binary)
        .args(["0", &u32::MAX.to_string()])
        .status()
        .unwrap()
        .success());
    let unguarded = program.replace("core::mem::forget(guard);", "");
    assert_ne!(unguarded, program);
    compile(&unguarded);
    assert!(!Command::new(&binary).arg("0").status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
