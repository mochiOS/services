use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn only_the_resumed_child_advances_the_epoch_before_installing_delivery() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("static FORK_EPOCH: AtomicU64 = AtomicU64::new(0)"));
    let fork = runtime
        .split("fn clone_registered_process(")
        .nth(1)
        .unwrap()
        .split("fn create_spawn_status_stream(")
        .next()
        .unwrap();
    let (parent, child) = fork.split_once("if image == 0 {").unwrap();
    assert!(!parent.contains("FORK_EPOCH"));
    let epoch = child.find("FORK_EPOCH").unwrap();
    assert!(
        epoch
            < child
                .find("setup_signal_delivery(thread_control, None)")
                .unwrap()
    );
    assert!(child[epoch..].contains("epoch.checked_add(1)"));
    assert_eq!(runtime.matches("epoch.checked_add(1)").count(), 1);
}

#[test]
fn actual_thread_lookup_retries_identity_copied_across_a_handler_fork() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime.find("fn current_thread_control(").unwrap();
    let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
use core::sync::atomic::{AtomicU32,AtomicU64,Ordering};
type Pthread=u64;
const THREAD_FREE:u32=0;const THREAD_REAPING:u32=4;const RUNNING:u32=2;
struct ThreadControl{state:AtomicU32,native_id:AtomicU64,thread_local_base:AtomicU64}
impl ThreadControl{const fn new()->Self{Self{state:AtomicU32::new(THREAD_FREE),native_id:AtomicU64::new(0),thread_local_base:AtomicU64::new(0)}}}
static THREADS:[ThreadControl;2]=[const{ThreadControl::new()};2];
static FORK_EPOCH:AtomicU64=AtomicU64::new(0);
static CURRENT:AtomicU64=AtomicU64::new(11);
static CALLS:AtomicU32=AtomicU32::new(0);
static MODE:AtomicU32=AtomicU32::new(0);
static LOCAL_BASE:AtomicU64=AtomicU64::new(0);
static LOCAL_CALLS:AtomicU32=AtomicU32::new(0);
static TOKENS:AtomicU32=AtomicU32::new(0);
mod thread_lookup{
    pub fn local_base()->Option<u64>{
        crate::LOCAL_CALLS.fetch_add(1,crate::Ordering::Relaxed);
        let base=crate::LOCAL_BASE.load(crate::Ordering::Relaxed);
        (base!=0).then_some(base)
    }
}
fn child_snapshot(){
    let new=CURRENT.fetch_add(1,Ordering::AcqRel)+1;
    THREADS[0].native_id.store(new,Ordering::Release);
    FORK_EPOCH.fetch_add(1,Ordering::AcqRel);
}
fn native_thread_id()->Result<u64,()>{
    let call=CALLS.fetch_add(1,Ordering::AcqRel);
    let observed=CURRENT.load(Ordering::Acquire);
    match MODE.load(Ordering::Acquire){
        1 if call==0=>child_snapshot(),
        2 if call<3=>child_snapshot(),
        4 if call==0=>{child_snapshot();return Err(())},
        5=>return Err(()),
        _=>{}
    }
    // The syscall filled its result before the handler cloned the image.
    // Its saved caller now resumes in the child holding that old result.
    Ok(observed)
}
fn thread_token_for(index:usize,_:&ThreadControl)->Option<Pthread>{
    if MODE.load(Ordering::Acquire)==6 && TOKENS.fetch_add(1,Ordering::Relaxed)==0 {child_snapshot()}
    if MODE.load(Ordering::Acquire)==3 && CALLS.load(Ordering::Acquire)==1 {child_snapshot()}
    Some(index as u64+1)
}
"#,
    );
    program.push_str(&runtime[start..end]);
    program.push_str(r#"
fn reset(mode:u32){
    CURRENT.store(11,Ordering::Release);FORK_EPOCH.store(0,Ordering::Release);
    CALLS.store(0,Ordering::Release);MODE.store(mode,Ordering::Release);
    THREADS[0].state.store(RUNNING,Ordering::Release);THREADS[0].native_id.store(11,Ordering::Release);
    THREADS[1].state.store(RUNNING,Ordering::Release);THREADS[1].native_id.store(99,Ordering::Release);
    THREADS[0].thread_local_base.store(0x1000,Ordering::Release);
    THREADS[1].thread_local_base.store(0x2000,Ordering::Release);
    LOCAL_BASE.store(0,Ordering::Relaxed);LOCAL_CALLS.store(0,Ordering::Relaxed);TOKENS.store(0,Ordering::Relaxed);
}
fn main(){
    for (mode,queries) in [(0,1),(1,2),(2,4),(3,2),(4,2)] {
        reset(mode);
        let (token,control)=current_thread_control().expect("lost current TCB after copied native identity");
        assert_eq!(token,1);assert!(core::ptr::eq(control,&THREADS[0]));
        assert_eq!(control.native_id.load(Ordering::Acquire),CURRENT.load(Ordering::Acquire));
        assert_eq!(CALLS.load(Ordering::Acquire),queries);
    }
    reset(0);THREADS[0].state.store(THREAD_FREE,Ordering::Release);
    assert!(current_thread_control().is_none(),"must not select another live thread");
    assert_eq!(CALLS.load(Ordering::Acquire),1);
    reset(0);THREADS[0].state.store(THREAD_REAPING,Ordering::Release);
    assert!(current_thread_control().is_none());
    reset(5);assert!(current_thread_control().is_none());
    assert_eq!(CALLS.load(Ordering::Acquire),1);
    // Private TLS selects the current record without any native query, even
    // when the fallback is deliberately unavailable.
    reset(5);LOCAL_BASE.store(0x1000,Ordering::Relaxed);
    for _ in 0..1000 {assert_eq!(current_thread_control().unwrap().0,1)}
    assert_eq!(CALLS.load(Ordering::Acquire),0);
    reset(5);LOCAL_BASE.store(0x2000,Ordering::Relaxed);
    assert_eq!(current_thread_control().unwrap().0,2);
    assert_eq!(CALLS.load(Ordering::Acquire),0);
    reset(0);LOCAL_BASE.store(0x3000,Ordering::Relaxed);
    assert_eq!(current_thread_control().unwrap().0,1);
    assert_eq!(CALLS.load(Ordering::Acquire),1);
    reset(0);LOCAL_BASE.store(0x1000,Ordering::Relaxed);
    THREADS[1].thread_local_base.store(0x1000,Ordering::Relaxed);
    assert_eq!(current_thread_control().unwrap().0,1);
    assert_eq!(CALLS.load(Ordering::Acquire),1);
    for state in [THREAD_FREE,THREAD_REAPING]{
        reset(5);LOCAL_BASE.store(0x1000,Ordering::Relaxed);
        THREADS[0].state.store(state,Ordering::Relaxed);
        assert!(current_thread_control().is_none());
        assert_eq!(CALLS.load(Ordering::Acquire),1);
    }
    reset(6);LOCAL_BASE.store(0x1000,Ordering::Relaxed);
    let (_,control)=current_thread_control().unwrap();
    assert_eq!(control.native_id.load(Ordering::Relaxed),CURRENT.load(Ordering::Relaxed));
    assert_eq!(LOCAL_CALLS.load(Ordering::Relaxed),2);
    assert_eq!(CALLS.load(Ordering::Acquire),0);
}
"#);
    let directory =
        std::env::temp_dir().join(format!("mochios-thread-identity-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
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
    let output = Command::new(binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
