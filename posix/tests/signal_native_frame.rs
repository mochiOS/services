use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn native_frames_are_pinned_thread_owned_and_retire_only_the_current_identity() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/signal_delivery.rs");
    let start = source.find("/// A native callback").unwrap();
    let end = source.find("fn context(").unwrap();
    let guard = include_str!("../../../user/crates/posix-client/src/upcall_guard.rs");
    let mut program = String::from(
        r#"
extern crate self as mochios_posix_client;
use core::{marker::{PhantomData,PhantomPinned},pin::Pin,sync::atomic::{AtomicU32,AtomicU64,AtomicUsize,Ordering}};
#[allow(non_camel_case_types)]type c_int=i32;
const EINVAL:i32=22;const EAGAIN:i32=11;const EOVERFLOW:i32=75;
static OWNER:AtomicU64=AtomicU64::new(37);
struct ThreadControl{native_delivery_defer:AtomicU32,active_native_signal_frame:AtomicUsize,
    active_native_signal_frame_id:AtomicU64,next_native_signal_frame_id:AtomicU64,
    signal_upcall_stack:AtomicUsize,signal_upcall_stack_size:AtomicUsize}
static CONTROL:ThreadControl=ThreadControl{native_delivery_defer:AtomicU32::new(0),
    active_native_signal_frame:AtomicUsize::new(0),active_native_signal_frame_id:AtomicU64::new(0),
    next_native_signal_frame_id:AtomicU64::new(1),signal_upcall_stack:AtomicUsize::new(0x10000),signal_upcall_stack_size:AtomicUsize::new(65536)};
fn current_thread_control()->Option<((),&'static ThreadControl)>{Some(((),&CONTROL))}
struct NativeError;impl NativeError{fn raw(self)->i64{-5}}
fn native_process_id()->Result<u64,NativeError>{Ok(OWNER.load(Ordering::Acquire))}
fn map_kernel_errno(_:i64)->i32{5}
mod signal_jump { #[derive(Clone,Copy)]pub struct Transition(pub usize); }
pub mod upcall_guard {
"#,
    );
    program.push_str(guard);
    program.push_str("\n}\nmod actual { use super::*;\n");
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
pub fn run(){
    assert!(matches!(NativeFrame::new(0),Err(EINVAL)));
    assert_eq!(CONTROL.next_native_signal_frame_id.load(Ordering::Acquire),1);
    let mut outer=Box::pin(NativeFrame::new(17).unwrap());
    outer.as_mut().activate().unwrap();
    let outer_ptr=CONTROL.active_native_signal_frame.load(Ordering::Acquire);
    let outer_id=CONTROL.active_native_signal_frame_id.load(Ordering::Acquire);
    assert_eq!(outer_ptr,outer.as_ref().get_ref() as *const NativeFrame as usize);
    assert!(stack_is_active(&CONTROL,outer_ptr,core::mem::size_of::<NativeFrame>()));
    assert!(!stack_is_active(&CONTROL,outer_ptr+1,1));
    assert_eq!(outer.as_ref().token,17);assert_eq!(outer.as_ref().owner,37);
    assert_eq!(outer.as_mut().activate(),Err(EINVAL));
    // A fork image retains the old storage identity, not token authority.
    OWNER.store(42,Ordering::Release);
    CONTROL.signal_upcall_stack.store(0x30000,Ordering::Release);
    let mut inner=Box::pin(NativeFrame::new(29).unwrap());
    inner.as_mut().activate().unwrap();
    let inner_ptr=CONTROL.active_native_signal_frame.load(Ordering::Acquire);
    let inner_id=CONTROL.active_native_signal_frame_id.load(Ordering::Acquire);
    assert_ne!(inner_ptr,outer_ptr);assert!(inner_id>outer_id);
    assert_eq!(inner.as_ref().owner,42);assert_eq!(inner.as_ref().token,29);
    assert_eq!(inner.as_ref().stack,0x30000);assert_eq!(outer.as_ref().stack,0x10000);
    assert_eq!(outer.as_mut().deactivate(),Err(EINVAL));
    assert_eq!(CONTROL.active_native_signal_frame.load(Ordering::Acquire),inner_ptr);
    // Neither a reused address with the wrong identity nor a non-top record
    // can remove an unrelated live frame.
    CONTROL.active_native_signal_frame_id.store(outer_id,Ordering::Release);
    assert_eq!(inner.as_mut().deactivate(),Err(EINVAL));
    assert_eq!(inner.as_mut().activate(),Err(EINVAL));
    CONTROL.active_native_signal_frame_id.store(inner_id,Ordering::Release);
    inner.as_mut().deactivate().unwrap();
    assert_eq!(CONTROL.active_native_signal_frame.load(Ordering::Acquire),outer_ptr);
    assert_eq!(CONTROL.active_native_signal_frame_id.load(Ordering::Acquire),outer_id);
    assert_eq!(inner.as_mut().deactivate(),Err(EINVAL));
    outer.as_mut().deactivate().unwrap();
    assert_eq!(CONTROL.active_native_signal_frame.load(Ordering::Acquire),0);
    assert_eq!(CONTROL.active_native_signal_frame_id.load(Ordering::Acquire),0);
    // A new frame occupying the exact same storage must not reuse its tag.
    let old_id=inner.as_ref().id;
    inner.as_mut().set(NativeFrame::new(31).unwrap());
    let mut reused=inner;
    assert_eq!(reused.as_ref().get_ref() as *const NativeFrame as usize,inner_ptr);
    assert!(reused.as_ref().id>old_id);
    let guard=upcall_guard::Guard::enter(&CONTROL.native_delivery_defer).unwrap();
    reused.as_mut().activate().unwrap();reused.as_mut().deactivate().unwrap();
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),1);drop(guard);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    assert_eq!(unsafe{visit_abandoned(&CONTROL,0,|_|Ok(()))},Err(EINVAL));
    let guard=upcall_guard::Guard::enter(&CONTROL.native_delivery_defer).unwrap();
    let mut records=Vec::new();let mut target=0;
    // Repeated forks may retain more than one service's pending-signal limit
    // worth of copied callback frames. Walk the live chain, not a fixed array.
    for index in 0..100 {
        OWNER.store(37+index,Ordering::Release);
        CONTROL.signal_upcall_stack.store((index as usize+1)*65536,Ordering::Release);
        let mut frame=Box::pin(NativeFrame::new(100+index).unwrap());
        frame.as_mut().activate().unwrap();records.push(frame);
        if index==49{target=CONTROL.active_native_signal_frame_id.load(Ordering::Acquire);}
    }
    let top=CONTROL.active_native_signal_frame.load(Ordering::Acquire);
    let top_id=CONTROL.active_native_signal_frame_id.load(Ordering::Acquire);
    let mut staged=Vec::new();
    assert!(unsafe{stage_jump(&CONTROL,u64::MAX,0,|_|panic!("invalid target staged"))}.is_err());
    assert_eq!(unsafe{visit_abandoned(&CONTROL,u64::MAX,|frame|{staged.push(frame);Ok(())})},Err(EINVAL));
    assert!(staged.is_empty());
    assert_eq!(unsafe{retire_to(&CONTROL,u64::MAX)},Err(EINVAL));
    assert_eq!(CONTROL.active_native_signal_frame.load(Ordering::Acquire),top);
    CONTROL.active_native_signal_frame_id.store(top_id+1,Ordering::Release);
    assert_eq!(unsafe{visit_abandoned(&CONTROL,top_id+1,|_|Ok(()))},Err(EINVAL));
    CONTROL.active_native_signal_frame_id.store(top_id,Ordering::Release);
    assert_eq!(unsafe{visit_abandoned(&CONTROL,target,|_|Err(5))},Err(5));
    assert_eq!(CONTROL.active_native_signal_frame.load(Ordering::Acquire),top);
    unsafe{visit_abandoned(&CONTROL,target,|frame|{staged.push(frame);Ok(())})}.unwrap();
    assert_eq!(staged.len(),50);
    for (position,frame) in staged.iter().enumerate(){
        let index=99-position as u64;
        assert_eq!(frame.owner,37+index);assert_eq!(frame.token,100+index);
        assert_eq!(frame.stack,(index as usize+1)*65536);assert_eq!(frame.size,65536);
    }
    let mut chain=None;
    let task=unsafe{stage_jump(&CONTROL,target,0,|cursor|{chain=Some(cursor);signal_jump::Transition(37)})}.unwrap();
    assert_eq!(unsafe{(*task).0},37);
    let mut chain=chain.unwrap();
    assert!(unsafe{chain.next()}.is_err(),"active storage was treated as retired");
    let mut orphan_chain=None;
    let orphan_task=unsafe{stage_jump(&CONTROL,target,136,|cursor|{orphan_chain=Some(cursor);signal_jump::Transition(41)})}.unwrap();
    let expected=unsafe{core::ptr::addr_of!((*records[98].as_ref().get_ref()).jump)}.cast::<signal_jump::Transition>();
    assert_eq!(orphan_task.cast_const(),expected);
    assert!(unsafe{stage_jump(&CONTROL,target,112,|_|panic!("owned frame behind orphan accepted"))}.is_err());
    unsafe{retire_to(&CONTROL,target)}.unwrap();
    assert_eq!(CONTROL.active_native_signal_frame_id.load(Ordering::Acquire),target);
    assert_eq!(CONTROL.active_native_signal_frame.load(Ordering::Acquire),records[49].as_ref().get_ref() as *const NativeFrame as usize);
    assert_eq!(records[99].as_mut().activate(),Err(EINVAL));
    unsafe{records[99].as_mut().get_unchecked_mut()}.jump.write(signal_jump::Transition(0xbad));
    assert_eq!(unsafe{(*orphan_task).0},41,"current upcall storage reused the staged jump");
    let mut orphan_chain=orphan_chain.unwrap();let mut orphans=0;
    while let Some(frame)=unsafe{orphan_chain.next()}.unwrap(){
        assert_ne!(frame.owner,136);orphans+=1;
    }
    assert_eq!(orphans,49);
    for index in (50..100).rev(){
        let frame=unsafe{chain.next()}.unwrap().unwrap();
        assert_eq!(frame.owner,37+index as u64);
        assert_eq!(frame.token,100+index as u64);
        // Model immediate reclamation: unread records must not depend on a
        // previously returned record's contents remaining accessible.
        unsafe{records[index].as_mut().get_unchecked_mut()}.id=0;
    }
    assert!(unsafe{chain.next()}.unwrap().is_none());
    staged.clear();
    unsafe{visit_abandoned(&CONTROL,target,|frame|{staged.push(frame);Ok(())})}.unwrap();
    assert!(staged.is_empty());
    let mut remaining=None;
    unsafe{stage_jump(&CONTROL,0,0,|cursor|{remaining=Some(cursor);signal_jump::Transition(41)})}.unwrap();
    unsafe{retire_to(&CONTROL,0)}.unwrap();
    let mut remaining=remaining.unwrap();let mut seen=0;
    while unsafe{remaining.next()}.unwrap().is_some(){seen+=1;}
    assert_eq!(seen,50);
    assert_eq!(CONTROL.active_native_signal_frame.load(Ordering::Acquire),0);
    assert_eq!(CONTROL.active_native_signal_frame_id.load(Ordering::Acquire),0);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),1);
    drop(records);drop(guard);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),0);
    CONTROL.next_native_signal_frame_id.store(u64::MAX,Ordering::Release);
    assert!(matches!(NativeFrame::new(1),Err(EOVERFLOW)));
    assert_eq!(CONTROL.next_native_signal_frame_id.load(Ordering::Acquire),u64::MAX);
    CONTROL.native_delivery_defer.store(u32::MAX,Ordering::Release);
    assert_eq!(reused.as_mut().activate(),Err(EOVERFLOW));
    assert_eq!(CONTROL.active_native_signal_frame.load(Ordering::Acquire),0);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire),u32::MAX);
}
}
fn main(){actual::run()}
"#,
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-native-frame-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let compile = |source: &str| {
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
            .write_all(source.as_bytes())
            .unwrap();
        compiler.wait_with_output().unwrap()
    };
    let output = compile(&program);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let movable = program.replace("pub fn run(){", "pub fn run(){ let frame=Box::pin(NativeFrame::new(1).unwrap());let _=Pin::into_inner(frame);");
    let output = compile(&movable);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be unpinned"));
    let transferable = program.replace("pub fn run(){", "pub fn run(){ let frame=Box::pin(NativeFrame::new(1).unwrap());std::thread::spawn(move||drop(frame));");
    let output = compile(&transferable);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot be sent between threads safely")
    );
    std::fs::remove_dir_all(directory).unwrap();
}
