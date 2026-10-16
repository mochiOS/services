//! Execute the actual runtime mask-update function with controlled IPC/copyout.
use std::io::Write;
use std::process::{Command, Stdio};
struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn committed_unblock_completes_delivery_even_when_old_mask_copy_fails() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source.find("fn update_current_signal_mask(").unwrap();
    let end = start + source[start..].find("\n#[unsafe(no_mangle)]").unwrap();
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{ffi::c_int,cell::{Cell,RefCell},sync::atomic::{AtomicU64,Ordering}};
const EAGAIN:i32=11;const EINVAL:i32=22;const EFAULT:i32=14;const EINTR:i32=4;const EIO:i32=5;
mod posix_protocol {pub const SIGNAL_MASK_QUERY:u32=0;pub const SIGNAL_MASK_SET:u32=1;pub const SIGNAL_MASK_BLOCK:u32=2;pub const SIGNAL_MASK_UNBLOCK:u32=3;}
mod mochios_posix_client {pub mod signal {pub const SIGNAL_SET_MASK:i32=0;pub const SIGNAL_BLOCK:i32=1;pub const SIGNAL_UNBLOCK:i32=2;}}
struct ThreadControl {signal_mask:AtomicU64}
static CONTROL:ThreadControl=ThreadControl{signal_mask:AtomicU64::new(0)};
thread_local! {
    static EVENTS:RefCell<Vec<&'static str>>=const{RefCell::new(Vec::new())};
    static INPUT_ERROR:Cell<bool>=const{Cell::new(false)};
    static OUTPUT_ERROR:Cell<bool>=const{Cell::new(false)};
    static SERVICE_ERROR:Cell<bool>=const{Cell::new(false)};
    static DELIVERY_ERROR:Cell<bool>=const{Cell::new(false)};
}
fn event(value:&'static str){EVENTS.with_borrow_mut(|events|events.push(value));}
fn register_current_thread()->Option<(u64,&'static ThreadControl)>{Some((1,&CONTROL))}
fn service_signal_mask(control:&ThreadControl,operation:u32,requested:u64)->Result<u64,c_int>{
    event("commit");if SERVICE_ERROR.with(Cell::get){return Err(EIO);}
    let old=control.signal_mask.load(Ordering::Acquire);
    let new=match operation {1=>requested,2=>old|requested,3=>old&!requested,_=>old};
    control.signal_mask.store(new,Ordering::Release);Ok(old)
}
fn drain_pending_signals()->Result<(),c_int>{event("deliver");if DELIVERY_ERROR.with(Cell::get){Err(EINTR)}else{Ok(())}}
mod signal_memory {
    pub fn read_set(source:*const u64)->Result<u64,i32>{crate::event("read");if crate::INPUT_ERROR.with(|v|v.get()){Err(crate::EFAULT)}else{Ok(unsafe{source.read_unaligned()})}}
    pub fn write_set(output:*mut u64,value:u64)->Result<(),i32>{crate::event("write");if crate::OUTPUT_ERROR.with(|v|v.get()){Err(crate::EFAULT)}else{unsafe{output.write_unaligned(value)};Ok(())}}
}
fn reset(mask:u64){CONTROL.signal_mask.store(mask,Ordering::Release);EVENTS.with_borrow_mut(Vec::clear);INPUT_ERROR.set(false);OUTPUT_ERROR.set(false);SERVICE_ERROR.set(false);DELIVERY_ERROR.set(false);}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main(){
    let requested=1;
    for how in [0,2] {
        for output_error in [false,true] {
            for delivery_error in [false,true] {
                reset(3);OUTPUT_ERROR.set(output_error);DELIVERY_ERROR.set(delivery_error);
                let mut old=0;
                let value=if how==0 {2}else{requested};
                let result=update_current_signal_mask(how,&value,&mut old);
                assert_eq!(result,if output_error{Err(EFAULT)}else if delivery_error{Err(EINTR)}else{Ok(())});
                assert_eq!(CONTROL.signal_mask.load(Ordering::Acquire),2);
                if !output_error {assert_eq!(old,3);}
                EVENTS.with_borrow(|events|assert_eq!(events.as_slice(),["read","commit","write","deliver"],"copyout must not skip already committed delivery"));
            }
        }
    }
    reset(1);let mut alias=2;
    assert_eq!(update_current_signal_mask(0,&alias,&raw mut alias),Ok(()));
    assert_eq!(alias,1);assert_eq!(CONTROL.signal_mask.load(Ordering::Acquire),2);
    reset(3);let mut old=0;
    assert_eq!(update_current_signal_mask(i32::MIN,std::ptr::null(),&mut old),Ok(()));
    assert_eq!(old,3);EVENTS.with_borrow(|events|assert_eq!(events.as_slice(),["commit","write"]));
    for mode in 0..3 {
        reset(3);INPUT_ERROR.set(mode==0);SERVICE_ERROR.set(mode==1);
        let mut old=7;
        assert_eq!(update_current_signal_mask(if mode==2 {i32::MIN}else{2},&requested,&mut old),Err(match mode {0=>EFAULT,1=>EIO,_=>EINVAL}));
        assert_eq!(old,7);assert_eq!(CONTROL.signal_mask.load(Ordering::Acquire),3);
        EVENTS.with_borrow(|events|assert!(!events.contains(&"write")&&!events.contains(&"deliver")));
    }
    reset(1);OUTPUT_ERROR.set(true);
    assert_eq!(update_current_signal_mask(1,&requested,&mut old),Err(EFAULT));
    EVENTS.with_borrow(|events|assert_eq!(events.as_slice(),["read","commit","write"]));
}
"#);
    let temporary = Temporary(
        std::env::temp_dir().join(format!(
            "mochios-mask-completion-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )),
    );
    std::fs::create_dir(&temporary.0).unwrap();
    let binary = temporary.0.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-", "-o"])
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
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
