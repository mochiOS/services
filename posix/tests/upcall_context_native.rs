//! Run native context entry points against the production upcall state and
//! FX validation. Host copies are controlled; no IRET/context switch is claimed.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn failed_context_operations_preserve_delivery_and_success_is_one_shot() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let source = include_str!("../../../core/src/syscall/upcall.rs");
    let thread = include_str!("../../../core/src/task/thread.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code,unused_attributes)]
extern crate self as mnu_abi;
use std::cell::{Cell,RefCell};
thread_local! {
    static CURRENT:Cell<bool>=const{Cell::new(true)};
    static PRESENT:Cell<bool>=const{Cell::new(true)};
    static LOCKED:Cell<bool>=const{Cell::new(false)};
    static COPY_ERROR:Cell<Option<status::Error>>=const{Cell::new(None)};
    static READS:Cell<usize>=const{Cell::new(0)};
    static WRITES:Cell<usize>=const{Cell::new(0)};
    static THREAD:RefCell<task::Thread>=RefCell::new(task::Thread::new());
}
"#,
    );
    program.push_str(&format!(
        "#[path={:?}]mod abi;pub use abi::*;\n",
        root.join("core/crates/abi/src/lib.rs")
    ));
    program.push_str("mod task {pub mod context {\n");
    program.push_str(probe::between(
        include_str!("../../../core/src/task/context.rs"),
        "const FXSAVE_AREA_SIZE:",
        "/// CPU コンテキスト",
    ));
    program.push_str("}\nmod thread {\n");
    program.push_str(probe::between(
        thread,
        "const THREAD_UPCALL_QUEUE_CAPACITY:",
        "// L4 風",
    ));
    program.push_str(r#"
pub struct Thread{state:ThreadUpcallState}
impl Thread {
    pub fn new()->Self{Self{state:ThreadUpcallState::new()}}
    pub fn start(&mut self,context:UserUpcallContext)->u64{
        self.state.install(0x1000,0x9000,true).unwrap();self.state.enqueue(u64::MAX).unwrap();
        self.state.begin(context).unwrap().token
    }
    pub fn upcall_snapshot(&self,token:u64)->Result<(UserUpcallContext,[u8;512]),ThreadUpcallError>{self.state.snapshot(token)}
    pub fn request_upcall_return_context(&mut self,token:u64,context:UserUpcallContext,fx:[u8;512])->Result<(),ThreadUpcallError>{self.state.request_return_context(token,context,fx)}
    pub fn request_upcall_return(&mut self,token:u64)->Result<(),ThreadUpcallError>{self.state.request_return(token)}
    pub fn request_context_restore(&mut self,context:UserUpcallContext,fx:[u8;512])->Result<(),ThreadUpcallError>{self.state.request_context_restore(context,fx)}
    pub fn take(&mut self)->Option<UserUpcallContext>{self.state.take_restored_context()}
}
}
pub use thread::{Thread,ThreadUpcallError,UserUpcallContext};
pub fn initial_fx()->[u8;512]{context::FxSaveArea::initial().snapshot_bytes()}
pub fn current_thread_id()->Option<u64>{crate::CURRENT.get().then_some(7)}
pub fn with_thread<T>(id:u64,body:impl FnOnce(&Thread)->T)->Option<T>{with_thread_mut(id,|thread|body(thread))}
pub fn with_thread_mut<T>(id:u64,body:impl FnOnce(&mut Thread)->T)->Option<T>{
    assert_eq!(id,7);if !crate::PRESENT.get(){return None;}
    assert!(!crate::LOCKED.replace(true));let result=crate::THREAD.with_borrow_mut(body);
    assert!(crate::LOCKED.replace(false));Some(result)
}
}
use task::{UserUpcallContext,ThreadUpcallError};
fn copy_from_user_native(pointer:u64,bytes:&mut[u8])->Result<(),status::Error>{
    assert!(!LOCKED.get());READS.set(READS.get()+1);
    if let Some(error)=COPY_ERROR.get(){return Err(error);}
    if pointer<4096{return Err(status::Error::InvalidAddress);}
    unsafe{bytes.copy_from_slice(core::slice::from_raw_parts(pointer as *const u8,bytes.len()));}Ok(())
}
fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),status::Error>{
    assert!(!LOCKED.get());WRITES.set(WRITES.get()+1);
    if let Some(error)=COPY_ERROR.get(){return Err(error);}
    if pointer<4096{return Err(status::Error::InvalidAddress);}
    unsafe{core::slice::from_raw_parts_mut(pointer as *mut u8,bytes.len()).copy_from_slice(bytes);}Ok(())
}
mod actual {use crate::{task,mnu_abi,UserUpcallContext,ThreadUpcallError,SUCCESS};
"#);
    for name in [
        "return_from_context",
        "restore_context",
        "return_from",
        "return_context",
        "inspect",
        "snapshot_context",
        "valid_user_return",
    ] {
        let start = source.find(&format!("fn {name}(")).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str("pub ");
        program.push_str(&source[start..end]);
    }
    program.push_str(r#"
}
fn main(){
    use actual::*;use status::Error;
    let mut image=unsafe{core::mem::zeroed::<ThreadUpcallSnapshot>()};
    image.instruction=0x4000;image.stack_pointer=0x8000;image.rflags=0x202;image.argument=u64::MAX;
    image.fx_state=task::initial_fx();
    image.registers.rcx=0x12345678;image.registers.r11=u64::MAX;
    let size=core::mem::size_of_val(&image)as u64;
    let original=return_context(&image).unwrap();
    let token=THREAD.with_borrow_mut(|thread|thread.start(original));
    let before=THREAD.with_borrow(|thread|thread.upcall_snapshot(token).unwrap());
    let input=&image as *const _ as u64;
    let mut output=image;let pointer=&mut output as *mut _ as u64;
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        COPY_ERROR.set(Some(error));
        assert_eq!(inspect(token,pointer,size),error.into_raw());assert_eq!(output,image);
        assert_eq!(return_from_context(token,input,size),error.into_raw());
        assert_eq!(restore_context(input,size),error.into_raw());
        assert_eq!(THREAD.with_borrow(|thread|thread.upcall_snapshot(token).unwrap()),before);
    }
    COPY_ERROR.set(None);
    assert_eq!(inspect(token,0,size),Error::InvalidAddress.into_raw());
    assert_eq!(inspect(token,pointer,size-1),Error::InvalidArgument.into_raw());
    assert_eq!(return_from_context(token,0,size),Error::InvalidAddress.into_raw());
    assert_eq!(return_from_context(token,input,size-1),Error::InvalidArgument.into_raw());
    assert_eq!(restore_context(0,size),Error::InvalidAddress.into_raw());
    assert_eq!(restore_context(input,size-1),Error::InvalidArgument.into_raw());
    let reads=READS.get();let writes=WRITES.get();
    assert_eq!(return_from_context(token+1,input,size),Error::InvalidArgument.into_raw());
    assert_eq!(return_from(token+1),Error::InvalidArgument.into_raw());
    assert_eq!(inspect(token+1,pointer,size),Error::InvalidArgument.into_raw());
    assert_eq!((READS.get(),WRITES.get()),(reads,writes));
    for (field,value) in [(0,0),(0,0xffff800000000000),(1,0xffff800000000000),(2,0),(2,0x3202)]{
        let mut bad=image;match field{0=>bad.instruction=value,1=>bad.stack_pointer=value,_=>bad.rflags=value}
        assert_eq!(return_from_context(token,&bad as *const _ as u64,size),Error::InvalidArgument.into_raw());
        assert_eq!(THREAD.with_borrow(|thread|thread.upcall_snapshot(token).unwrap()),before);
    }
    let mut bad=image;bad.fx_state[27]=0x80;
    assert_eq!(return_from_context(token,&bad as *const _ as u64,size),Error::InvalidArgument.into_raw());
    assert_eq!(restore_context(input,size),Error::NotReady.into_raw());
    for context_missing in [false,true]{
        if context_missing{CURRENT.set(false)}else{PRESENT.set(false)}
        for result in [return_from_context(token,input,size),return_from(token),inspect(token,pointer,size),restore_context(input,size)]{
            assert_eq!(result,Error::NotReady.into_raw());
        }
        CURRENT.set(true);PRESENT.set(true);
    }
    assert_eq!(inspect(token,pointer,size),0);assert_eq!(return_context(&output),Some(original));
    output.instruction=0;output.registers.rcx=0;
    assert_eq!(THREAD.with_borrow(|thread|thread.upcall_snapshot(token).unwrap()),before);
    assert_eq!(inspect(token,pointer,size),0);assert_eq!(return_context(&output),Some(original));
    assert_eq!(return_from_context(token,input,size),0);
    assert_eq!(return_from_context(token,input,size),Error::InvalidArgument.into_raw());
    assert_eq!(inspect(token,pointer,size),Error::InvalidArgument.into_raw());
    assert_eq!(THREAD.with_borrow_mut(|thread|thread.take()),Some(original));
    assert_eq!(THREAD.with_borrow_mut(|thread|thread.take()),None);
    assert_eq!(return_from(token),Error::InvalidArgument.into_raw());
    assert_eq!(restore_context(input,size),0);assert_eq!(restore_context(input,size),Error::NotReady.into_raw());
    assert_eq!(THREAD.with_borrow_mut(|thread|thread.take()),Some(original));
    let token=THREAD.with_borrow_mut(|thread|thread.start(original));
    assert_eq!(return_from(token),0);
    assert_eq!(THREAD.with_borrow_mut(|thread|thread.take()),Some(original));
    assert_eq!(return_from(token),Error::InvalidArgument.into_raw());
}
"#);
    probe::run(&program);
}
