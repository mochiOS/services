//! Execute production pair creation and endpoint owners with scripted Handle
//! registration boundaries. Handle-table node allocation is not modeled here.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn pair_allocation_registration_and_copy_failures_release_both_endpoint_owners() {
    let objects = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/src/task/fd_table.rs")
        .canonicalize()
        .unwrap();
    let mut program = String::from(
        "#![feature(allocator_api)]\n#![allow(dead_code)]\nextern crate alloc;\nextern crate self as mnu_abi;\npub mod status {\n",
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str(r#"
}
use status::Error;
use std::cell::{Cell,RefCell};
use std::sync::Arc;
const SUCCESS:u64=0;
pub const HANDLE_OPTION_NONBLOCKING:u64=1;
#[repr(C)]pub struct StreamPair{read:u32,write:u32}
thread_local! {
    static FAIL_AFTER:Cell<Option<usize>>=const{Cell::new(None)};
    static CURRENT:Cell<bool>=const{Cell::new(true)};
    static PRESENT:Cell<bool>=const{Cell::new(true)};
    static FULL:Cell<bool>=const{Cell::new(false)};
    static LIVE:Cell<bool>=const{Cell::new(false)};
    static REFERENCES:Cell<[usize;2]>=const{Cell::new([0,0])};
    static CLOSES:Cell<[usize;2]>=const{Cell::new([0,0])};
    static INSERT_FAILURE:Cell<usize>=const{Cell::new(0)};
    static INSERTS:Cell<usize>=const{Cell::new(0)};
    static COPY_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static COPIES:Cell<usize>=const{Cell::new(0)};
    static OUTPUT:Cell<[u32;2]>=const{Cell::new([0;2])};
    static PROCESS:RefCell<task::Process>=const{RefCell::new(task::Process::new())};
}
struct FaultAllocator;
unsafe impl std::alloc::GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8{
        let fail=FAIL_AFTER.with(|state|match state.get(){
            Some(0)=>{state.set(None);true},Some(count)=>{state.set(Some(count-1));false},None=>false,
        });
        if fail{std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(layout)}}
    }
    unsafe fn dealloc(&self,pointer:*mut u8,layout:std::alloc::Layout){unsafe{std::alloc::System.dealloc(pointer,layout)}}
}
#[global_allocator]static ALLOCATOR:FaultAllocator=FaultAllocator;
mod interrupt{pub mod spinlock{
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T>{
        pub fn new(value:T)->Self{Self(std::sync::Mutex::new(value))}
        pub fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}
    }
}}
mod syscall{
    pub mod security{pub fn current_process_id()->Option<u64>{crate::CURRENT.get().then_some(7)}}
    pub mod fs{
        pub fn alloc_stream_state()->Option<usize>{
            if crate::FULL.get(){return None;}
            assert!(!crate::LIVE.replace(true));crate::REFERENCES.set([1,1]);Some(42)
        }
        pub fn close_pipe_endpoint_from_kernel(stream:usize,write:bool){
            assert_eq!(stream,42);let index=usize::from(write);
            let mut references=crate::REFERENCES.get();assert_eq!(references[index],1);
            references[index]=0;crate::REFERENCES.set(references);
            let mut closes=crate::CLOSES.get();closes[index]+=1;crate::CLOSES.set(closes);
            if references==[0,0]{assert!(crate::LIVE.replace(false));}
        }
    }
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{
        assert_eq!((pointer,bytes.len()),(1,8));crate::COPIES.set(crate::COPIES.get()+1);
        if let Some(error)=crate::COPY_ERROR.get(){return Err(error);}
        crate::OUTPUT.set([u32::from_ne_bytes(bytes[..4].try_into().unwrap()),
            u32::from_ne_bytes(bytes[4..].try_into().unwrap())]);Ok(())
    }
}
"#);
    program.push_str(&format!("#[path={objects:?}]mod objects;\n"));
    program.push_str(
        r#"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct HandleRights(u64);
impl HandleRights{
    const READ:Self=Self(1);const WRITE:Self=Self(2);const WAIT:Self=Self(4);
    const CONTROL:Self=Self(8);const DUPLICATE:Self=Self(16);const TRANSFER:Self=Self(32);
    fn union(self,other:Self)->Self{Self(self.0|other.0)}
}
enum KernelObject{File(Arc<objects::FileHandle>)}
struct ObjectHandleEntry{object:KernelObject,rights:HandleRights}
impl ObjectHandleEntry{fn new(object:KernelObject,rights:HandleRights)->Self{Self{object,rights}}}
#[derive(Clone,Copy)]struct Handle(u32);
impl Handle{fn raw(self)->u32{self.0}}
mod task{
    use super::*;
    pub use objects::FileHandle;
    pub struct Table{pub entries:[Option<ObjectHandleEntry>;2]}
    impl Table{
        pub fn insert(&mut self,entry:ObjectHandleEntry)->Option<Handle>{
            let call=INSERTS.get()+1;INSERTS.set(call);
            if INSERT_FAILURE.get()==call{return None;}
            let index=self.entries.iter().position(Option::is_none)?;
            self.entries[index]=Some(entry);Some(Handle(index as u32+1))
        }
        pub fn close(&mut self,handle:Handle){drop(self.entries[handle.0 as usize-1].take());}
    }
    pub struct Process{pub table:Table}
    impl Process{
        pub const fn new()->Self{Self{table:Table{entries:[None,None]}}}
        pub fn object_handles_mut(&mut self)->&mut Table{&mut self.table}
    }
    pub fn with_process_mut<T>(id:u64,operation:impl FnOnce(&mut Process)->T)->Option<T>{
        assert_eq!(id,7);if !PRESENT.get(){return None;}
        PROCESS.with_borrow_mut(|process|Some(operation(process)))
    }
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn stream_pair_create(",
        "pub fn launch_value_get(",
    ));
    program.push_str(
        r#"
fn reset(){
    PROCESS.set(task::Process::new());assert!(!LIVE.get());
    CURRENT.set(true);PRESENT.set(true);FULL.set(false);CLOSES.set([0,0]);
    INSERTS.set(0);INSERT_FAILURE.set(0);COPIES.set(0);COPY_ERROR.set(None);OUTPUT.set([0;2]);
}
fn empty(){
    assert!(!LIVE.get());assert_eq!(REFERENCES.get(),[0,0]);
    assert_eq!(CLOSES.get(),[1,1]);
    PROCESS.with_borrow(|process|assert!(process.table.entries.iter().all(Option::is_none)));
    assert_eq!(OUTPUT.get(),[0;2]);
}
fn main(){
    reset();assert_eq!(stream_pair_create(0),Error::InvalidAddress.into_raw());
    assert!(!LIVE.get());assert_eq!(CLOSES.get(),[0,0]);
    CURRENT.set(false);assert_eq!(stream_pair_create(1),Error::NotReady.into_raw());
    assert!(!LIVE.get());assert_eq!(CLOSES.get(),[0,0]);
    reset();FULL.set(true);assert_eq!(stream_pair_create(1),Error::ResourceUnavailable.into_raw());
    assert!(!LIVE.get());assert_eq!(CLOSES.get(),[0,0]);assert_eq!(INSERTS.get(),0);
    // Two OpenFile Arcs and two KernelObject Arcs: all actual allocations.
    for allocation in 0..4 {
        reset();FAIL_AFTER.set(Some(allocation));
        let result=stream_pair_create(1);
        assert_eq!(FAIL_AFTER.get(),None);
        assert_eq!(result,Error::ResourceUnavailable.into_raw());empty();
        assert_eq!(INSERTS.get(),0);assert_eq!(COPIES.get(),0);
    }
    reset();PRESENT.set(false);assert_eq!(stream_pair_create(1),Error::NotReady.into_raw());empty();
    for failure in [1,2] {
        reset();INSERT_FAILURE.set(failure);
        assert_eq!(stream_pair_create(1),Error::ResourceUnavailable.into_raw());empty();
        assert_eq!(INSERTS.get(),failure);assert_eq!(COPIES.get(),0);
    }
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure] {
        reset();COPY_ERROR.set(Some(error));
        assert_eq!(stream_pair_create(1),error.into_raw());empty();assert_eq!(COPIES.get(),1);
    }
    reset();assert_eq!(stream_pair_create(1),0);
    assert_eq!(OUTPUT.get(),[1,2]);assert!(LIVE.get());assert_eq!(CLOSES.get(),[0,0]);
    PROCESS.with_borrow_mut(|process|{
        let entries=&process.table.entries;
        assert_eq!(entries[0].as_ref().unwrap().rights,HandleRights(61));
        assert_eq!(entries[1].as_ref().unwrap().rights,HandleRights(62));
        let KernelObject::File(read)=&entries[0].as_ref().unwrap().object;
        let KernelObject::File(write)=&entries[1].as_ref().unwrap().object;
        assert_eq!(read.stream_endpoint(),Some((42,false)));
        assert_eq!(write.stream_endpoint(),Some((42,true)));
        assert!(!Arc::ptr_eq(&read.open,&write.open));
        process.table.close(Handle(1));assert!(LIVE.get());
        process.table.close(Handle(2));assert!(!LIVE.get());
    });
    assert_eq!(CLOSES.get(),[1,1]);
}
"#,
    );
    probe::run_with_toolchain(&program, "nightly-2026-07-16");
}
