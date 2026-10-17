#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn dma_allocation_preserves_native_failures_and_never_recycles_published_storage() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
#[path={status:?}]mod status;
use status::Error;
use std::cell::{{Cell,RefCell}};
use std::sync::atomic::{{AtomicU64,Ordering}};
static NEXT_DMA_HANDLE:AtomicU64=AtomicU64::new(1);
const SUCCESS:u64=0;const PHYSICAL:u64=0x20000;
thread_local!{{
 static ALLOWED:Cell<bool>=const{{Cell::new(true)}};
 static CONTEXT:Cell<bool>=const{{Cell::new(true)}};
 static PROCESS:Cell<bool>=const{{Cell::new(true)}};
 static LOCKED:Cell<bool>=const{{Cell::new(false)}};
 static FRAME_FAIL:Cell<bool>=const{{Cell::new(false)}};
 static OFFSET_MODE:Cell<u8>=const{{Cell::new(0)}};
 static INSTALL_MODE:Cell<u8>=const{{Cell::new(0)}};
 static INSTALL_ERROR:Cell<u64>=const{{Cell::new(0)}};
 static COPY_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
 static FREE_FAIL:Cell<bool>=const{{Cell::new(false)}};
 static OWNED:Cell<bool>=const{{Cell::new(false)}};
 static ALLOCATIONS:Cell<usize>=const{{Cell::new(0)}};
 static RELEASED:Cell<usize>=const{{Cell::new(0)}};
 static COPIES:Cell<usize>=const{{Cell::new(0)}};
 static ZEROED:Cell<usize>=const{{Cell::new(0)}};
 static MEMORY:RefCell<Option<Box<[u8;8192]>>>=const{{RefCell::new(None)}};
}}
fn caller_has_dma_capability()->bool{{ALLOWED.get()}}
fn current_process()->Option<(u64,u64)>{{CONTEXT.get().then_some((1,4096))}}
fn page_align_up(value:u64)->Option<u64>{{value.checked_add(4095).map(|v|v&!4095)}}
enum InstallError{{Unpublished(u64),Retained(u64)}}
fn install_dma_buffer(_: &mut task::Process,pid:u64,table:u64,handle:u64,physical:u64,size:u64,count:usize)->Result<u64,InstallError>{{
 assert!(LOCKED.get());assert_eq!((pid,table,physical,size,count),(1,4096,PHYSICAL,8192,2));assert!(handle>0);
 assert!(MEMORY.with_borrow(|p|p.as_ref().unwrap().iter().all(|&b|b==0)));
 match INSTALL_MODE.get(){{
  1=>Err(InstallError::Unpublished(INSTALL_ERROR.get())),
  2=>{{OWNED.set(true);Err(InstallError::Retained(INSTALL_ERROR.get()))}},
  _=>{{OWNED.set(true);Ok(0x10000)}}
 }}
}}
fn release_dma_frames(physical:u64,count:usize){{assert!(!LOCKED.get());assert!(!OWNED.get());assert_eq!((physical,count),(PHYSICAL,2));
 assert!(MEMORY.with_borrow_mut(Option::take).is_some());RELEASED.set(RELEASED.get()+1);
}}
fn free(handle:u64)->u64{{assert!(!LOCKED.get());assert!(handle>0);assert!(OWNED.get());
 if FREE_FAIL.get(){{return Error::BackingFailure.into_raw();}}
 OWNED.set(false);release_dma_frames(PHYSICAL,2);0
}}
mod task{{pub struct Process;
 pub fn with_process_mut<T>(id:u64,f:impl FnOnce(&mut Process)->T)->Option<T>{{
  assert_eq!(id,1);if !crate::PROCESS.get(){{return None;}}assert!(!crate::LOCKED.replace(true));
  let result=f(&mut Process);assert!(crate::LOCKED.replace(false));Some(result)
 }}
}}
mod mem{{
 pub mod frame{{pub struct Frame;impl Frame{{pub fn start_address(&self)->Address{{Address}}}}pub struct Address;impl Address{{pub fn as_u64(self)->u64{{crate::PHYSICAL}}}}
  pub fn allocate_contiguous_frames(count:usize)->Result<Frame,()>{{
   assert_eq!(count,2);crate::ALLOCATIONS.set(crate::ALLOCATIONS.get()+1);if crate::FRAME_FAIL.get(){{return Err(());}}
   crate::MEMORY.with_borrow_mut(|p|{{assert!(p.is_none());*p=Some(Box::new([0x7b;8192]));}});Ok(Frame)
  }}
 }}
 pub mod paging{{pub fn physical_memory_offset()->Option<u64>{{match crate::OFFSET_MODE.get(){{
  1=>None,2=>Some(u64::MAX),3=>Some(u64::MAX-crate::PHYSICAL-4096),
  _=>Some(crate::MEMORY.with_borrow(|p|p.as_ref().unwrap().as_ptr()as u64)-crate::PHYSICAL)
 }}}}}}
}}
mod performance{{pub fn frame_zero_start()->u64{{assert!(!crate::LOCKED.get());0}}
 pub fn record_frame_zero(start:u64,size:usize){{assert_eq!((start,size),(0,8192));crate::ZEROED.set(crate::ZEROED.get()+1);}}
}}
mod syscall{{
 pub fn validate_user_ptr(pointer:u64,size:u64)->bool{{pointer==1&&size==32}}
 pub fn copy_to_user_native(pointer:u64,data:&[u8])->Result<(),crate::Error>{{
  assert!(!crate::LOCKED.get());assert!(crate::OWNED.get());assert_eq!((pointer,data.len()),(1,32));crate::COPIES.set(crate::COPIES.get()+1);
  let field=|offset|u64::from_ne_bytes(data[offset..offset+8].try_into().unwrap());
  assert!(field(0)>0);assert_eq!((field(8),field(16),field(24)),(0x10000,crate::PHYSICAL,8192));
  if let Some(e)=crate::COPY_ERROR.get(){{Err(e)}}else{{Ok(())}}
 }}
}}
"#,
        status = root.join("core/crates/abi/src/status.rs")
    );
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    program.push_str("#[repr(C)]\n");
    program.push_str(probe::between(
        abi,
        "pub struct DmaAllocation {",
        "/// 成功",
    ));
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/dma.rs"),
        "pub fn alloc(",
        "pub fn free(",
    ));
    program.push_str(r#"
fn reset(){assert!(!LOCKED.get());MEMORY.with_borrow_mut(Option::take);ALLOWED.set(true);CONTEXT.set(true);PROCESS.set(true);
 FRAME_FAIL.set(false);OFFSET_MODE.set(0);INSTALL_MODE.set(0);INSTALL_ERROR.set(0);COPY_ERROR.set(None);FREE_FAIL.set(false);
 OWNED.set(false);ALLOCATIONS.set(0);RELEASED.set(0);COPIES.set(0);ZEROED.set(0);
}
fn main(){
 reset();assert_eq!(alloc(4097,1),0);assert!(OWNED.get());assert_eq!((ALLOCATIONS.get(),ZEROED.get(),COPIES.get(),RELEASED.get()),(1,1,1,0));
 reset();ALLOWED.set(false);assert_eq!(alloc(4097,1),Error::AccessDenied.into_raw());assert_eq!(ALLOCATIONS.get(),0);
 for (length,pointer,error) in [(0,1,Error::InvalidArgument),(4097,0,Error::InvalidAddress),(u64::MAX,1,Error::LimitExceeded),(i64::MAX as u64,1,Error::LimitExceeded)]{
  reset();assert_eq!(alloc(length,pointer),error.into_raw());assert_eq!(ALLOCATIONS.get(),0);
 }
 reset();CONTEXT.set(false);assert_eq!(alloc(4097,1),Error::NotReady.into_raw());assert_eq!(ALLOCATIONS.get(),0);
 reset();FRAME_FAIL.set(true);assert_eq!(alloc(4097,1),Error::ResourceUnavailable.into_raw());assert_eq!(RELEASED.get(),0);
 for mode in 1..=3{reset();OFFSET_MODE.set(mode);assert_eq!(alloc(4097,1),Error::BackingFailure.into_raw());assert_eq!((RELEASED.get(),ZEROED.get(),COPIES.get()),(1,0,0));}
 for mode in [1,2]{for error in [Error::InvalidArgument.into_raw(),Error::ResourceUnavailable.into_raw(),Error::BackingFailure.into_raw()]{
  reset();INSTALL_MODE.set(mode);INSTALL_ERROR.set(error);assert_eq!(alloc(4097,1),error);
  assert_eq!(COPIES.get(),0);assert_eq!(RELEASED.get(),usize::from(mode==1));assert_eq!(OWNED.get(),mode==2);
 }}
 reset();PROCESS.set(false);assert_eq!(alloc(4097,1),Error::NotReady.into_raw());assert_eq!(RELEASED.get(),1);
 for error in [Error::InvalidAddress,Error::AccessDenied,Error::ResourceUnavailable,Error::BackingFailure,Error::NotReady]{reset();COPY_ERROR.set(Some(error));assert_eq!(alloc(4097,1),error.into_raw());assert_eq!(RELEASED.get(),1);assert!(!OWNED.get());}
 reset();COPY_ERROR.set(Some(Error::InvalidAddress));FREE_FAIL.set(true);assert_eq!(alloc(4097,1),Error::InvalidAddress.into_raw());assert_eq!(RELEASED.get(),0);assert!(OWNED.get());
 reset();
}
"#);
    probe::run(&program);
}
