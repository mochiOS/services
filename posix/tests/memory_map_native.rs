//! Execute the native mapper, substituting only process storage, page tables
//! and backing transport. Placement, validation and accounting are production.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_mapping_validates_authority_and_preserves_state_before_publication() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
#[path={status:?}]pub mod status;
#[path={request:?}]pub mod memory_map;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::cell::{{Cell,RefCell}};
use status::Error;
#[macro_export]macro_rules! debug{{($($arg:tt)*)=>{{}}}}
thread_local!{{
 static THREAD:Cell<bool>=const{{Cell::new(true)}};
 static OWNER:Cell<bool>=const{{Cell::new(true)}};
 static PROCESS:Cell<bool>=const{{Cell::new(true)}};
 static ROOT:Cell<bool>=const{{Cell::new(true)}};
 static LOCKED:Cell<bool>=const{{Cell::new(false)}};
 static LOOKUPS:Cell<usize>=const{{Cell::new(0)}};
 static GRANTED:Cell<u64>=const{{Cell::new(67)}};
 static KIND:Cell<u8>=const{{Cell::new(0)}};
 static GATE:Cell<Option<Error>>=const{{Cell::new(None)}};
 static LOWER:Cell<u64>=const{{Cell::new(0)}};
 static FLUSH:Cell<u64>=const{{Cell::new(0)}};
 static COPY:Cell<Option<Error>>=const{{Cell::new(None)}};
 static WALK_FAIL:Cell<bool>=const{{Cell::new(false)}};
 static OCCUPIED:Cell<bool>=const{{Cell::new(false)}};
 static FAIL_ALLOC:Cell<bool>=const{{Cell::new(false)}};
 static STATE:RefCell<task::Process>=const{{RefCell::new(task::Process{{regions:Vec::new(),cursor:0}})}};
}}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{{
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{{
  if FAIL_ALLOC.try_with(|f|f.replace(false)).unwrap_or(false){{std::ptr::null_mut()}}else{{unsafe{{std::alloc::System.alloc(l)}}}}
 }}
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(p,l)}}}}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
fn current_thread_id()->Option<u64>{{THREAD.get().then_some(1)}}
fn randomized_mapping_base(_:u64,floor:u64,_:u64)->u64{{assert!(LOCKED.get());floor}}
mod config{{pub struct Exec{{pub memory_map_base_min:u64,pub memory_map_aslr_max_pages:u64}}
 pub struct Config{{pub exec:Exec}} pub fn kernel()->Config{{Config{{exec:Exec{{memory_map_base_min:0x10000,memory_map_aslr_max_pages:1}}}}}}}}
mod mem{{
 #[path={usage:?}]pub mod mapping_usage;
 pub mod shared_memory{{pub struct SharedMemory;
  impl SharedMemory{{pub fn new(_:u64,_:u64)->Result<Self,crate::Error>{{Ok(Self)}}}}
 }}
 pub mod vm_object{{
  use crate::*;
  #[derive(Debug)]pub struct VmObject{{pub ram:bool}}
  impl VmObject{{
   pub fn provider(_:u64,id:u64)->Result<Self,u64>{{assert_eq!(id,77);Ok(Self{{ram:false}})}}
   pub fn shared_memory(_:Arc<super::shared_memory::SharedMemory>)->Self{{Self{{ram:true}}}}
   pub fn memory_identity(&self)->Option<u64>{{self.ram.then_some(1)}}
   pub fn memory_generation(&self)->Option<u64>{{Some(1)}}
   pub fn with_memory_generation_native<T>(&self,_:Option<u64>,f:impl FnOnce()->Result<T,Error>)->Result<T,Error>{{
    assert!(LOCKED.get());if let Some(e)=GATE.get(){{return Err(e);}}f()
   }}
   pub fn flush_unmapped_range(&self,_:u64,_:u64)->Result<(),u64>{{assert!(!LOCKED.get());if FLUSH.get()!=0{{Err(FLUSH.get())}}else{{Ok(())}}}}
  }}
 }}
 pub mod paging{{
  pub unsafe fn next_user_page_entry(_:u64,_:u64,_:u64)->Result<Option<u64>,u64>{{
   assert!(crate::LOCKED.get());if crate::WALK_FAIL.get(){{Err(9)}}else{{Ok(None)}}
  }}
  pub fn is_user_range_occupied_in_table(_:u64,start:u64,_:u64)->bool{{assert!(crate::LOCKED.get());crate::OCCUPIED.get()&&start==0x10000}}
 }}
 pub mod mapping_replace{{
  pub fn replace(p:&mut crate::task::Process,r:crate::task::MemoryRegion,_:Option<u64>)->Result<Vec<crate::task::MemoryRegion>,crate::Error>{{
   assert!(crate::LOCKED.get());let old=std::mem::replace(&mut p.regions,vec![r]);Ok(old)
  }}
 }}
}}
mod task{{
 use crate::*;
 #[derive(Clone,Copy)]pub struct HandleRights(pub u64);
 impl HandleRights{{pub const READ:Self=Self(1);pub const WRITE:Self=Self(2);pub const MAP:Self=Self(64);
  pub fn union(self,r:Self)->Self{{Self(self.0|r.0)}}pub fn contains(self,r:Self)->bool{{self.0&r.0==r.0}}
 }}
 pub enum KernelObject{{Provider(u64),VmObject(Arc<mem::vm_object::VmObject>),Other}}
 pub struct Thread;impl Thread{{pub fn process_id(&self)->u64{{2}}}}
 pub fn with_thread<T>(id:u64,f:impl FnOnce(&Thread)->T)->Option<T>{{assert_eq!(id,1);OWNER.get().then(||f(&Thread))}}
 pub fn with_process_mut<T>(id:u64,f:impl FnOnce(&mut Process)->T)->Option<T>{{
  assert_eq!(id,2);if !PROCESS.get(){{return None;}}assert!(!LOCKED.replace(true));
  let r=STATE.with_borrow_mut(f);assert!(LOCKED.replace(false));Some(r)
 }}
 pub struct Process{{pub regions:Vec<MemoryRegion>,pub cursor:u64}}
 impl Process{{
  pub fn mapping_cursor(&self)->u64{{self.cursor}}
  pub fn set_mapping_cursor(&mut self,x:u64){{self.cursor=x;}}
  pub fn page_table(&self)->Option<u64>{{ROOT.get().then_some(4096)}}
  pub fn memory_regions(&self)->&[MemoryRegion]{{&self.regions}}
  pub fn mmio_mappings(&self)->&[Borrowed]{{&[]}}pub fn dma_buffers(&self)->&[Borrowed]{{&[]}}
  pub fn add_memory_region(&mut self,r:MemoryRegion)->bool{{self.regions.push(r);true}}
 }}
 pub struct Borrowed;impl Borrowed{{pub fn virt_start(&self)->u64{{0}}pub fn end(&self)->Option<u64>{{Some(0)}}}}
 #[derive(Clone)]pub struct MemoryRegion{{pub address:u64,pub size:u64,pub access:u64,pub shared:bool,pub max:u64,pub object:Option<Arc<mem::vm_object::VmObject>>}}
 impl MemoryRegion{{
  pub fn anonymous(a:u64,s:u64,access:u64,_:u64,_:bool,shared:bool)->Self{{Self{{address:a,size:s,access,shared,max:7,object:None}}}}
  pub fn file_backed(a:u64,s:u64,access:u64,_:u64,o:Arc<mem::vm_object::VmObject>,_:u64,_:bool,shared:bool,max:u64)->Self{{Self{{address:a,size:s,access,shared,max,object:Some(o)}}}}
  pub fn start(&self)->u64{{self.address}}pub fn end(&self)->Option<u64>{{self.address.checked_add(self.size)}}
  pub fn len(&self)->u64{{self.size}}pub fn is_shared(&self)->bool{{self.shared}}pub fn permits_access(&self,a:u64)->bool{{self.access&a==a}}
  pub fn backing(&self)->&Self{{self}}pub fn file_object(&self)->Option<&Arc<mem::vm_object::VmObject>>{{self.object.as_ref()}}
  pub fn file_offset(&self)->u64{{0}}
 }}
}}
mod syscall{{
 pub fn copy_from_user_native(pointer:u64,out:&mut[u8])->Result<(),crate::Error>{{
  assert!(!crate::LOCKED.get());if let Some(e)=crate::COPY.get(){{return Err(e);}}
  out.copy_from_slice(unsafe{{std::slice::from_raw_parts(pointer as *const u8,out.len())}});Ok(())
 }}
 pub mod handle{{
  use crate::*;
  pub fn object_with_rights_native(raw:u64,required:task::HandleRights)->Result<(task::KernelObject,task::HandleRights),Error>{{
   assert!(!LOCKED.get());LOOKUPS.set(LOOKUPS.get()+1);
   assert_eq!(required.0,if EXPECT_WRITE.get(){{67}}else{{65}});
   if raw!=17{{return Err(Error::InvalidArgument);}}
   let rights=task::HandleRights(GRANTED.get());if !rights.contains(required){{return Err(Error::AccessDenied);}}
   let o=match KIND.get(){{0=>task::KernelObject::Provider(1),1=>task::KernelObject::VmObject(Arc::new(mem::vm_object::VmObject{{ram:true}})),_=>task::KernelObject::Other}};
   Ok((o,rights))
  }}
  pub fn provider_memory_object(_: &u64)->Result<u64,u64>{{assert!(!LOCKED.get());if LOWER.get()!=0{{Err(LOWER.get())}}else{{Ok(if ABSENT.get(){{0}}else{{77}})}}}}
 }}
}}
thread_local!{{static EXPECT_WRITE:Cell<bool>=const{{Cell::new(false)}};static ABSENT:Cell<bool>=const{{Cell::new(false)}};}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        request = root.join("core/crates/abi/src/memory_map.rs"),
        usage = root.join("core/src/mem/mapping_usage.rs"),
    );
    for line in include_str!("../../../core/crates/abi/src/lib.rs").lines() {
        if line.starts_with("pub const MEMORY_ACCESS_") || line.starts_with("pub const MEMORY_MAP_")
        {
            program.push_str(line);
            program.push('\n');
        }
    }
    let source = include_str!("../../../core/src/syscall/process.rs");
    probe::constants(&mut program, source, &["USER_SPACE_END"]);
    program.push_str(probe::between(
        source,
        "#[inline]\nfn page_align_up(",
        "/// Exit",
    ));
    program.push_str(probe::between(
        source,
        "pub fn memory_map(",
        "/// Removes native virtual-memory",
    ));
    program.push_str(r#"
fn reset(){
 assert!(!LOCKED.get());THREAD.set(true);OWNER.set(true);PROCESS.set(true);ROOT.set(true);
 LOOKUPS.set(0);GRANTED.set(67);KIND.set(0);GATE.set(None);LOWER.set(0);FLUSH.set(0);COPY.set(None);
 WALK_FAIL.set(false);OCCUPIED.set(false);EXPECT_WRITE.set(false);ABSENT.set(false);
 STATE.with_borrow_mut(|p|{p.regions.clear();p.regions.reserve(4);p.cursor=0;});
}
fn map(handle:u64)->u64{memory_map(0,4096,3,0,handle,0)}
fn unchanged(){STATE.with_borrow(|p|{assert!(p.regions.is_empty());assert_eq!(p.cursor,0);});}
fn main(){
 reset();assert_eq!(map(0),0x10000);assert_eq!(LOOKUPS.get(),0);
 STATE.with_borrow(|p|assert_eq!(p.cursor,0x11000));
 assert_eq!(map(0),0x11000);STATE.with_borrow(|p|assert_eq!(p.cursor,0x12000));
 // Exact placement does not advance the hint or reserve its intervening gap.
 reset();assert_eq!(memory_map(0x800000,4096,3,1,0,0),0x800000);
 STATE.with_borrow(|p|assert_eq!(p.cursor,0));
 assert_eq!(map(0),0x10000);
 reset();STATE.with_borrow_mut(|p|p.cursor=0x800000);
 assert_eq!(memory_map(0x10000,4096,3,1,0,0),0x10000);
 STATE.with_borrow(|p|assert_eq!(p.cursor,0x800000));
 reset();assert_eq!(map(17),0x10000);assert_eq!(LOOKUPS.get(),1);
 reset();KIND.set(1);assert_eq!(map(17),0x10000);STATE.with_borrow(|p|assert_eq!(p.regions[0].max,3));
 reset();GRANTED.set(65);assert_eq!(map(17),0x10000); // private COW needs no backing WRITE
 reset();GRANTED.set(65);assert_eq!(memory_map(0,4096,1,2,17,0),0x10000);STATE.with_borrow(|p|assert_eq!(p.regions[0].max,5));
 reset();GRANTED.set(65);EXPECT_WRITE.set(true);assert_eq!(memory_map(0,4096,3,2,17,0),Error::AccessDenied.into_raw());unchanged();
 reset();KIND.set(1);assert_eq!(memory_map(0,4096,4,0,17,0),Error::AccessDenied.into_raw());unchanged();
 reset();KIND.set(2);assert_eq!(map(17),Error::InvalidArgument.into_raw());unchanged();
 reset();assert_eq!(map(18),Error::InvalidArgument.into_raw());unchanged();
 reset();ABSENT.set(true);assert_eq!(map(17),Error::InvalidArgument.into_raw());unchanged();
 for error in [(-38i64)as u64,(-5i64)as u64,Error::PeerClosed.into_raw()]{reset();LOWER.set(error);assert_eq!(map(17),error);unchanged();}
 for error in [Error::NotReady,Error::BackingFailure]{reset();GATE.set(Some(error));assert_eq!(map(17),error.into_raw());unchanged();}
 for mode in 0..4{reset();match mode{0=>THREAD.set(false),1=>OWNER.set(false),2=>PROCESS.set(false),_=>ROOT.set(false)};
  assert_eq!(map(0),Error::NotReady.into_raw());unchanged();}
 reset();FAIL_ALLOC.set(true);assert_eq!(map(17),Error::ResourceUnavailable.into_raw());unchanged();
 reset();FAIL_ALLOC.set(true);assert_eq!(memory_map(0,4096,3,2,0,0),Error::ResourceUnavailable.into_raw());unchanged();
 for args in [(0,0,3,0,0,0),(0,4096,8,0,0,0),(0,4096,6,0,0,0),(0,4096,3,8,0,0),
  (0,4096,3,4,0,0),(0,4096,3,1,0,0),(1,4096,3,1,0,0),(0,4096,3,0,0,4096),(0,4096,3,0,17,1)]{
  reset();assert_eq!(memory_map(args.0,args.1,args.2,args.3,args.4,args.5),Error::InvalidArgument.into_raw());assert_eq!(LOOKUPS.get(),0);unchanged();}
 reset();assert_eq!(memory_map(0,u64::MAX,3,0,0,0),Error::LimitExceeded.into_raw());unchanged();
 reset();assert_eq!(memory_map(0,8192,3,0,17,u64::MAX&!4095),Error::LimitExceeded.into_raw());unchanged();
 reset();assert_eq!(memory_map(USER_SPACE_END+1,4096,3,1,0,0),Error::InvalidAddress.into_raw());unchanged();
 reset();OCCUPIED.set(true);assert_eq!(memory_map(0x10000,4096,3,1,0,0),Error::AlreadyExists.into_raw());unchanged();
 reset();OCCUPIED.set(true);assert_eq!(map(0),0x11000);
 let request=memory_map::Request{length:4096,access:3,byte_ceiling:4096,..Default::default()};
 reset();let bytes=request.encode();assert_eq!(memory_map_bounded(bytes.as_ptr()as u64,64),0x10000);
 reset();let bytes=memory_map::Request{byte_ceiling:4095,..request}.encode();assert_eq!(memory_map_bounded(bytes.as_ptr()as u64,64),Error::ResourceUnavailable.into_raw());unchanged();
 reset();WALK_FAIL.set(true);let bytes=request.encode();assert_eq!(memory_map_bounded(bytes.as_ptr()as u64,64),Error::BackingFailure.into_raw());unchanged();
 reset();COPY.set(Some(Error::InvalidAddress));assert_eq!(memory_map_bounded(0,64),Error::InvalidAddress.into_raw());unchanged();
 reset();assert_eq!(memory_map_bounded(0,63),Error::InvalidArgument.into_raw());unchanged();
 reset();let mut bytes=request.encode();bytes[63]=1;assert_eq!(memory_map_bounded(bytes.as_ptr()as u64,64),Error::InvalidArgument.into_raw());unchanged();
 // Replacement writeback remains outside the process lock. A provider's
 // opaque post-publication error is not authorization to replay the map.
 reset();EXPECT_WRITE.set(true);assert_eq!(memory_map(0x10000,4096,3,3,17,0),0x10000);
 FLUSH.set((-28i64)as u64);assert_eq!(memory_map(0x10000,4096,3,5,0,0),(-28i64)as u64);
 STATE.with_borrow(|p|{assert_eq!(p.regions.len(),1);assert!(p.regions[0].object.is_none());});
}
"#);
    probe::run_with_toolchain(&program, "nightly-2026-07-16");
}

#[test]
fn bounded_and_unbounded_posix_mapping_choose_errno_only_in_userspace() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code,non_camel_case_types)]
extern crate self as mnu_abi;
extern crate self as mochios_posix_client;
extern crate self as mochios_posix_protocol;
pub mod status{{
{}
 #[path={normalize:?}]mod wire;
 pub use wire::normalize_failure;
}}
pub const STATUS_EIO:i32=-5;pub const STATUS_EAGAIN:i32=-11;
#[path={errno:?}]pub mod newlib_errno;
#[path={memory:?}]pub mod memory;
use std::cell::Cell;
type c_int=i32;
mod posix_protocol{{pub const RLIM_INFINITY:u64=u64::MAX;}}
thread_local!{{static RESULT:Cell<u64>=const{{Cell::new(0)}};static BOUNDED:Cell<bool>=const{{Cell::new(false)}};}}
"#,
        include_str!("../../../core/crates/abi/src/status.rs"),
        normalize = root.join("user/crates/posix-protocol/src/status.rs"),
        errno = root.join("user/crates/posix-client/src/newlib_errno.rs"),
        memory = root.join("user/crates/posix-client/src/memory.rs"),
    );
    for line in include_str!("../../../core/crates/abi/src/lib.rs").lines() {
        if line.starts_with("pub const MEMORY_ACCESS_") || line.starts_with("pub const MEMORY_MAP_")
        {
            program.push_str(line);
            program.push('\n');
        }
    }
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["MEMORY_SYNC_DEFERRED", "MEMORY_SYNC_REFRESH"],
    );
    program.push_str(
        "mod syscall {\nuse crate::mnu_abi;\nuse mnu_abi::status::Error as NativeError;\n",
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct SysError",
        "#[inline(always)]",
    ));
    program.push_str(&format!(r#"
 #[derive(Debug,PartialEq)]pub enum SyscallNumber{{MemoryMap}}
 pub fn raw_syscall6(number:SyscallNumber,a:u64,l:u64,access:u64,options:u64,h:u64,offset:u64)->RawSyscallResult{{
  assert!(!crate::BOUNDED.get());assert_eq!(number,SyscallNumber::MemoryMap);
  assert_eq!((a,l,access,options,h,offset),(4096,8192,3,2,17,4096));RawSyscallResult::new(crate::RESULT.get())
 }}
 pub mod memory{{
  #[path={request:?}]mod request;pub use request::Request;
  pub fn map_bounded(r:Request)->Result<u64,super::SysError>{{
   assert!(crate::BOUNDED.get());assert_eq!((r.address,r.length,r.access,r.options,r.backing_handle,r.backing_offset,r.byte_ceiling,r.reserved),(4096,8192,3,2,17,4096,16384,0));
   super::RawSyscallResult::new(crate::RESULT.get()).into_result()
  }}
 }}
}}
mod address_space{{use crate::{{c_int,posix_protocol,syscall}};
"#, request=root.join("core/crates/abi/src/memory_map.rs")));
    program.push_str(probe::between(
        include_str!("../../../user/crates/newlib-runtime/src/address_space.rs"),
        "#[derive(Clone, Copy)]",
        "/// Read before STATE",
    ));
    program.push_str(r#"
}
fn main(){
 for bounded in [false,true]{
  BOUNDED.set(bounded);
  let limit=address_space::Limit::from_soft(if bounded{16384}else{u64::MAX});
  for (error,errno) in [(status::Error::InvalidAddress,12),(status::Error::InvalidArgument,22),
   (status::Error::AccessDenied,13),(status::Error::ResourceUnavailable,12),(status::Error::NotReady,11),
   (status::Error::LimitExceeded,139),(status::Error::BackingFailure,5),(status::Error::AlreadyExists,17),
   (status::Error::NotFound,2),(status::Error::PeerClosed,32)]{
   RESULT.set(error.into_raw());assert_eq!(limit.map(4096,8192,3,2,17,4096),Err(errno));
  }
  for (opaque,errno) in [(-5i64,5),(-28,28),(-75,139)]{
   RESULT.set(opaque as u64);assert_eq!(limit.map(4096,8192,3,2,17,4096),Err(errno));
  }
  RESULT.set(0x10000);assert_eq!(limit.map(4096,8192,3,2,17,4096),Ok(0x10000));
 }
}
"#);
    probe::run(&program);
}
