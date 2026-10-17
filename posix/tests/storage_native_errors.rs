//! Actual block/control entry points and buffer allocator. Device, usercopy,
//! platform transport and authority checks are controlled host backends.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn storage_uses_native_local_failures_and_preserves_backend_status() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        "#![allow(dead_code)]\nextern crate alloc;\nextern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\nmod storage {{include!({:?});}}\nmod util {{#[path={:?}]pub mod object_snapshot;}}\n",
        root.join("core/crates/abi/src/lib.rs"),
        root.join("core/src/syscall/storage.rs"),
        root.join("core/src/util/object_snapshot.rs"),
    );
    program.push_str(r#"
use std::{cell::Cell,alloc::{GlobalAlloc,Layout,System}};
use status::Error;
use storage::{block_read,block_write,block_flush,control,device_control};
thread_local! {
    static FAIL:Cell<bool>=const{Cell::new(false)};
    static ALLOCS:Cell<usize>=const{Cell::new(0)};
    static PERMITTED:Cell<bool>=const{Cell::new(true)};
    static EXPECTED_CAP:Cell<capability::Capability>=const{Cell::new(capability::Capability::DeviceStorage)};
    static READY:Cell<bool>=const{Cell::new(true)};
    static RESULT:Cell<i32>=const{Cell::new(0)};
    static READS:Cell<usize>=const{Cell::new(0)};
    static WRITES:Cell<usize>=const{Cell::new(0)};
    static FLUSHES:Cell<usize>=const{Cell::new(0)};
    static INPUTS:Cell<usize>=const{Cell::new(0)};
    static OUTPUTS:Cell<usize>=const{Cell::new(0)};
    static INPUT_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static OUTPUT_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static PLATFORM_FAIL:Cell<bool>=const{Cell::new(false)};
    static PLATFORM_CALLS:Cell<usize>=const{Cell::new(0)};
    static PLATFORM_STATUS:Cell<u32>=const{Cell::new(0)};
}
struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self,l:Layout)->*mut u8{ALLOCS.set(ALLOCS.get()+1);if FAIL.replace(false){return std::ptr::null_mut()}unsafe{System.alloc(l)}}
    unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
mod capability {
    #[derive(Clone,Copy,Debug,PartialEq)]pub enum Capability{DeviceStorage,Other}
    impl Capability{pub fn from_str(s:&str)->Option<Self>{match s{"device.storage"=>Some(Self::DeviceStorage),"device.other"=>Some(Self::Other),_=>None}}}
}
mod syscall {
    pub mod security {
        pub fn caller_has_any_capability(caps:&[crate::capability::Capability])->bool{assert_eq!(caps,[crate::EXPECTED_CAP.get()]);crate::PERMITTED.get()}
    }
    fn check(p:u64,n:usize)->Result<(),crate::Error>{if p==0||p.checked_add(n as u64-1).is_none(){Err(crate::Error::InvalidAddress)}else{Ok(())}}
    pub fn copy_from_user_native(p:u64,b:&mut[u8])->Result<(),crate::Error>{
        crate::INPUTS.set(crate::INPUTS.get()+1);if let Some(e)=crate::INPUT_ERROR.get(){return Err(e)}check(p,b.len())?;
        unsafe{std::ptr::copy_nonoverlapping(p as *const u8,b.as_mut_ptr(),b.len())};Ok(())
    }
    pub fn copy_to_user_native(p:u64,b:&[u8])->Result<(),crate::Error>{
        crate::OUTPUTS.set(crate::OUTPUTS.get()+1);if let Some(e)=crate::OUTPUT_ERROR.get(){return Err(e)}check(p,b.len())?;
        unsafe{std::ptr::copy_nonoverlapping(b.as_ptr(),p as *mut u8,b.len())};Ok(())
    }
}
mod cext {pub mod disk {
    pub fn is_loaded()->bool{crate::READY.get()}
    pub fn read_sector(id:u32,lba:u64,bytes:&mut[u8])->i32{assert_eq!((id,lba),(9,77));crate::READS.set(crate::READS.get()+1);assert!(bytes.iter().all(|b|*b==0));bytes.fill(0x73);crate::RESULT.get()}
    pub fn write_sector(id:u32,lba:u64,bytes:&[u8])->i32{assert_eq!((id,lba),(9,77));crate::WRITES.set(crate::WRITES.get()+1);assert!(bytes.iter().all(|b|*b==0x5a));crate::RESULT.get()}
    pub fn flush(id:u32)->i32{assert_eq!(id,9);crate::FLUSHES.set(crate::FLUSHES.get()+1);crate::RESULT.get()}
}}
mod platform {
    pub fn device_control(authority:&str,op:u16,id:u32,args:[u64;4])->Result<crate::StorageControlResponse,()>{
        assert!(matches!(authority,"device.storage"|"device.other"));assert_eq!((op,id,args),(42,9,[1,2,3,4]));crate::PLATFORM_CALLS.set(crate::PLATFORM_CALLS.get()+1);
        if crate::PLATFORM_FAIL.get(){Err(())}else{Ok(crate::StorageControlResponse{status:crate::PLATFORM_STATUS.get(),device_id:91,values:[5,6,7,8]})}
    }
}
fn reset(){FAIL.set(false);ALLOCS.set(0);PERMITTED.set(true);EXPECTED_CAP.set(capability::Capability::DeviceStorage);READY.set(true);RESULT.set(0);READS.set(0);WRITES.set(0);FLUSHES.set(0);INPUTS.set(0);OUTPUTS.set(0);INPUT_ERROR.set(None);OUTPUT_ERROR.set(None);PLATFORM_FAIL.set(false);PLATFORM_CALLS.set(0);PLATFORM_STATUS.set(0);}
fn idle(){assert_eq!((READS.get(),WRITES.get(),FLUSHES.get(),INPUTS.get(),OUTPUTS.get(),ALLOCS.get()),(0,0,0,0,0,0));}
fn main(){
    let mut bytes=[0x5a_u8;512];let p=bytes.as_mut_ptr() as u64;
    for op in [block_read as fn(u64,u64,u64,u64)->u64,block_write] {
        reset();PERMITTED.set(false);assert_eq!(op(9,77,p,512),Error::AccessDenied.into_raw());idle();
        for (id,ptr,n,error) in [(u64::MAX,p,512,Error::InvalidArgument),(9,p,0,Error::InvalidArgument),(9,p,511,Error::InvalidArgument),(9,p,262656,Error::LimitExceeded),(9,p,u64::MAX,Error::LimitExceeded),(9,0,512,Error::InvalidAddress),(9,u64::MAX-1,512,Error::InvalidAddress)] {
            reset();assert_eq!(op(id,77,ptr,n),error.into_raw());idle();
        }
        reset();READY.set(false);assert_eq!(op(9,77,p,512),Error::NotReady.into_raw());idle();
        reset();FAIL.set(true);assert_eq!(op(9,77,p,512),Error::ResourceUnavailable.into_raw());assert!(!FAIL.get());assert_eq!(ALLOCS.get(),1);assert_eq!((READS.get(),WRITES.get(),INPUTS.get(),OUTPUTS.get()),(0,0,0,0));
    }
    reset();assert_eq!(block_write(9,77,p,512),0);assert_eq!((INPUTS.get(),WRITES.get(),ALLOCS.get()),(1,1,1));
    reset();assert_eq!(block_read(9,77,p,512),0);assert_eq!(bytes,[0x73;512]);assert_eq!((READS.get(),OUTPUTS.get(),ALLOCS.get()),(1,1,1));
    for error in [Error::InvalidAddress,Error::AccessDenied,Error::ResourceUnavailable,Error::BackingFailure,Error::NotReady] {
        bytes.fill(0x5a);reset();INPUT_ERROR.set(Some(error));assert_eq!(block_write(9,77,p,512),error.into_raw());assert_eq!(WRITES.get(),0);
        reset();OUTPUT_ERROR.set(Some(error));assert_eq!(block_read(9,77,p,512),error.into_raw());assert_eq!(bytes,[0x5a;512]);
    }
    for status in [-5,-38,Error::BackingFailure.into_raw() as i32,Error::NotReady.into_raw() as i32] {
        let expected=status as i64 as u64;
        bytes.fill(0x5a);reset();RESULT.set(status);assert_eq!(block_read(9,77,p,512),expected);assert_eq!(bytes,[0x5a;512]);assert_eq!(OUTPUTS.get(),0);
        reset();RESULT.set(status);assert_eq!(block_write(9,77,p,512),expected);assert_eq!(WRITES.get(),1);
        reset();RESULT.set(status);assert_eq!(block_flush(9),expected);assert_eq!(FLUSHES.get(),1);
    }
    reset();PERMITTED.set(false);assert_eq!(block_flush(9),Error::AccessDenied.into_raw());idle();
    reset();assert_eq!(block_flush(u64::MAX),Error::InvalidArgument.into_raw());idle();
    reset();READY.set(false);assert_eq!(block_flush(9),Error::NotReady.into_raw());idle();
    reset();assert_eq!(block_flush(9),0);assert_eq!(FLUSHES.get(),1);
    // Exercise the maximum transfer without changing or installing a device.
    let mut large=vec![0x5a_u8;262144];let large_p=large.as_mut_ptr() as u64;
    reset();assert_eq!(block_write(9,77,large_p,262144),0);assert_eq!(ALLOCS.get(),1);
    reset();assert_eq!(block_read(9,77,large_p,262144),0);assert!(large.iter().all(|b|*b==0x73));

    let request=StorageControlRequest{operation:42,reserved0:0,device_id:9,arguments:[1,2,3,4]};
    let r=&request as *const _ as u64;let mut out=[0xcc_u8;40];let o=out.as_mut_ptr() as u64;
    reset();PERMITTED.set(false);assert_eq!(control(r,o),Error::AccessDenied.into_raw());idle();
    for error in [Error::InvalidAddress,Error::AccessDenied,Error::ResourceUnavailable,Error::BackingFailure,Error::NotReady] {
        reset();INPUT_ERROR.set(Some(error));assert_eq!(control(r,o),error.into_raw());assert_eq!(PLATFORM_CALLS.get(),0);assert_eq!(OUTPUTS.get(),0);
        reset();OUTPUT_ERROR.set(Some(error));assert_eq!(control(r,o),error.into_raw());assert_eq!(PLATFORM_CALLS.get(),1);assert_eq!(out,[0xcc;40]);
    }
    let bad=StorageControlRequest{reserved0:1,..request};reset();assert_eq!(control(&bad as *const _ as u64,o),Error::InvalidArgument.into_raw());assert_eq!(PLATFORM_CALLS.get(),0);
    reset();PLATFORM_FAIL.set(true);assert_eq!(control(r,o),Error::BackingFailure.into_raw());assert_eq!(OUTPUTS.get(),0);
    for status in [0,7,u32::MAX] {reset();PLATFORM_STATUS.set(status);assert_eq!(control(r,o),0);let response=unsafe{std::ptr::read_unaligned(out.as_ptr().cast::<StorageControlResponse>())};assert_eq!(response,StorageControlResponse{status,device_id:91,values:[5,6,7,8]});}
    for (ptr,n,error) in [(1,0,Error::InvalidArgument),(1,129,Error::LimitExceeded),(0,9,Error::InvalidAddress),(u64::MAX-1,9,Error::InvalidAddress)] {
        reset();assert_eq!(device_control(r,o,ptr,n),error.into_raw());idle();assert_eq!(PLATFORM_CALLS.get(),0);
    }
    for authority in [b"unknown" as &[u8],&[0xff]] {reset();assert_eq!(device_control(r,o,authority.as_ptr() as u64,authority.len() as u64),if authority==[0xff]{Error::InvalidArgument}else{Error::AccessDenied}.into_raw());assert_eq!(PLATFORM_CALLS.get(),0);}
    let authority=b"device.other";
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure,Error::NotReady] {
        reset();INPUT_ERROR.set(Some(error));assert_eq!(device_control(r,o,authority.as_ptr() as u64,authority.len() as u64),error.into_raw());assert_eq!(INPUTS.get(),1);assert_eq!(PLATFORM_CALLS.get(),0);
    }
    reset();EXPECTED_CAP.set(capability::Capability::Other);PERMITTED.set(false);assert_eq!(device_control(r,o,authority.as_ptr() as u64,authority.len() as u64),Error::AccessDenied.into_raw());assert_eq!(INPUTS.get(),1);assert_eq!(PLATFORM_CALLS.get(),0);
    reset();EXPECTED_CAP.set(capability::Capability::Other);assert_eq!(device_control(r,o,authority.as_ptr() as u64,authority.len() as u64),0);assert_eq!(INPUTS.get(),2);assert_eq!(PLATFORM_CALLS.get(),1);assert_eq!(ALLOCS.get(),0);
}
"#);
    probe::run(&program);
}
