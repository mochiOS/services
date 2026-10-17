#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_positioned_io_preserves_progress_and_copies_outside_provider_guards() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
#[path={status:?}]pub mod status;
use status::Error;
use std::cell::{{Cell,RefCell}};
const SUCCESS:u64=0;
pub mod provider{{pub const MAX_DATA_LEN:usize={capacity};}}
thread_local!{{
    static WRITE:Cell<bool>=const{{Cell::new(false)}};
    static LOCKED:Cell<bool>=const{{Cell::new(false)}};
    static FAIL_ALLOC:Cell<bool>=const{{Cell::new(false)}};
    static ADMISSION:Cell<Option<Error>>=const{{Cell::new(None)}};
    static CACHE_ERROR:Cell<u64>=const{{Cell::new(0)}};
    static LOCK_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static BACKEND_ERROR:Cell<u64>=const{{Cell::new(0)}};
    static COPY_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static FAIL_AFTER:Cell<usize>=const{{Cell::new(0)}};
    static SHORT:Cell<Option<usize>>=const{{Cell::new(None)}};
    static IDENTITY:Cell<bool>=const{{Cell::new(true)}};
    static COPIES:Cell<usize>=const{{Cell::new(0)}};
    static BACKENDS:Cell<usize>=const{{Cell::new(0)}};
    static OVERLAYS:Cell<usize>=const{{Cell::new(0)}};
    static UPDATES:Cell<usize>=const{{Cell::new(0)}};
    static POSITIONS:RefCell<Vec<u64>>=const{{RefCell::new(Vec::new())}};
}}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{{
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{{
        if FAIL_ALLOC.try_with(|flag|flag.replace(false)).unwrap_or(false){{core::ptr::null_mut()}}
        else{{unsafe{{std::alloc::System.alloc(l)}}}}
    }}
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(p,l)}}}}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[derive(Debug,PartialEq)]struct HandleRights(bool);
impl HandleRights{{const READ:Self=Self(false);const WRITE:Self=Self(true);}}
struct ProviderObject;struct Memory;struct Snapshot;
enum KernelObject{{Provider(ProviderObject),VmObject(Memory),HandleSnapshot(Snapshot),Completion(Snapshot),Other}}
fn object_native(raw:u64,right:HandleRights)->Result<KernelObject,Error>{{
    assert_eq!(right,HandleRights(WRITE.get()));
    if let Some(error)=ADMISSION.get(){{return Err(error);}}
    match raw{{1=>Ok(KernelObject::VmObject(Memory)),2=>Ok(KernelObject::Provider(ProviderObject)),
        3=>Ok(KernelObject::HandleSnapshot(Snapshot)),5=>Ok(KernelObject::Completion(Snapshot)),_=>Ok(KernelObject::Other)}}
}}
fn backend(position:u64,length:usize)->Result<usize,u64>{{
    POSITIONS.with_borrow_mut(|p|p.push(position));
    let count=BACKENDS.get();BACKENDS.set(count+1);
    if count>=FAIL_AFTER.get()&&BACKEND_ERROR.get()!=0{{return Err(BACKEND_ERROR.get());}}
    Ok(SHORT.get().unwrap_or(length))
}}
impl Memory{{
    fn read_at(&self,p:u64,out:&mut[u8])->Result<usize,u64>{{out.fill(0x6b);backend(p,out.len())}}
    fn write_at(&self,p:u64,data:&[u8])->Result<usize,u64>{{assert!(data.iter().all(|b|*b==0x5a));backend(p,data.len())}}
}}
impl Snapshot{{fn read_at(&self,p:u64,out:&mut[u8])->usize{{out.fill(0x6b);backend(p,out.len()).unwrap()}}}}
fn provider_cache_identity(_: &ProviderObject)->Result<Option<u64>,u64>{{
    if CACHE_ERROR.get()!=0{{Err(CACHE_ERROR.get())}}else{{Ok(IDENTITY.get().then_some(99))}}
}}
fn provider_read_at(_: &ProviderObject,p:u64,out:&mut[u8])->Result<usize,u64>{{
    assert_eq!(LOCKED.get(),IDENTITY.get());out.fill(0x6b);backend(p,out.len())
}}
fn provider_write_at(_: &ProviderObject,p:u64,data:&[u8])->Result<usize,u64>{{
    assert_eq!(LOCKED.get(),IDENTITY.get());assert!(data.iter().all(|b|*b==0x5a));backend(p,data.len())
}}
mod mem{{pub mod vm_object{{
    pub struct Guard;
    impl Drop for Guard{{fn drop(&mut self){{assert!(crate::LOCKED.replace(false));}}}}
    pub fn lock_provider_io(_: &crate::ProviderObject,identity:u64)->Result<Guard,crate::Error>{{
        assert_eq!(identity,99);
        if let Some(error)=crate::LOCK_ERROR.get(){{return Err(error);}}
        assert!(!crate::LOCKED.replace(true));Ok(Guard)
    }}
    pub fn update_provider_range(_: &Guard,_:u64,_:&[u8]){{
        assert!(crate::LOCKED.get());crate::UPDATES.set(crate::UPDATES.get()+1);
    }}
    pub fn overlay_provider_range(_: &crate::ProviderObject,_:u64,_:u64,_:&mut[u8])->Result<(),u64>{{
        assert!(crate::LOCKED.get());crate::OVERLAYS.set(crate::OVERLAYS.get()+1);Ok(())
    }}
}}}}
mod syscall{{
    fn copy(pointer:u64)->Result<(),crate::Error>{{
        use crate::*;
        assert!(!LOCKED.get(),"user copy under provider I/O guard");
        let count=COPIES.get();COPIES.set(count+1);
        if count>=FAIL_AFTER.get(){{if let Some(error)=COPY_ERROR.get(){{return Err(error);}}}}
        if pointer==0{{Err(Error::InvalidAddress)}}else{{Ok(())}}
    }}
    pub fn copy_from_user_native(p:u64,out:&mut[u8])->Result<(),crate::Error>{{copy(p)?;out.fill(0x5a);Ok(())}}
    pub fn copy_to_user_native(p:u64,bytes:&[u8])->Result<(),crate::Error>{{
        copy(p)?;assert!(bytes.iter().all(|b|*b==0x6b));Ok(())
    }}
}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        capacity = mnu_abi::provider::MAX_DATA_LEN,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn read_at(",
        "/// Controls a native update owner",
    ));
    program.push_str(r#"
fn reset(write:bool){
    assert!(!LOCKED.get());WRITE.set(write);ADMISSION.set(None);CACHE_ERROR.set(0);LOCK_ERROR.set(None);
    BACKEND_ERROR.set(0);COPY_ERROR.set(None);FAIL_AFTER.set(0);SHORT.set(None);IDENTITY.set(true);
    COPIES.set(0);BACKENDS.set(0);OVERLAYS.set(0);UPDATES.set(0);POSITIONS.with_borrow_mut(Vec::clear);
}
fn invoke(raw:u64,pointer:u64,length:u64,offset:u64)->u64{
    if WRITE.get(){write_at(raw,pointer,length,offset)}else{read_at(raw,pointer,length,offset)}
}
fn main(){
    let chunk=provider::MAX_DATA_LEN as u64;
    for write in [false,true]{
        for raw in [1,2,3,5].into_iter().filter(|raw|!write||![3,5].contains(raw)){
            reset(write);assert_eq!(invoke(raw,4096,chunk+3,81),chunk+3);
            POSITIONS.with_borrow(|p|assert_eq!(p,&[81,81+chunk]));
            assert_eq!(COPIES.get(),2);assert!(!LOCKED.get());
            if raw==2{assert_eq!(if write{UPDATES.get()}else{OVERLAYS.get()},2);}
            reset(write);assert_eq!(invoke(raw,0,0,u64::MAX),0);assert_eq!(BACKENDS.get(),0);
            reset(write);FAIL_ALLOC.set(true);assert_eq!(invoke(raw,1,8,0),Error::ResourceUnavailable.into_raw());
            assert_eq!((BACKENDS.get(),COPIES.get()),(0,0));
            reset(write);SHORT.set(Some(3));assert_eq!(invoke(raw,1,8,0),3);assert_eq!(BACKENDS.get(),1);
            reset(write);SHORT.set(Some(0));assert_eq!(invoke(raw,1,8,0),0);
            reset(write);SHORT.set(Some(9));assert_eq!(invoke(raw,1,8,0),Error::BackingFailure.into_raw());
            reset(write);assert_eq!(invoke(raw,0,8,0),Error::InvalidAddress.into_raw());
            reset(write);assert_eq!(invoke(raw,u64::MAX-chunk+1,chunk+1,0),chunk);
            for error in [Error::InvalidAddress,Error::NotReady,Error::BackingFailure]{
                reset(write);COPY_ERROR.set(Some(error));assert_eq!(invoke(raw,1,chunk+1,0),error.into_raw());
                reset(write);COPY_ERROR.set(Some(error));FAIL_AFTER.set(1);assert_eq!(invoke(raw,1,chunk+1,0),chunk);
            }
            for (length,offset) in [(u64::MAX,0),(1,u64::MAX)]{
                reset(write);assert_eq!(invoke(raw,1,length,offset),Error::LimitExceeded.into_raw());
                assert_eq!((BACKENDS.get(),COPIES.get()),(0,0));
            }
        }
        for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady]{
            reset(write);ADMISSION.set(Some(error));assert_eq!(invoke(1,1,8,0),error.into_raw());
            assert_eq!((BACKENDS.get(),COPIES.get()),(0,0));
        }
        reset(write);assert_eq!(invoke(4,1,8,0),Error::InvalidArgument.into_raw());
        for raw in [1,2]{
            for error in [Error::NotReady.into_raw(),Error::BackingFailure.into_raw(),(-28i64)as u64]{
                reset(write);BACKEND_ERROR.set(error);assert_eq!(invoke(raw,1,chunk+1,0),error);
                reset(write);BACKEND_ERROR.set(error);FAIL_AFTER.set(1);assert_eq!(invoke(raw,1,chunk+1,0),chunk);
                assert!(!LOCKED.get());
            }
        }
        reset(write);CACHE_ERROR.set(Error::BackingFailure.into_raw());
        assert_eq!(invoke(2,1,8,0),Error::BackingFailure.into_raw());assert_eq!(BACKENDS.get(),0);
        reset(write);LOCK_ERROR.set(Some(Error::ResourceUnavailable));
        assert_eq!(invoke(2,1,8,0),Error::ResourceUnavailable.into_raw());assert_eq!(BACKENDS.get(),0);
        reset(write);IDENTITY.set(false);assert_eq!(invoke(2,1,8,0),8);assert!(!LOCKED.get());
    }
    reset(true);assert_eq!(invoke(3,1,8,0),Error::InvalidArgument.into_raw());
    reset(true);assert_eq!(invoke(5,1,8,0),Error::InvalidArgument.into_raw());
}
"#);
    probe::run(&program);
}
