#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn sequential_entries_require_native_read_or_write_authority_before_dispatch() {
    let mut program = probe::program();
    program.push_str(r#"
use std::cell::Cell;
use mnu_abi::status::Error;
#[derive(Debug,PartialEq)]struct HandleRights(bool);
impl HandleRights{const READ:Self=Self(false);const WRITE:Self=Self(true);}
struct ProviderObject;
enum KernelObject{File(u64),Provider(ProviderObject),Other}
thread_local!{
    static RIGHT:Cell<bool>=const{Cell::new(false)};
    static ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static CALLS:Cell<usize>=const{Cell::new(0)};
}
fn object_native(raw:u64,right:HandleRights)->Result<KernelObject,Error>{
    assert_eq!(right,HandleRights(RIGHT.get()));
    if let Some(error)=ERROR.get(){return Err(error);}
    match raw{1=>Ok(KernelObject::File(17)),2=>Ok(KernelObject::Provider(ProviderObject)),
        3=>Ok(KernelObject::Other),_=>Err(Error::InvalidArgument)}
}
fn invoked(marker:u64,buffer:u64,length:u64)->u64{assert_eq!((buffer,length),(19,23));CALLS.set(CALLS.get()+1);marker}
mod syscall{pub mod fs{
    pub fn read_file_handle(file:&u64,b:u64,l:u64)->u64{assert_eq!(*file,17);crate::invoked(31,b,l)}
    pub fn write_file_handle(file:&u64,b:u64,l:u64)->u64{assert_eq!(*file,17);crate::invoked(32,b,l)}
}}
fn provider_read(_: &ProviderObject,b:u64,l:u64)->u64{invoked(41,b,l)}
fn provider_write(_: &ProviderObject,b:u64,l:u64)->u64{invoked(42,b,l)}
fn provider_write_impl(_: &ProviderObject,b:u64,l:u64,end:Option<u64>)->u64{assert_eq!(end,Some(29));invoked(43,b,l)}
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn read(",
        "pub fn stream_read(",
    ));
    program.push_str(r#"
fn invoke(mode:u8,raw:u64)->u64{RIGHT.set(mode!=0);match mode{0=>read(raw,19,23),1=>write(raw,19,23),_=>write_bounded(raw,19,23,29)}}
fn main(){
    for (mode,marker) in [(0,41),(1,42),(2,43)]{
        assert_eq!(invoke(mode,2),marker);
        for raw in [0,3]{assert_eq!(invoke(mode,raw),Error::InvalidArgument.into_raw());}
        for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady]{
            let before=CALLS.get();ERROR.set(Some(error));assert_eq!(invoke(mode,2),error.into_raw());ERROR.set(None);
            assert_eq!(CALLS.get(),before);
        }
    }
    assert_eq!(invoke(0,1),31);assert_eq!(invoke(1,1),32);
    let before=CALLS.get();assert_eq!(invoke(2,1),Error::InvalidArgument.into_raw());assert_eq!(CALLS.get(),before);
}
"#);
    probe::run(&program);
}

#[test]
fn inline_reads_fail_recoverably_and_preserve_prefixes_without_copying_under_io_lock() {
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
#[path={provider:?}]pub mod provider;
mod util{{#[path={storage:?}]pub mod object_snapshot;}}
use status::Error;
use std::cell::Cell;
const SUCCESS:u64=0;const ENOSYS:u64=(-38i64)as u64;const ENOTSUP:u64=(-95i64)as u64;
thread_local!{{
    static LOCKED:Cell<bool>=const{{Cell::new(false)}};
    static IDENTITY:Cell<bool>=const{{Cell::new(false)}};
    static FAIL_ALLOC:Cell<bool>=const{{Cell::new(false)}};
    static CALLS:Cell<usize>=const{{Cell::new(0)}};
    static COPIES:Cell<usize>=const{{Cell::new(0)}};
    static FAIL_AFTER:Cell<usize>=const{{Cell::new(0)}};
    static COPY_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static LOWER_ERROR:Cell<u64>=const{{Cell::new(0)}};
    static MODE:Cell<u8>=const{{Cell::new(0)}};
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
struct ProviderObject{{object_id:u64}}
fn provider_cache_identity(_: &ProviderObject)->Result<Option<u64>,u64>{{Ok(IDENTITY.get().then_some(77))}}
fn provider_read_shared(_: &ProviderObject,_:u64,_:u64,_:usize)->u64{{panic!("not the inline read path")}}
mod mem{{pub mod vm_object{{
    pub struct Guard;
    impl Drop for Guard{{fn drop(&mut self){{assert!(crate::LOCKED.replace(false));}}}}
    pub fn lock_provider_io(_: &crate::ProviderObject,id:u64)->Result<Guard,crate::Error>{{assert_eq!(id,77);assert!(!crate::LOCKED.replace(true));Ok(Guard)}}
    pub fn overlay_provider_range(_: &crate::ProviderObject,id:u64,offset:u64,_:&mut[u8])->Result<(),u64>{{
        assert!(crate::LOCKED.get());assert_eq!((id,offset),(77,100));Ok(())
    }}
}}}}
mod syscall{{pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{{
    use crate::*;assert!(!LOCKED.get());assert_ne!(pointer,0);
    let count=COPIES.get();COPIES.set(count+1);
    if count>=FAIL_AFTER.get(){{if let Some(error)=COPY_ERROR.get(){{return Err(error);}}}}
    assert!(bytes.iter().all(|byte|*byte==0x6b));Ok(())
}}}}
fn provider_call(owner:&ProviderObject,request:provider::RequestHeader,input:&[u8],storage:&mut[u8])
    ->Result<(provider::ResponseHeader,usize),u64>{{
    assert_eq!(owner.object_id,17);assert_eq!(request.object_id,17);assert!(input.is_empty());
    assert_eq!(LOCKED.get(),IDENTITY.get());
    assert_eq!(request.opcode,if IDENTITY.get(){{provider::OP_READ_WITH_POSITION}}else{{provider::OP_READ}});
    let call=CALLS.get();CALLS.set(call+1);
    if call>=FAIL_AFTER.get()&&LOWER_ERROR.get()!=0{{return Err(LOWER_ERROR.get());}}
    let count=if MODE.get()==4{{2}}else{{request.length as usize}};
    let prefix=if IDENTITY.get(){{8}}else{{0}};
    storage[provider::RESPONSE_HEADER_LEN..].fill(0x6b);
    if prefix!=0{{storage[provider::RESPONSE_HEADER_LEN..provider::RESPONSE_HEADER_LEN+8].copy_from_slice(&100u64.to_le_bytes());}}
    Ok((provider::ResponseHeader{{opcode:request.opcode,status:0,object_id:17,
        value:if MODE.get()==1{{count as u64+1}}else{{count as u64}},data_length:(prefix+count)as u32}},
        match MODE.get(){{2=>0,3=>usize::MAX,_=>prefix+count}}))
}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        provider = root.join("core/crates/abi/src/provider.rs"),
        storage = root.join("core/src/util/object_snapshot.rs"),
    );
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &[
            "HANDLE_SEEK_START",
            "HANDLE_SEEK_CURRENT",
            "HANDLE_SEEK_END",
        ],
    );
    let source = include_str!("../../../core/src/syscall/handle.rs");
    program.push_str(probe::between(
        source,
        "fn provider_read_chunk<'a>(",
        "struct TemporaryMemoryHandle",
    ));
    program.push_str(probe::between(
        source,
        "fn provider_read(provider:",
        "fn provider_write(provider:",
    ));
    program.push_str(r#"
fn reset(identity:bool){assert!(!LOCKED.get());IDENTITY.set(identity);CALLS.set(0);COPIES.set(0);MODE.set(0);
    COPY_ERROR.set(None);LOWER_ERROR.set(0);FAIL_AFTER.set(0);}
fn run(length:u64)->u64{provider_read(&ProviderObject{object_id:17},1,length)}
fn main(){
    reset(false);assert_eq!(run(8192),8192);assert_eq!((CALLS.get(),COPIES.get()),(2,2));
    reset(true);assert_eq!(run(8),8);assert_eq!((CALLS.get(),COPIES.get()),(1,1));
    for identity in [false,true]{
        reset(identity);FAIL_ALLOC.set(true);assert_eq!(run(8),Error::ResourceUnavailable.into_raw());
        assert_eq!((CALLS.get(),COPIES.get()),(0,0));
        for mode in [1,2,3]{reset(identity);MODE.set(mode);assert_eq!(run(8),Error::BackingFailure.into_raw());assert_eq!(COPIES.get(),0);}
        reset(identity);MODE.set(4);assert_eq!(run(8),2);
        reset(identity);assert_eq!(run(0),0);assert_eq!(CALLS.get(),0);
    }
    for error in [Error::InvalidAddress,Error::NotReady,Error::BackingFailure]{
        reset(false);COPY_ERROR.set(Some(error));assert_eq!(run(8192),error.into_raw());
        reset(false);COPY_ERROR.set(Some(error));FAIL_AFTER.set(1);assert_eq!(run(8192),4096);
    }
    for error in [Error::PeerClosed.into_raw(),Error::BackingFailure.into_raw(),(-5i64)as u64,(-11i64)as u64]{
        reset(false);LOWER_ERROR.set(error);assert_eq!(run(8192),error);
        reset(false);LOWER_ERROR.set(error);FAIL_AFTER.set(1);assert_eq!(run(8192),4096);
    }
    reset(false);assert_eq!(provider_read(&ProviderObject{object_id:17},u64::MAX-4095,8192),4096);
    reset(false);assert_eq!(run(u64::MAX),Error::LimitExceeded.into_raw());assert_eq!(CALLS.get(),0);
}
"#);
    probe::run(&program);
}
