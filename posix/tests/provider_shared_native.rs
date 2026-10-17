#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn shared_read_native_failures_release_scratch_handles_and_keep_completed_prefixes() {
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
const SUCCESS:u64=0;
thread_local!{{
    static LIVE:Cell<bool>=const{{Cell::new(false)}};
    static LOCKED:Cell<bool>=const{{Cell::new(false)}};
    static CLOSES:Cell<usize>=const{{Cell::new(0)}};
    static CALLS:Cell<usize>=const{{Cell::new(0)}};
    static COPIES:Cell<usize>=const{{Cell::new(0)}};
    static FAIL_ALLOC:Cell<bool>=const{{Cell::new(false)}};
    static CREATE_ERROR:Cell<u64>=const{{Cell::new(0)}};
    static LOOKUP_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static LOCK_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static COPY_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static IPC_ERROR:Cell<u64>=const{{Cell::new(0)}};
    static MEMORY_ERROR:Cell<u64>=const{{Cell::new(0)}};
    static OVERLAY_ERROR:Cell<u64>=const{{Cell::new(0)}};
    static WIRE_ERROR:Cell<i64>=const{{Cell::new(0)}};
    static FAIL_AFTER:Cell<usize>=const{{Cell::new(0)}};
    static MODE:Cell<u8>=const{{Cell::new(0)}};
    static INLINE_CALLS:Cell<usize>=const{{Cell::new(0)}};
}}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{{
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{{
        if FAIL_ALLOC.try_with(|flag|flag.replace(false)).unwrap_or(false){{std::ptr::null_mut()}}
        else{{unsafe{{std::alloc::System.alloc(l)}}}}
    }}
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(p,l)}}}}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[derive(Debug,PartialEq,Copy,Clone)]struct HandleRights(u64);
impl HandleRights{{const READ:Self=Self(1);const WRITE:Self=Self(2);const MAP:Self=Self(64);
    fn union(self,other:Self)->Self{{Self(self.0|other.0)}}}}
#[derive(Debug,Copy,Clone)]struct ObjectHandle(u32);
impl ObjectHandle{{fn from_raw(raw:u32)->Option<Self>{{(raw!=0).then_some(Self(raw))}}}}
struct ProviderObject{{object_id:u64}}
fn provider_cache_identity(_: &ProviderObject)->Result<Option<u64>,u64>{{Ok(Some(77))}}
fn provider_read_chunk<'a>(_: &ProviderObject,identity:Option<u64>,length:usize,storage:&'a mut[u8])->Result<&'a[u8],u64>{{
    assert_eq!(identity,Some(77));assert!(LOCKED.get());assert!(!LIVE.get());
    INLINE_CALLS.set(INLINE_CALLS.get()+1);storage[..length].fill(0x6b);Ok(&storage[..length])
}}
struct Memory;
impl Memory{{fn read_at(&self,position:u64,bytes:&mut[u8])->Result<usize,u64>{{
    assert!(LOCKED.get());assert!(LIVE.get());assert_eq!(position,0);
    if CALLS.get()-1>=FAIL_AFTER.get()&&MEMORY_ERROR.get()!=0{{return Err(MEMORY_ERROR.get());}}
    bytes.fill(0x6b);Ok(if MODE.get()==7{{bytes.len().saturating_sub(1)}}else{{bytes.len()}})
}}}}
enum KernelObject{{VmObject(Memory),Other}}
fn memory_object_create(length:u64,options:u64)->u64{{
    assert_eq!(options,0);assert!(length>0&&length%4096==0);assert!(!LIVE.get());
    if CREATE_ERROR.get()!=0{{return CREATE_ERROR.get();}}LIVE.set(true);17
}}
fn object_native(raw:u64,rights:HandleRights)->Result<KernelObject,Error>{{
    assert_eq!((raw,rights),(17,HandleRights::MAP));assert!(LIVE.get());
    if let Some(error)=LOOKUP_ERROR.get(){{return Err(error);}}
    Ok(if MODE.get()==8{{KernelObject::Other}}else{{KernelObject::VmObject(Memory)}})
}}
fn close(raw:u64)->u64{{assert_eq!(raw,17);assert!(!LOCKED.get());assert!(LIVE.replace(false));CLOSES.set(CLOSES.get()+1);0}}
fn provider_endpoint(owner:&ProviderObject)->u64{{assert_eq!(owner.object_id,41);99}}
mod mem{{pub mod vm_object{{
    pub struct Guard;
    impl Drop for Guard{{fn drop(&mut self){{assert!(crate::LOCKED.replace(false));}}}}
    pub fn lock_provider_io(_: &crate::ProviderObject,identity:u64)->Result<Guard,crate::Error>{{
        assert_eq!(identity,77);
        if crate::CALLS.get()>=crate::FAIL_AFTER.get(){{if let Some(error)=crate::LOCK_ERROR.get(){{return Err(error);}}}}
        assert!(!crate::LOCKED.replace(true));Ok(Guard)
    }}
    pub fn overlay_provider_range(_: &crate::ProviderObject,identity:u64,start:u64,_:&mut[u8])->Result<(),u64>{{
        assert!(crate::LOCKED.get());assert_eq!((identity,start),(77,100));
        if crate::CALLS.get()-1>=crate::FAIL_AFTER.get()&&crate::OVERLAY_ERROR.get()!=0{{Err(crate::OVERLAY_ERROR.get())}}else{{Ok(())}}
    }}
}}}}
mod syscall{{
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{{
        use crate::*;assert!(!LOCKED.get());assert_eq!(LIVE.get(),INLINE_CALLS.get()==0);
        let copy=COPIES.get();COPIES.set(copy+1);
        if copy>=FAIL_AFTER.get(){{if let Some(error)=COPY_ERROR.get(){{return Err(error);}}}}
        if pointer==0{{return Err(Error::InvalidAddress);}}
        assert!(bytes.iter().all(|byte|*byte==0x6b));Ok(())
    }}
    pub mod ipc{{pub fn call_provider_with_handle_from_kernel(endpoint:u64,request:&[u8],reply:&mut[u8],handle:crate::ObjectHandle,rights:crate::HandleRights)->Result<usize,u64>{{
        use crate::*;assert!(LOCKED.get());assert!(LIVE.get());assert_eq!((endpoint,handle.0,rights.0),(99,17,67));
        let (request,data)=provider::RequestHeader::decode(request).unwrap();assert!(data.is_empty());
        assert_eq!((request.opcode,request.object_id,request.basis),(provider::OP_READ_SHARED,41,0));
        let call=CALLS.get();CALLS.set(call+1);
        if call>=FAIL_AFTER.get()&&IPC_ERROR.get()!=0{{return Err(IPC_ERROR.get());}}
        if MODE.get()==1{{return Ok(reply.len()+1);}}
        let status=if call>=FAIL_AFTER.get(){{WIRE_ERROR.get()}}else{{0}};
        let decline=matches!(MODE.get(),9|11|12)&&call>=FAIL_AFTER.get();
        let count=if decline||MODE.get()==10{{0}}else{{match MODE.get(){{4=>request.length as u64+1,6=>2,_=>request.length as u64}}}};
        let position=100u64.to_le_bytes();let payload=if status!=0||decline{{&[][..]}}else{{&position[..]}};
        let length=provider::ResponseHeader{{opcode:if MODE.get()==12{{provider::OP_MEMORY_OBJECT}}else{{request.opcode}},object_id:if matches!(MODE.get(),2|11){{42}}else{{41}},
            status,value:if status!=0{{0}}else{{count}},data_length:payload.len()as u32}}.encode(payload,reply).unwrap();
        if MODE.get()==3{{reply[0]^=1;}}if MODE.get()==5{{reply[32]=0;}}Ok(length)
    }}}}
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
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "struct TemporaryMemoryHandle(",
        "fn provider_write(provider:",
    ));
    program.push_str(r#"
fn reset(){assert!(!LIVE.get());assert!(!LOCKED.get());CLOSES.set(0);CALLS.set(0);COPIES.set(0);INLINE_CALLS.set(0);
    CREATE_ERROR.set(0);LOOKUP_ERROR.set(None);LOCK_ERROR.set(None);COPY_ERROR.set(None);
    IPC_ERROR.set(0);MEMORY_ERROR.set(0);OVERLAY_ERROR.set(0);WIRE_ERROR.set(0);MODE.set(0);FAIL_AFTER.set(0);}
fn outcome(pointer:u64,length:usize)->Option<u64>{let result=provider_read_shared(&ProviderObject{object_id:41},77,pointer,length);
    assert!(!LIVE.get());assert!(!LOCKED.get());assert_eq!(CLOSES.get(),usize::from(CREATE_ERROR.get()==0));result}
fn run(pointer:u64,length:usize)->u64{outcome(pointer,length).expect("not an inline decline")}
fn read(length:usize)->u64{provider_read(&ProviderObject{object_id:41},1,length as u64)}
fn main(){
    let chunk=provider::MAX_SHARED_READ_LEN;
    reset();assert_eq!(run(1,chunk+3),(chunk+3)as u64);assert_eq!((CALLS.get(),COPIES.get()),(2,2));
    for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady,Error::ResourceUnavailable,Error::BackingFailure]{
        reset();CREATE_ERROR.set(error.into_raw());assert_eq!(run(1,8),error.into_raw());assert_eq!(CALLS.get(),0);
        reset();LOOKUP_ERROR.set(Some(error));assert_eq!(run(1,8),error.into_raw());assert_eq!(CALLS.get(),0);
        reset();LOCK_ERROR.set(Some(error));assert_eq!(run(1,8),error.into_raw());assert_eq!(CALLS.get(),0);
        reset();COPY_ERROR.set(Some(error));assert_eq!(run(1,8),error.into_raw());
        reset();COPY_ERROR.set(Some(error));FAIL_AFTER.set(1);assert_eq!(run(1,chunk+1),chunk as u64);
        reset();LOCK_ERROR.set(Some(error));FAIL_AFTER.set(1);assert_eq!(run(1,chunk+1),chunk as u64);
    }
    reset();FAIL_ALLOC.set(true);assert_eq!(run(1,8),Error::ResourceUnavailable.into_raw());assert_eq!(CALLS.get(),0);
    for mode in [1,2,3,4,5,7,8]{reset();MODE.set(mode);assert_eq!(run(1,8),Error::BackingFailure.into_raw());assert_eq!(COPIES.get(),0);}
    for error in [Error::PeerClosed.into_raw(),Error::BackingFailure.into_raw(),(-5i64)as u64]{
        reset();IPC_ERROR.set(error);assert_eq!(run(1,8),error);
        reset();MEMORY_ERROR.set(error);assert_eq!(run(1,8),error);
        reset();OVERLAY_ERROR.set(error);assert_eq!(run(1,8),error);
        reset();IPC_ERROR.set(error);FAIL_AFTER.set(1);assert_eq!(run(1,chunk+1),chunk as u64);
    }
    for status in [-95,-38,-11]{reset();WIRE_ERROR.set(status);assert_eq!(run(1,8),status as u64);
        reset();WIRE_ERROR.set(status);FAIL_AFTER.set(1);assert_eq!(run(1,chunk+1),chunk as u64);}
    reset();MODE.set(6);assert_eq!(run(1,8),2);
    reset();assert_eq!(run(0,8),Error::InvalidAddress.into_raw());
    reset();assert_eq!(run(u64::MAX-chunk as u64+1,chunk+1),chunk as u64);
    // A validated empty success is negotiation, not EOF or an error. It
    // releases both the scratch Handle and backing reservation before retry.
    reset();MODE.set(9);assert_eq!(outcome(1,8),None);assert_eq!(COPIES.get(),0);
    reset();MODE.set(9);assert_eq!(read(8192),8192);
    assert_eq!((CALLS.get(),INLINE_CALLS.get(),CLOSES.get()),(1,3,1));assert!(!LIVE.get());
    // Declining a later chunk returns its completed prefix, never replays it.
    reset();MODE.set(9);FAIL_AFTER.set(1);assert_eq!(read(chunk+8),chunk as u64);
    assert_eq!((CALLS.get(),INLINE_CALLS.get(),CLOSES.get()),(2,0,1));
    // A positioned zero count remains EOF and must not fall back.
    reset();MODE.set(10);assert_eq!(read(8192),0);assert_eq!(INLINE_CALLS.get(),0);
    for mode in [5,11,12]{reset();MODE.set(mode);assert_eq!(read(8192),Error::BackingFailure.into_raw());assert_eq!(INLINE_CALLS.get(),0);}
    for status in [-95,-38,-11]{
        reset();WIRE_ERROR.set(status);assert_eq!(read(8192),status as u64);assert_eq!(INLINE_CALLS.get(),0);
        reset();IPC_ERROR.set(status as u64);assert_eq!(read(8192),status as u64);assert_eq!(INLINE_CALLS.get(),0);
        reset();WIRE_ERROR.set(status);FAIL_AFTER.set(1);assert_eq!(read(chunk+8),chunk as u64);assert_eq!(INLINE_CALLS.get(),0);
    }
    reset();IPC_ERROR.set(Error::NotReady.into_raw());assert_eq!(read(8192),Error::NotReady.into_raw());assert_eq!(INLINE_CALLS.get(),0);
}
"#);
    probe::run(&program);
}
