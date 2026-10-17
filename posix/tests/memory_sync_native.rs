#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn sync_checks_full_coverage_before_io_and_preserves_native_failures() {
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
use std::sync::Arc;
use std::cell::{{Cell,RefCell}};
const SUCCESS:u64=0;const MEMORY_ACCESS_WRITE:u64=2;
thread_local! {{
    static CONTEXT:Cell<bool>=const{{Cell::new(true)}};
    static PRESENT:Cell<bool>=const{{Cell::new(true)}};
    static LOCKED:Cell<bool>=const{{Cell::new(false)}};
    static IO:RefCell<Vec<(u64,u64,u64)>>=const{{RefCell::new(Vec::new())}};
    static FAILURE:Cell<Option<(u64,u64)>>=const{{Cell::new(None)}};
    static REPLACE:Cell<bool>=const{{Cell::new(false)}};
    static PROCESS:RefCell<task::Process>=const{{RefCell::new(task::Process{{regions:Vec::new()}})}};
}}
fn page_align_up(value:u64)->Option<u64>{{value.checked_add(4095).map(|v|v&!4095)}}
fn is_user_range(start:u64,length:u64)->bool{{start>0&&start.checked_add(length).is_some_and(|end|end<=0x800000000000)}}
mod syscall {{pub mod security {{pub fn current_process_id()->Option<u64>{{crate::CONTEXT.get().then_some(7)}}}}}}
mod mem {{#[path={plan:?}]pub mod range_plan;#[path={writeback:?}]pub mod writeback;}}
mod task {{
    use super::*;
    pub struct Object(pub u64);
    impl Object {{
        pub fn flush_range(&self,offset:u64,length:u64)->Result<(),u64>{{
            assert!(!LOCKED.get(),"I/O while process table is locked");
            IO.with_borrow_mut(|io|io.push((self.0,offset,length)));
            if REPLACE.replace(false){{PROCESS.with_borrow_mut(|p|p.regions.clear());}}
            if let Some((id,error))=FAILURE.get(){{if id==self.0{{return Err(error);}}}}
            Ok(())
        }}
    }}
    pub struct Region {{pub start:u64,pub end:Option<u64>,pub offset:u64,pub shared:bool,pub writable:bool,pub object:Option<Arc<Object>>}}
    impl Region {{
        pub fn start(&self)->u64{{self.start}}
        pub fn end(&self)->Option<u64>{{self.end}}
        pub fn is_shared(&self)->bool{{self.shared}}
        pub fn permits_access(&self,access:u64)->bool{{assert_eq!(access,2);self.writable}}
        pub fn backing(&self)->&Self{{self}}
        pub fn file_offset(&self)->u64{{self.offset}}
        pub fn file_object(&self)->Option<&Arc<Object>>{{self.object.as_ref()}}
    }}
    pub struct Process {{pub regions:Vec<Region>}}
    impl Process {{pub fn find_memory_region(&self,cursor:u64)->Option<&Region>{{
        assert!(LOCKED.get());self.regions.iter().find(|r|r.start<=cursor&&cursor<r.start+8192)
    }}}}
    pub fn with_process<T>(id:u64,body:impl FnOnce(&Process)->T)->Option<T>{{
        assert_eq!(id,7);if !PRESENT.get(){{return None;}}
        assert!(!LOCKED.replace(true));let result=PROCESS.with_borrow(body);LOCKED.set(false);Some(result)
    }}
}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        plan = root.join("core/src/mem/range_plan.rs"),
        writeback = root.join("core/src/mem/writeback.rs"),
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/process.rs"),
        "pub fn memory_sync(",
        "fn fill_random_buffer(",
    ));
    program.push_str(r#"
fn reset(){
    CONTEXT.set(true);PRESENT.set(true);LOCKED.set(false);IO.with_borrow_mut(Vec::clear);
    FAILURE.set(None);REPLACE.set(false);
    PROCESS.with_borrow_mut(|p|p.regions=vec![
        task::Region{start:4096,end:Some(12288),offset:65536,shared:true,writable:true,object:Some(Arc::new(task::Object(1)))},
        task::Region{start:12288,end:Some(20480),offset:131072,shared:true,writable:true,object:Some(Arc::new(task::Object(2)))},
    ]);
}
fn no_io(){assert!(!LOCKED.get());IO.with_borrow(|io|assert!(io.is_empty()));}
fn main(){
    for (address,length,options,error) in [(0,4096,0,Error::InvalidAddress),
        (4096,0,0,Error::InvalidArgument),(4097,4096,0,Error::InvalidArgument),
        (4096,4096,1,Error::InvalidArgument),(4096,u64::MAX,0,Error::InvalidAddress),
        (0x800000000000,4096,0,Error::InvalidAddress)]{
        reset();assert_eq!(memory_sync(address,length,options),error.into_raw());no_io();
    }
    for context in [false,true]{reset();CONTEXT.set(context);PRESENT.set(!context);
        assert_eq!(memory_sync(4096,4096,0),Error::NotReady.into_raw());no_io();
    }
    reset();PROCESS.with_borrow_mut(|p|{p.regions.pop();});
    assert_eq!(memory_sync(4096,12288,0),Error::InvalidAddress.into_raw());no_io();
    reset();PROCESS.with_borrow_mut(|p|p.regions[1].end=Some(12288));
    assert_eq!(memory_sync(4096,12288,0),Error::BackingFailure.into_raw());no_io();
    reset();PROCESS.with_borrow_mut(|p|p.regions[1].offset=u64::MAX);
    assert_eq!(memory_sync(16384,4096,0),Error::InvalidAddress.into_raw());no_io();
    // The first I/O replaces all mappings; the second still uses its retained object.
    reset();REPLACE.set(true);assert_eq!(memory_sync(8192,8192,0),0);
    IO.with_borrow(|io|assert_eq!(*io,[(1,69632,4096),(2,131072,4096)]));
    PROCESS.with_borrow(|p|assert!(p.regions.is_empty()));
    for skip in 0..3{reset();PROCESS.with_borrow_mut(|p|match skip{
        0=>p.regions[1].shared=false,1=>p.regions[1].writable=false,2=>p.regions[1].object=None,_=>unreachable!()});
        assert_eq!(memory_sync(4096,16384,0),0);
        IO.with_borrow(|io|assert_eq!(*io,[(1,65536,8192)]));
    }
    for error in [Error::InvalidAddress,Error::InvalidArgument,Error::ResourceUnavailable,
        Error::BackingFailure,Error::AccessDenied,Error::NotReady,Error::LimitExceeded,
        Error::AlreadyExists,Error::NotFound,Error::PeerClosed]{
        reset();FAILURE.set(Some((1,error.into_raw())));
        assert_eq!(memory_sync(4096,16384,0),error.into_raw());
        IO.with_borrow(|io|assert_eq!(*io,[(1,65536,8192)]));assert!(!LOCKED.get());
    }
    reset();FAILURE.set(Some((2,(-5i64)as u64)));
    assert_eq!(memory_sync(4096,16384,0),(-5i64)as u64);
    IO.with_borrow(|io|assert_eq!(io.len(),2));
}
"#);
    probe::run(&program);
}
