#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn anonymous_faults_prepare_no_heap_page_and_file_faults_keep_their_backing_bytes() {
    let source = include_str!("../../../core/src/syscall/process.rs");
    let prepare = probe::between(
        source,
        "let page = match pager.as_ref()",
        "// Loading a shared cache page",
    );
    let select = probe::between(
        source,
        "let source: &[u8] = match (pager.as_ref(), page.as_ref())",
        "let install = ||",
    );
    let mut program = String::from(
        r#"
use std::{alloc::{GlobalAlloc,Layout,System},cell::Cell,sync::Arc};
mod mnu_abi { pub mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str(r#"
}}
use mnu_abi::status::Error;
thread_local! {
    static TRACK:Cell<bool>=const{Cell::new(false)};
    static ALLOCATIONS:Cell<usize>=const{Cell::new(0)};
    static READS:Cell<usize>=const{Cell::new(0)};
    static SOURCE_LENGTH:Cell<usize>=const{Cell::new(usize::MAX)};
    static FIRST:Cell<u8>=const{Cell::new(0)};
}
struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:Layout)->*mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false){ALLOCATIONS.set(ALLOCATIONS.get()+1)}
        unsafe {System.alloc(layout)}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:Layout){unsafe{System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[derive(Debug,PartialEq)]enum MemoryFault{Operation(u64),Backing(u64)}
struct Object{bytes:Arc<[u8;4096]>,generation:u64,error:Option<u64>}
impl Object {
    fn page(&self,index:u64)->Result<Arc<[u8;4096]>,u64>{
        assert_eq!(index,7);READS.set(READS.get()+1);
        self.error.map_or_else(||Ok(self.bytes.clone()),Err)
    }
    fn memory_generation(&self)->Option<u64>{Some(self.generation)}
}
fn run(pager:Option<(Arc<Object>,u64)>,shared_file:bool,generation:Option<u64>)->Result<(),MemoryFault>{
"#);
    program.push_str(prepare);
    program.push_str("if shared_file {return Ok(())}\n");
    program.push_str(select);
    program.push_str(
        r#"
    SOURCE_LENGTH.set(source.len());FIRST.set(source.first().copied().unwrap_or(0));Ok(())
}
fn main(){
    TRACK.set(true);
    for _ in 0..1000{assert_eq!(run(None,false,None),Ok(()))}
    TRACK.set(false);
    assert_eq!(ALLOCATIONS.get(),0);assert_eq!(SOURCE_LENGTH.get(),0);assert_eq!(READS.get(),0);
    let object=Arc::new(Object{bytes:Arc::new([0x5a;4096]),generation:1,error:None});
    assert_eq!(run(Some((object.clone(),7)),false,Some(1)),Ok(()));
    assert_eq!(SOURCE_LENGTH.get(),4096);assert_eq!(FIRST.get(),0x5a);assert_eq!(READS.get(),1);
    let error=Error::BackingFailure.into_raw();
    let failed=Arc::new(Object{bytes:object.bytes.clone(),generation:1,error:Some(error)});
    assert_eq!(run(Some((failed.clone(),7)),false,Some(1)),Err(MemoryFault::Backing(error)));
    // A changed generation retries without installing a substitute zero page.
    SOURCE_LENGTH.set(usize::MAX);
    assert_eq!(run(Some((failed,7)),false,Some(0)),Ok(()));
    assert_eq!(SOURCE_LENGTH.get(),usize::MAX);
    READS.set(0);assert_eq!(run(Some((object,7)),true,Some(1)),Ok(()));assert_eq!(READS.get(),0);
}
"#,
    );
    probe::run(&program);
}
