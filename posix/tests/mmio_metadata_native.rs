#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn mmio_metadata_checks_overlap_and_preserves_state_on_allocation_failure() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
extern crate self as mnu_abi;
#[path={:?}]mod status;
use status::Error;
type Result<T> = core::result::Result<T, ()>;
use std::sync::atomic::{{AtomicBool,Ordering}};
static FAIL:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{{
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{{
        if FAIL.swap(false,Ordering::Relaxed){{return std::ptr::null_mut();}}
        unsafe{{std::alloc::System.alloc(l)}}
    }}
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(p,l)}}}}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[derive(Clone,Copy)]struct MmioMapping{{start:u64,length:u64}}
impl MmioMapping{{
    fn end(&self)->Option<u64>{{self.start.checked_add(self.length)}}
    fn start(&self)->u64{{self.start}}
    fn virt_start(&self)->u64{{self.start}}
}}
struct Process{{
    mmio_mappings:Vec<MmioMapping>,memory_regions:Vec<MmioMapping>,dma_buffers:Vec<MmioMapping>,
    heap_start:u64,heap_end:u64,stack_bottom:u64,stack_top:u64,
}}
impl Process{{
"#,
        root.join("core/crates/abi/src/status.rs")
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/process.rs"),
        "    pub fn add_mmio_mapping(",
        "    pub fn remove_mmio_mapping(",
    ));
    program.push_str(r#"
}
fn fresh()->Process{Process{mmio_mappings:Vec::new(),memory_regions:Vec::new(),dma_buffers:Vec::new(),heap_start:0,heap_end:0,stack_bottom:0,stack_top:0}}
fn range(start:u64)->MmioMapping{MmioMapping{start,length:4096}}
fn main(){
    let mut p=fresh();FAIL.store(true,Ordering::Relaxed);
    assert_eq!(p.add_mmio_mapping(range(4096)),Err(Error::ResourceUnavailable));
    assert!(!FAIL.load(Ordering::Relaxed));assert!(p.mmio_mappings.is_empty());
    assert_eq!(p.add_mmio_mapping(range(4096)),Ok(()));
    assert_eq!(p.mmio_mappings.len(),1);
    FAIL.store(true,Ordering::Relaxed);
    assert_eq!(p.add_mmio_mapping(range(4096)),Err(Error::AlreadyExists));
    assert!(FAIL.swap(false,Ordering::Relaxed));assert_eq!(p.mmio_mappings.len(),1);
    assert_eq!(p.add_mmio_mapping(range(8192)),Ok(()));
    assert_eq!(p.add_mmio_mapping(range(u64::MAX)),Err(Error::InvalidAddress));
    for overlap in 0..4{
        let mut p=fresh();match overlap{
            0=>p.memory_regions.push(range(4096)),1=>p.dma_buffers.push(range(4096)),
            2=>{p.heap_start=4096;p.heap_end=8192;},
            3=>{p.stack_bottom=4096;p.stack_top=8192;},_=>unreachable!()
        }
        FAIL.store(true,Ordering::Relaxed);
        assert_eq!(p.add_mmio_mapping(range(4096)),Err(Error::AlreadyExists));
        assert!(FAIL.swap(false,Ordering::Relaxed));assert!(p.mmio_mappings.is_empty());
    }
}
"#);
    probe::run(&program);
}
