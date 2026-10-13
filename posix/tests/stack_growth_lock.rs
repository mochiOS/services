use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_stack_growth_serializes_admission_and_preserves_reservations() {
    let source = include_str!("../../../core/src/interrupt/idt.rs");
    let start = source
        .find("fn try_grow_user_stack(fault_addr: u64) -> bool {")
        .unwrap();
    let end = source[start..].find("/// x87").unwrap() + start;
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static LOCKED:AtomicBool=AtomicBool::new(false);
static MODE:AtomicUsize=AtomicUsize::new(0);
static MAPS:AtomicUsize=AtomicUsize::new(0);
const TOP:u64=0x1000000;
const BOTTOM:u64=TOP-65536;
fn locked() {assert!(LOCKED.load(Ordering::Acquire));}
mod task {
    pub struct Thread; impl Thread {pub fn process_id(&self)->u64 {1}}
    pub fn current_thread_id()->Option<u64> {Some(1)}
    pub fn with_thread<T>(_:u64,f:impl FnOnce(&Thread)->T)->Option<T> {Some(f(&Thread))}
    pub struct Region {pub start:u64,pub end:Option<u64>}
    impl Region {pub fn start(&self)->u64 {self.start} pub fn end(&self)->Option<u64> {self.end}}
    pub struct Process {pub bottom:u64,pub regions:Vec<Region>}
    impl Process {
        pub fn stack_bottom(&self)->u64 {crate::locked();self.bottom}
        pub fn stack_top(&self)->u64 {crate::locked();crate::TOP}
        pub fn page_table(&self)->Option<u64> {crate::locked(); if crate::MODE.load(crate::Ordering::Acquire)==7 {None} else {Some(4096)}}
        pub fn memory_regions(&self)->&[Region] {crate::locked();&self.regions}
        pub fn find_mmio_mapping_by_addr(&self,_:u64,_:u64)->Option<()> {crate::locked();(crate::MODE.load(crate::Ordering::Acquire)==3).then_some(())}
        pub fn find_dma_buffer_by_addr(&self,_:u64,_:u64)->Option<()> {crate::locked();(crate::MODE.load(crate::Ordering::Acquire)==4).then_some(())}
        pub fn set_stack_bottom(&mut self,bottom:u64) {crate::locked();self.bottom=bottom}
    }
    thread_local! {pub static PROCESS:std::cell::RefCell<Process>=std::cell::RefCell::new(Process {bottom:crate::BOTTOM,regions:Vec::new()});}
    pub fn with_process_mut<T>(_:u64,f:impl FnOnce(&mut Process)->T)->Option<T> {
        assert!(!crate::LOCKED.swap(true,crate::Ordering::AcqRel));
        let value=PROCESS.with(|p| f(&mut p.borrow_mut()));
        crate::LOCKED.store(false,crate::Ordering::Release); Some(value)
    }
}
mod mem {pub mod paging {
    pub fn is_user_range_occupied_in_table(table:u64,start:u64,length:u64)->bool {
        crate::locked(); assert_eq!(table,4096); assert_eq!(start+length,crate::BOTTOM);
        crate::MODE.load(crate::Ordering::Acquire)==5
    }
    pub fn map_and_copy_segment_to(table:u64,start:u64,file:u64,length:u64,bytes:&[u8],write:bool,exec:bool)->Result<(),()> {
        crate::locked(); assert_eq!(table,4096); assert_eq!(file,0); assert!(bytes.is_empty());assert!(write);assert!(!exec);
        assert_eq!(start+length,crate::BOTTOM);crate::MAPS.fetch_add(1,crate::Ordering::AcqRel);
        if crate::MODE.load(crate::Ordering::Acquire)==6 {Err(())} else {Ok(())}
    }
}}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() {
    for mode in 0..8 {
        MODE.store(mode,Ordering::Release);MAPS.store(0,Ordering::Release);
        task::PROCESS.with(|p| {
            let mut p=p.borrow_mut();p.bottom=BOTTOM;p.regions.clear();
            if mode==1 {p.regions.push(task::Region {start:BOTTOM-4096,end:Some(BOTTOM)});}
            if mode==2 {p.regions.push(task::Region {start:BOTTOM-4096,end:None});}
        });
        assert_eq!(try_grow_user_stack(BOTTOM-1),mode==0);
        assert_eq!(MAPS.load(Ordering::Acquire),usize::from(mode==0 || mode==6));
        task::PROCESS.with(|p| assert_eq!(p.borrow().bottom,if mode==0 {BOTTOM-4096} else {BOTTOM}));
        assert!(!LOCKED.load(Ordering::Acquire));
    }
    MODE.store(0,Ordering::Release); MAPS.store(0,Ordering::Release);
    task::PROCESS.with(|p| p.borrow_mut().bottom=BOTTOM);
    assert!(!try_grow_user_stack(BOTTOM));
    assert!(!try_grow_user_stack(TOP-8*1024*1024-1));
    assert_eq!(MAPS.load(Ordering::Acquire),0);
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-stack-lock-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
        .arg("-o")
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
