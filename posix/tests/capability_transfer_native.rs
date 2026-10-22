#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn transfer_reserves_destination_before_removal_under_one_process_lock() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        "#![allow(dead_code)]\nextern crate alloc;\nextern crate self as mnu_abi;\n#[path={:?}]mod abi;pub use abi::*;\nuse status::Error;\nuse alloc::{{string::{{String,ToString}},vec::Vec}};\nuse std::cell::RefCell;\nuse std::sync::atomic::{{AtomicBool,Ordering}};\n",
        root.join("core/crates/abi/src/lib.rs"),
    );
    program.push_str(r#"
static ARM:AtomicBool=AtomicBool::new(false);
static FAIL:AtomicBool=AtomicBool::new(false);
static REVOKE:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{
        if FAIL.swap(false,Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe{std::alloc::System.alloc(l)}
    }
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
thread_local!{static REGISTRY:RefCell<DynamicCapabilityRegistry>=const{RefCell::new(DynamicCapabilityRegistry{names:Vec::new()})};}
fn with_dynamic_registry<R>(f:impl FnOnce(&mut DynamicCapabilityRegistry)->R)->R{REGISTRY.with_borrow_mut(f)}
"#);
    let capability = include_str!("../../../core/src/capability/mod.rs");
    for (start, end) in [
        (
            "/// kernel が直接強制する低レベル権限",
            "/// mnu が直接強制する権限",
        ),
        ("/// mnu が直接強制する権限", "static DYNAMIC_CAPABILITIES:"),
        ("fn valid_capability_name(", "/// `parent` が、"),
    ] {
        program.push_str(probe::between(capability, start, end));
    }
    program.push_str(&capability[capability.find("/// `parent` が、").unwrap()..]);
    program.push_str(r#"
const SUCCESS:u64=0;const EACCES:u64=(-13i64)as u64;const EINVAL:u64=(-22i64)as u64;const ENOSYS:u64=(-38i64)as u64;
mod task {pub mod process {
    use crate::*;
    type ProcessId=u64;
    pub struct Process {pub id:u64,pub caps:CapabilitySet,pub authorities:KernelAuthoritySet}
    impl Process {
        fn id(&self)->u64{self.id}
        pub fn exe_path(&self)->&str{"unused"}
        pub fn capabilities(&self)->&CapabilitySet{&self.caps}
        pub fn capabilities_mut(&mut self)->&mut CapabilitySet{&mut self.caps}
        pub fn kernel_authorities(&self)->&KernelAuthoritySet{&self.authorities}
        pub fn kernel_authorities_mut(&mut self)->&mut KernelAuthoritySet{&mut self.authorities}
    }
    pub struct Table {pub processes:[Option<Process>;4]}
    struct Lock(std::sync::Mutex<Table>);
    impl Lock {fn lock(&self)->std::sync::MutexGuard<'_,Table>{
        let mut guard=self.0.try_lock().expect("nested process-table lock");
        if REVOKE.swap(false,Ordering::Relaxed){
            for p in guard.processes.iter_mut().flatten().filter(|p|p.id==1){
                p.caps=CapabilitySet::empty();p.authorities=KernelAuthoritySet::empty();
            }
        }
        if ARM.swap(false,Ordering::Relaxed){FAIL.store(true,Ordering::Relaxed);}
        guard
    }}
    static PROCESS_TABLE:Lock=Lock(std::sync::Mutex::new(Table{processes:[None,None,None,None]}));
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/task/process.rs"),
        "pub(crate) fn with_process_pair_mut",
        "pub(crate) fn with_mapping_table",
    ));
    program.push_str(r#"
    pub fn with_process<R>(id:u64,f:impl FnOnce(&Process)->R)->Option<R>{
        let table=PROCESS_TABLE.0.lock().unwrap();table.processes.iter().flatten().find(|p|p.id==id).map(f)
    }
    pub fn with_process_mut<R>(id:u64,f:impl FnOnce(&mut Process)->R)->Option<R>{
        let mut table=PROCESS_TABLE.lock();table.processes.iter_mut().flatten().find(|p|p.id==id).map(f)
    }
    pub fn process_has_capability(id:u64,cap:Capability)->bool{
        with_process(id,|p|p.caps.contains(cap)).unwrap_or(false)
    }
    pub fn process_has_kernel_authority(id:u64,cap:&KernelAuthority)->bool{
        with_process(id,|p|p.authorities.implies(cap)).unwrap_or(false)
    }
    pub fn set(source:Option<&str>,destination:Option<&str>,reverse:bool){
        let make=|id,name:Option<&str>|{
            let mut caps=CapabilitySet::empty();let mut authorities=KernelAuthoritySet::empty();
            if let Some(name)=name{if let Some(a)=parse_kernel_authority_spec(name){authorities.insert(a)}else{caps.insert(Capability::from_str(name).unwrap())}}
            Process{id,caps:caps.try_clone().unwrap(),authorities:authorities.try_clone().unwrap()}
        };
        let source=Some(make(1,source));let destination=Some(make(2,destination));
        PROCESS_TABLE.0.lock().unwrap().processes=if reverse{[None,destination,None,source]}else{[source,None,destination,None]};
    }
    pub fn remove_destination(){PROCESS_TABLE.0.lock().unwrap().processes.iter_mut().for_each(|p|if p.as_ref().is_some_and(|p|p.id==2){*p=None;});}
}}
use task::process;
mod control {use super::*;pub static RACE:AtomicBool=AtomicBool::new(false);pub static MISSING:AtomicBool=AtomicBool::new(false);}
fn current_process()->Option<u64>{(!control::MISSING.load(Ordering::Relaxed)).then_some(1)}
fn resolve_destination_process(dest:u64)->Option<u64>{
    if dest==99{return None;}
    if control::RACE.swap(false,Ordering::Relaxed){process::remove_destination();}
    Some(dest)
}
fn read_capability_spec_from_user(pointer:u64,length:u64)->Result<String,u64>{
    Ok(unsafe{std::str::from_utf8(std::slice::from_raw_parts(pointer as *const u8,length as usize)).unwrap()}.to_string())
}
fn intern_capability_token(name:&str)->Option<CapabilityToken>{parse_capability_token(name)}
"#);
    let syscall = include_str!("../../../core/src/syscall/capability.rs");
    program.push_str(probe::between(
        syscall,
        "#[derive(Clone, Copy)]",
        "/// 指定スレッド",
    ));
    program.push_str(probe::between(
        syscall,
        "pub fn transfer_capability(",
        "pub fn restrict_capability(",
    ));
    program.push_str(probe::between(
        syscall,
        "fn parse_capability_token(",
        "fn intern_capability_token(",
    ));
    program = program
        .replace("dest_process.as_u64()", "dest_process")
        .replace(
            "crate::task::with_process(",
            "crate::task::process::with_process(",
        )
        .replace(
            "crate::task::with_process_mut(",
            "crate::task::process::with_process_mut(",
        );
    program.push_str(r#"
fn transfer(destination:u64,name:&str)->u64{transfer_capability(destination,name.as_ptr()as u64,name.len()as u64)}
fn owns(id:u64,name:&str)->bool{process::with_process(id,|p|match parse_capability_token(name).unwrap(){
    CapabilityToken::Plain(c)=>p.caps.contains_exact(c),CapabilityToken::Authority(a)=>p.authorities.contains_exact(&a)
}).unwrap_or(false)}
fn main(){
    for name in ["fs.read.tmp","memory.phys.map@4096:4096"]{
        for reverse in [false,true]{
            process::set(Some(name),None,reverse);ARM.store(true,Ordering::Relaxed);
            assert_eq!(transfer(2,name),Error::ResourceUnavailable.into_raw());
            assert!(!FAIL.load(Ordering::Relaxed));assert!(owns(1,name));assert!(!owns(2,name));
            assert_eq!(transfer(2,name),SUCCESS);assert!(!owns(1,name));assert!(owns(2,name));
            process::set(Some(name),Some(name),reverse);ARM.store(true,Ordering::Relaxed);
            assert_eq!(transfer(2,name),SUCCESS);assert!(FAIL.swap(false,Ordering::Relaxed));
            assert!(!owns(1,name));assert!(owns(2,name));
            process::set(Some(name),None,reverse);control::RACE.store(true,Ordering::Relaxed);
            assert_eq!(transfer(2,name),Error::NotFound.into_raw());assert!(owns(1,name));
            process::set(Some(name),None,reverse);
            assert_eq!(transfer(1,name),SUCCESS);assert!(owns(1,name));assert!(!owns(2,name));
            process::set(Some(name),None,reverse);REVOKE.store(true,Ordering::Relaxed);
            assert_eq!(transfer(2,name),Error::AccessDenied.into_raw());assert!(!owns(2,name));
        }
    }
    process::set(Some("fs.read.all"),None,false);
    assert_eq!(transfer(2,"fs.read.tmp"),Error::AccessDenied.into_raw());
    assert!(owns(1,"fs.read.all"));assert!(!owns(2,"fs.read.tmp"));
    process::set(Some("capabilities.manage"),None,false);ARM.store(true,Ordering::Relaxed);
    assert_eq!(transfer(2,"fs.read.tmp\x1funused"),Error::ResourceUnavailable.into_raw());
    assert!(!owns(2,"fs.read.tmp"));assert!(owns(1,"capabilities.manage"));
    assert_eq!(transfer(2,"fs.read.tmp\x1funused"),SUCCESS);assert!(owns(2,"fs.read.tmp"));
    assert_eq!(transfer(2,"fs.read.tmp\x1fwrong"),Error::AccessDenied.into_raw());
    for grant in ["fs.scope.read@/file\x1funused","fs.scope.read-write@/home/user/file\x1funused"] {
        assert_eq!(transfer(2,grant),Error::InvalidArgument.into_raw());
        assert!(!owns(2,"fs.read.all"));
    }
    assert_eq!(transfer(99,"fs.read.tmp"),Error::NotFound.into_raw());
    control::MISSING.store(true,Ordering::Relaxed);
    assert_eq!(transfer(2,"fs.read.tmp"),Error::NotReady.into_raw());
}
"#);
    probe::run(&program);
}
