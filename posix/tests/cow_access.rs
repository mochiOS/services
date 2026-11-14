#[path = "../../../core/src/mem/cow_access.rs"]
mod cow_access;
use cow_access::*;
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

const WRITABLE: u64 = 1 << 1;
const PRESENT: u64 = 1;
const USER: u64 = 1 << 2;
const NX: u64 = 1 << 63;

#[test]
fn read_only_cow_storage_never_authorizes_a_write_fault() {
    let flags = PRESENT | USER | NX | COPY_ON_WRITE;
    assert!(may_resolve(flags));
    let restricted = with_write_access(flags, false);
    assert_eq!(restricted, flags | WRITE_DISABLED);
    assert!(!may_resolve(restricted));
    assert!(!may_resolve(restricted & !PRESENT & !NX));
    assert!(may_resolve(with_write_access(restricted, true)));
    assert!(!may_resolve(flags | WRITABLE));
    assert!(!may_resolve(PRESENT | USER | NX));
    assert!(!may_resolve(flags & !USER));
    assert!(!may_resolve(flags & !PRESENT));
}

#[test]
fn cloning_preserves_denial_and_can_later_isolate_read_only_or_none_pages() {
    for flags in [
        PRESENT | USER,
        USER | NX,
        PRESENT | USER | NX | COPY_ON_WRITE | WRITE_DISABLED,
    ] {
        let cloned = clone_private(flags, false);
        assert!(!may_resolve(cloned));
        assert_ne!(cloned & COPY_ON_WRITE, 0);
        assert!(may_resolve(with_write_access(cloned | NX, true) | PRESENT));
        assert_eq!(cloned & (PRESENT | NX), flags & (PRESENT | NX));
    }
    for flags in [
        PRESENT | USER | NX | WRITABLE,
        PRESENT | USER | NX | COPY_ON_WRITE,
    ] {
        // Current metadata can deny writing even when an old PTE allowed it.
        assert!(!may_resolve(clone_private(flags, false)));
        assert!(may_resolve(clone_private(flags, true)));
        assert_eq!(
            copy_private(flags, false) & (WRITABLE | COPY_ON_WRITE | WRITE_DISABLED),
            0
        );
        assert_eq!(copy_private(flags, true) & WRITABLE, WRITABLE);
    }
    for flags in [
        PRESENT | USER,
        PRESENT | USER | WRITABLE,
        PRESENT | USER | COPY_ON_WRITE,
    ] {
        assert!(
            !may_resolve(clone_private(flags, true)),
            "executable private pages never grant COW writes"
        );
        assert_eq!(copy_private(flags, true) & WRITABLE, 0);
    }
}

#[test]
fn live_cow_fault_and_usercopy_keep_root_locked_and_revalidate_identity() {
    let mut program = String::from(
        r#"
#[derive(Debug,PartialEq,Eq)]pub enum Kernel{Memory(result::Memory)}
mod result{#[derive(Debug,PartialEq,Eq)]pub enum Memory{InvalidAddress,PermissionDenied,Busy}pub type Result<T>=core::result::Result<T,crate::Kernel>;}
thread_local!{static MODE:std::cell::Cell<u8>=const{std::cell::Cell::new(0)};static LOCKED:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};static CALLS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};}
mod syscall{pub mod security{pub fn current_process_id()->Option<u64>{Some(1)}}}
mod task{
 pub struct Process;pub struct Region;
 impl Region{
  pub fn allows_write_at(&self,_:u64)->bool{matches!(crate::MODE.get(),0|4|6)}
  pub fn allows_execute_at(&self,_:u64)->bool{matches!(crate::MODE.get(),2|4)}
 }
 impl Process{
  pub fn page_table(&self)->Option<u64>{Some(if crate::MODE.get()==5{18}else{17})}
  pub fn find_memory_region(&self,_:u64)->Option<&Region>{(crate::MODE.get()!=3).then_some(&Region)}
  pub fn memory_regions(&self)->&[()]{&[]}
 }
 pub fn with_process_mut<T>(id:u64,body:impl FnOnce(&mut Process)->T)->Option<T>{
  assert_eq!(id,1);assert!(!crate::LOCKED.replace(true));let result=body(&mut Process);assert!(crate::LOCKED.replace(false));Some(result)
 }
}
mod mem{
 pub mod mapping_admission{pub fn check_access(_:&[()],_:u64,_:u64)->crate::result::Result<()>{
  assert!(crate::LOCKED.get());if crate::MODE.get()==6{Err(crate::Kernel::Memory(crate::result::Memory::Busy))}else{Ok(())}
 }}
 pub mod paging{pub fn resolve_copy_on_write(table:u64,address:u64)->crate::result::Result<bool>{
  assert!(crate::LOCKED.get());assert_eq!((table,address),(17,0x1000));crate::CALLS.set(crate::CALLS.get()+1);Ok(true)
 }}
}
"#,
    );
    program.push_str(&probe::definition(
        include_str!("../../../core/src/syscall/process.rs"),
        "fn resolve_user_copy_on_write(",
    ));
    program.push_str(
        r#"
fn main(){for mode in 0..7{
 MODE.set(mode);CALLS.set(0);
 let result=resolve_user_copy_on_write(17,0x1000);
 match mode{
  0|3=>{assert_eq!(result,Ok(true));assert_eq!(CALLS.get(),1);},
  5=>assert_eq!(result,Err(Kernel::Memory(result::Memory::InvalidAddress))),
  6=>assert_eq!(result,Err(Kernel::Memory(result::Memory::Busy))),
  _=>assert_eq!(result,Err(Kernel::Memory(result::Memory::PermissionDenied))),
 }
 if !matches!(mode,0|3){assert_eq!(CALLS.get(),0,"denied writes must not reach PTE mutation");}
 assert!(!LOCKED.get());
}}
"#,
    );
    probe::run(&program);
    let process = include_str!("../../../core/src/syscall/process.rs");
    let fault = process
        .split("pub(crate) fn resolve_user_copy_on_write(")
        .nth(1)
        .unwrap()
        .split("pub fn handle_user_memory_fault(")
        .next()
        .unwrap();
    assert!(fault.contains("with_process_mut"));
    assert!(fault.contains("process.page_table() != Some(table)"));
    let usercopy = include_str!("../../../core/src/syscall/mod.rs");
    let copy = usercopy
        .split("fn copy_into_current_root(")
        .nth(1)
        .unwrap()
        .split("pub fn copy_to_user_native(")
        .next()
        .unwrap();
    assert!(copy.contains("with_process_mut"));
    assert!(copy.contains("process.page_table() != Some(table)"));
    assert!(
        include_str!("../../../core/src/interrupt/idt.rs")
            .contains("process::resolve_user_copy_on_write")
    );
}
