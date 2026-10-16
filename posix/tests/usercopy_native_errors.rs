#[path = "support/native_error_probe.rs"]
#[allow(dead_code)]
mod probe;

#[test]
fn production_usercopy_preserves_fault_categories_and_retry_boundaries() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let cause = probe::between(abi, "pub enum MemoryFaultCause {", "\n}");
    let mut program = String::from("#![allow(dead_code)]\nmod mnu_abi {pub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n#[derive(Clone,Copy,Debug)]\n");
    program.push_str(cause);
    program.push_str("\n}\n}\nmod usercopy_error {\nuse crate::mnu_abi;\n");
    program.push_str(
        include_str!("../../../core/src/syscall/usercopy_error.rs")
            .split_once('\n')
            .unwrap()
            .1,
    );
    program.push_str("}\n");
    program.push_str(r#"
use std::{cell::RefCell,collections::VecDeque};
use mnu_abi::{MemoryFaultCause as Cause,status::Error};
mod result {
    #[derive(Clone,Copy,Debug)] pub enum Memory{Busy,OutOfMemory,PermissionDenied,InvalidAddress}
    pub type Result<T>=core::result::Result<T,crate::Kernel>;
}
#[derive(Clone,Copy,Debug)] enum Kernel {Memory(result::Memory),Other}
#[derive(Clone,Copy)] struct Fault {cause:Cause,retry:bool}
impl Fault {fn cause(self)->Cause{self.cause} fn is_retryable(self)->bool{self.retry}}
struct State {
    root:Option<u64>, resident:bool, read:VecDeque<result::Result<()>>, write:VecDeque<result::Result<()>>,
    faults:VecDeque<Result<(),Fault>>, reads:usize,writes:usize,yields:usize,audits:usize,locked:bool,
}
impl Default for State {fn default()->Self{Self{
    root:Some(1),resident:true,read:vec![Ok(())].into(),write:vec![Ok(())].into(),faults:VecDeque::new(),
    reads:0,writes:0,yields:0,audits:0,locked:false,
}}}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
const EFAULT:u64=(-14_i64)as u64;
fn current_user_page_table()->Option<u64>{STATE.with_borrow(|s|s.root)}
fn is_canonical_user_range(address:u64,len:u64)->bool{address!=0&&len!=0&&address.checked_add(len).is_some_and(|end|end<=1<<47)}
fn last_syscall_snapshot()->(u64,[u64;6]){(699,[0;6])}
fn current_process_name_for_log()->Option<String>{Some("probe".into())}
#[derive(Clone,Copy)] struct Pid(u64);impl Pid{fn as_u64(self)->u64{self.0}}
mod security {pub fn current_process_id()->Option<crate::Pid>{Some(crate::Pid(7))}}
mod syscall {pub mod security {pub fn current_process_id()->Option<crate::Pid>{crate::security::current_process_id()}}}
mod audit {pub enum AuditEventKind{Usercopy} pub fn log(_:AuditEventKind,_:&str){crate::STATE.with_borrow_mut(|s|s.audits+=1);}}
mod task {
    pub struct Process;impl Process {pub fn page_table(&self)->Option<u64>{crate::current_user_page_table()}}
    pub fn with_process<T>(id:crate::Pid,operation:impl FnOnce(&Process)->T)->Option<T>{
        assert_eq!(id.as_u64(),7);crate::STATE.with_borrow_mut(|s|{assert!(!s.locked);s.locked=true;});
        let result=operation(&Process);crate::STATE.with_borrow_mut(|s|s.locked=false);Some(result)
    }
    pub fn yield_now(){crate::STATE.with_borrow_mut(|s|s.yields+=1);}
}
mod mem {pub mod paging {
    pub fn is_user_range_mapped_in_table(_:u64,_:u64,_:u64)->bool{crate::STATE.with_borrow(|s|{assert!(s.locked);s.resident})}
    pub fn is_user_range_writable_in_table(a:u64,b:u64,c:u64)->bool{is_user_range_mapped_in_table(a,b,c)}
}}
mod process {
    pub fn handle_user_memory_fault(_:u64,_:bool,_:bool)->Result<(),crate::Fault>{
        crate::STATE.with_borrow_mut(|s|{assert!(!s.locked,"fault preparation must not hold PROC");
            let result=s.faults.pop_front().expect("extra backing fault");if result.is_ok(){s.resident=true;}result
        })
    }
}
fn copy_out_of_current_root(_:u64,_:u64,bytes:&mut[u8])->result::Result<()>{
    STATE.with_borrow_mut(|s|{s.reads+=1;let result=s.read.pop_front().expect("extra read");if result.is_ok(){bytes.fill(0x71);}result})
}
fn copy_into_current_root(_:u64,_:u64,_:&[u8])->result::Result<()>{STATE.with_borrow_mut(|s|{s.writes+=1;s.write.pop_front().expect("extra write")})}
"#);
    let source = include_str!("../../../core/src/syscall/mod.rs");
    program.push_str(probe::between(
        source,
        "fn retry_usercopy<T>(",
        "/// ユーザー空間から",
    ));
    program.push_str(probe::between(
        source,
        "pub fn copy_from_user(",
        "/// Resident usercopy",
    ));
    program.push_str(probe::between(
        source,
        "pub fn copy_to_user(",
        "pub fn read_user_u64(",
    ));
    program.push_str(r#"
fn main(){
    use result::Memory;
    let mut bytes=[0;4];
    STATE.set(State::default());assert_eq!(copy_from_user_native(4096,&mut bytes),Ok(()));assert_eq!(bytes,[0x71;4]);
    for write in [false,true] {
        let mut state=State::default();let sequence=vec![Err(Kernel::Memory(Memory::Busy)),Err(Kernel::Memory(Memory::Busy)),Ok(())].into();
        if write{state.write=sequence;}else{state.read=sequence;}
        STATE.set(state);
        assert_eq!(if write{copy_to_user_native(8192,&bytes)}else{copy_from_user_native(4096,&mut bytes)},Ok(()));
        STATE.with_borrow(|s|{assert_eq!(s.reads+s.writes,3);assert_eq!(s.yields,2);assert_eq!(s.audits,0);});
        for (cause,expected) in [
            (Cause::Unmapped,Error::InvalidAddress),(Cause::AccessDenied,Error::InvalidAddress),
            (Cause::OutsideBacking,Error::InvalidAddress),(Cause::Unresolved,Error::InvalidAddress),
            (Cause::ResourceUnavailable,Error::ResourceUnavailable),(Cause::BackingFailure,Error::BackingFailure),
        ] {
            let mut state=State{resident:false,faults:vec![Err(Fault{cause,retry:false})].into(),..State::default()};
            if write {state.write=vec![Err(Kernel::Memory(Memory::InvalidAddress))].into();}
            else {state.read=vec![Err(Kernel::Memory(Memory::InvalidAddress))].into();}
            STATE.set(state);
            let actual=if write{copy_to_user_native(8192,&bytes)}else{copy_from_user_native(4096,&mut bytes)};
            assert_eq!(actual,Err(expected));STATE.with_borrow(|s|{assert_eq!(s.reads+s.writes,1);assert_eq!(s.audits,1);});
        }
        let mut state=State{resident:false,faults:vec![Err(Fault{cause:Cause::Unresolved,retry:true}),Ok(())].into(),..State::default()};
        let sequence=vec![Err(Kernel::Memory(Memory::InvalidAddress)),Ok(())].into();
        if write{state.write=sequence;}else{state.read=sequence;}
        STATE.set(state);
        assert_eq!(if write{copy_to_user_native(8192,&bytes)}else{copy_from_user_native(4096,&mut bytes)},Ok(()));
        STATE.with_borrow(|s|{assert_eq!(s.reads+s.writes,2);assert_eq!(s.yields,1);assert_eq!(s.audits,0);});
        for (failure,expected) in [(Kernel::Memory(Memory::OutOfMemory),Error::ResourceUnavailable),(Kernel::Other,Error::BackingFailure)] {
            let mut state=State::default();let sequence=vec![Err(failure),Err(failure)].into();
            if write{state.write=sequence;}else{state.read=sequence;}
            STATE.set(state);
            assert_eq!(if write{copy_to_user_native(8192,&bytes)}else{copy_from_user_native(4096,&mut bytes)},Err(expected));
        }
    }
    STATE.set(State{root:None,..State::default()});
    assert_eq!(copy_from_user_native(4096,&mut bytes),Err(Error::InvalidAddress));
    assert_eq!(copy_to_user_native(8192,&bytes),Err(Error::InvalidAddress));
    assert_eq!(copy_from_user_native(0,&mut []),Ok(()));assert_eq!(copy_to_user_native(0,&[]),Ok(()));
    // The not-yet-migrated entry points keep their old result convention.
    assert_eq!(copy_from_user(4096,&mut bytes),Err(EFAULT));assert_eq!(copy_to_user(8192,&bytes),Err(EFAULT));
    for address in [0,u64::MAX] {assert_eq!(fault_in_user_range(1,address,4,false),Err(Error::InvalidAddress));}
    STATE.with_borrow(|s|assert_eq!(s.reads+s.writes,0));
}
"#);
    probe::run(&program);
}
