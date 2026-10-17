//! Run production Handle wrappers with controlled native call results.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(name).unwrap();
    let body = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (offset, byte) in source[body..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=body + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function {name}");
}

fn wrapper_program() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        "#![allow(dead_code)]\nextern crate self as mnu_abi;\n#[path={:?}]mod abi;pub use abi::*;\n#[path={:?}]mod handle_result;\n",
        root.join("core/crates/abi/src/lib.rs"),
        root.join("user/crates/platform/src/handle_result.rs"),
    );
    program.push_str(
        "mod syscall {pub use crate::{SyscallNumber,status::Error as NativeError,EINVAL};\n",
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct RawSyscallResult",
    ));
    program.push_str(r#"
thread_local! {
    static RESULT:std::cell::Cell<SysResult<u64>>=const{std::cell::Cell::new(Ok(7))};
    static CALLS:std::cell::RefCell<Vec<(SyscallNumber,Vec<u64>)>>=const{std::cell::RefCell::new(Vec::new())};
}
pub fn result(value:SysResult<u64>){RESULT.set(value);CALLS.with_borrow_mut(Vec::clear);}
pub fn calls()->Vec<(SyscallNumber,Vec<u64>)>{CALLS.with_borrow(Clone::clone)}
fn call(number:SyscallNumber,args:&[u64])->SysResult<u64>{
    CALLS.with_borrow_mut(|calls|calls.push((number,args.to_vec())));RESULT.get()
}
pub fn call0(n:SyscallNumber)->SysResult<u64>{call(n,&[])}
pub fn call1(n:SyscallNumber,a:u64)->SysResult<u64>{call(n,&[a])}
pub fn call2(n:SyscallNumber,a:u64,b:u64)->SysResult<u64>{call(n,&[a,b])}
pub fn call3(n:SyscallNumber,a:u64,b:u64,c:u64)->SysResult<u64>{call(n,&[a,b,c])}
pub fn call4(n:SyscallNumber,a:u64,b:u64,c:u64,d:u64)->SysResult<u64>{call(n,&[a,b,c,d])}
pub fn call6(n:SyscallNumber,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64)->SysResult<u64>{call(n,&[a,b,c,d,e,f])}
}
mod production {
use crate::syscall::{self,SysResult,SysError,SyscallNumber};
type Handle=u32;
"#);
    let source = include_str!("../../../user/crates/platform/src/lib.rs");
    for name in [
        "pub fn create_interrupt_handle(",
        "pub fn create_stopped(",
        "pub fn open_handle_for_endpoint(",
        "pub fn open_handle_for_process_id(",
        "pub fn clone_address_space(",
        "pub fn create_handle(",
        "fn decode(raw:",
        "pub fn duplicate(",
        "pub fn inherited(",
    ] {
        program.push_str(function(source, name));
        program.push('\n');
    }
    let handles = &source[source.find("pub mod handle {").unwrap()..];
    for name in [
        "pub fn read(",
        "pub fn write(",
        "pub fn read_at(",
        "pub fn write_at(",
        "pub fn control(",
    ] {
        program.push_str(function(handles, name));
        program.push('\n');
    }
    program.push_str("pub struct MemoryObject{pub handle:u32}\nimpl MemoryObject{\n");
    program.push_str(function(
        include_str!("../../../user/crates/platform/src/memory_object.rs"),
        "fn create_with_options(",
    ));
    program.push_str("pub fn create()->SysResult<u32>{Self::create_with_options(4096,0).map(|o|o.handle)}\n}\n}\n");
    program
}

#[test]
fn native_handle_results_reject_malformed_success_and_preserve_failures() {
    let mut program = wrapper_program();
    program.push_str(r#"
fn main(){
    use syscall::{SysError,SysResult};
    use status::Error;
    let mut metadata=[0;512];
    let length=process_create::encode_context(
        "opaque:program","program",&ThreadCreateContext{
            entry:0x10000,stack_pointer:0x20000,..ThreadCreateContext::default()
        },&[],&[],&mut metadata
    ).unwrap();
    let metadata=&metadata[..length];
    let factories:Vec<(SyscallNumber,Vec<u64>,Box<dyn Fn()->SysResult<u32>>)>=vec![
        (SyscallNumber::ThreadHandleCreate,vec![],Box::new(production::create_interrupt_handle)),
        (SyscallNumber::ProcessCreate,vec![3,metadata.as_ptr() as u64,metadata.len() as u64],Box::new(||production::create_stopped(3,metadata))),
        (SyscallNumber::ProcessHandleOpen,vec![19,1<<63],Box::new(||production::open_handle_for_endpoint(19,1<<63))),
        (SyscallNumber::ProcessHandleOpenById,vec![27,1<<63],Box::new(||production::open_handle_for_process_id(27,1<<63))),
        (SyscallNumber::AddressSpaceClone,vec![],Box::new(production::clone_address_space)),
        (SyscallNumber::IpcCreateHandle,vec![0,0],Box::new(production::create_handle)),
        (SyscallNumber::HandleDuplicate,vec![17,1<<63],Box::new(||production::duplicate(17,1<<63))),
        (SyscallNumber::LaunchHandleGet,vec![u64::MAX],Box::new(||production::inherited(u64::MAX))),
        (SyscallNumber::MemoryObjectCreate,vec![4096,0],Box::new(production::MemoryObject::create)),
    ];
    for (number,args,factory) in factories {
        for raw in [1,7,u32::MAX as u64] {
            syscall::result(Ok(raw));
            assert_eq!(factory(),Ok(raw as u32));
            assert_eq!(syscall::calls(),vec![(number,args.clone())]);
        }
        for raw in [0,u32::MAX as u64+1,(1<<32)+7,u64::MAX] {
            syscall::result(Ok(raw));
            assert_eq!(factory(),Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64)));
            // No retry or cleanup using a truncated/foreign selector.
            assert_eq!(syscall::calls(),vec![(number,args.clone())]);
        }
        for raw in [Error::AccessDenied.into_raw() as i64,Error::NotFound.into_raw() as i64,
                    Error::ResourceUnavailable.into_raw() as i64,-9,-12,-22,-38] {
            syscall::result(Err(SysError::from_raw(raw)));
            assert_eq!(factory(),Err(SysError::from_raw(raw)));
            assert_eq!(syscall::calls(),vec![(number,args.clone())]);
        }
    }
}
"#);
    probe::run(&program);
}

#[test]
fn native_io_results_are_bounded_by_the_supplied_buffer_without_retries() {
    let mut program = wrapper_program();
    program.push_str(r#"
fn main(){
    use syscall::{SysError,SysResult};
    use status::Error;
    let input=[0x71;3];
    for operation in 0..5 {
        for capacity in [0,1,8] {
            let mut buffer=[0x53;8];
            let pointer=buffer.as_ptr() as u64;
            let number=match operation {
                0=>SyscallNumber::HandleRead,1=>SyscallNumber::HandleWrite,
                2=>SyscallNumber::HandleReadAt,3=>SyscallNumber::HandleWriteAt,
                _=>SyscallNumber::HandleControl,
            };
            let mut args=vec![17,pointer,capacity as u64];
            if operation==2 || operation==3 {args.push(u64::MAX);}
            if operation==4 {args=vec![17,91,input.as_ptr() as u64,3,pointer,capacity as u64];}
            let mut invoke=||->SysResult<usize>{
                let bytes=&mut buffer[..capacity];
                match operation {
                    0=>production::read(17,bytes),
                    1=>production::write(17,bytes),
                    2=>production::read_at(17,bytes,u64::MAX),
                    3=>production::write_at(17,bytes,u64::MAX),
                    _=>production::control(17,91,&input,bytes),
                }
            };
            for raw in [0,capacity as u64/2,capacity as u64] {
                syscall::result(Ok(raw));
                assert_eq!(invoke(),Ok(raw as usize));
                assert_eq!(syscall::calls(),vec![(number,args.clone())]);
            }
            for raw in [capacity as u64+1,u32::MAX as u64,u64::MAX] {
                syscall::result(Ok(raw));
                assert_eq!(invoke(),Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64)));
                assert_eq!(syscall::calls(),vec![(number,args.clone())]);
            }
            for raw in [Error::AccessDenied.into_raw() as i64,Error::BackingFailure.into_raw() as i64,
                        Error::ResourceUnavailable.into_raw() as i64,-9,-12,-22,-38] {
                syscall::result(Err(SysError::from_raw(raw)));
                assert_eq!(invoke(),Err(SysError::from_raw(raw)));
                assert_eq!(syscall::calls(),vec![(number,args.clone())]);
            }
            assert_eq!(buffer,[0x53;8]);
        }
    }
}
"#);
    probe::run(&program);
}
