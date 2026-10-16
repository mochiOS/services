use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_restore_copies_before_commit_and_rejects_invalid_self_contexts() {
    let source = include_str!("../../../core/src/syscall/upcall.rs");
    let thread = include_str!("../../../core/src/task/thread.rs");
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let mut program = String::new();
    let start = thread.find("pub struct UserUpcallContext {").unwrap();
    let end = start + thread[start..].find("\n}\n").unwrap() + 3;
    program.push_str("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n");
    program.push_str(&thread[start..end]);
    program.push_str("mod mnu_abi {\n");
    program.push_str("pub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n");
    for name in [
        "pub struct ThreadInitialRegisters {",
        "pub struct ThreadUpcallSnapshot {",
    ] {
        let start = abi.find(name).unwrap();
        let end = start + abi[start..].find("\n}\n").unwrap() + 3;
        program.push_str("#[repr(C)] #[derive(Clone, Copy, Debug, PartialEq, Eq)]\n");
        program.push_str(&abi[start..end]);
    }
    program.push_str(r#"
}
const INVALID_ARGUMENT:u64=mnu_abi::status::Error::InvalidArgument.into_raw();
const INVALID_ADDRESS:u64=mnu_abi::status::Error::InvalidAddress.into_raw();
const NOT_READY:u64=mnu_abi::status::Error::NotReady.into_raw();const SUCCESS:u64=0;
#[derive(Debug)] enum ThreadUpcallError { Active, InvalidContext }
thread_local! {static MODE:std::cell::Cell<u8>=const {std::cell::Cell::new(0)};
static COMMITS:std::cell::Cell<usize>=const {std::cell::Cell::new(0)};}
fn copy_from_user_native(pointer:u64,bytes:&mut [u8])->Result<(),mnu_abi::status::Error> {
    if pointer==1 {return Err(mnu_abi::status::Error::InvalidAddress)}
    unsafe {bytes.copy_from_slice(core::slice::from_raw_parts(pointer as *const u8,bytes.len()));}
    Ok(())
}
mod task {
    pub fn current_thread_id()->Option<u64>{if crate::MODE.with(|v|v.get())==1 {None}else{Some(7)}}
    pub struct Thread;
    impl Thread {
        pub fn request_context_restore(&mut self,context:crate::UserUpcallContext,fx:[u8;512])->Result<(),crate::ThreadUpcallError> {
            assert_eq!(context.user_rip,0x4000);assert_eq!(context.user_rsp,0x8000);
            assert_eq!(context.rcx,0x1234);assert_eq!(fx[160],0x5b);
            match crate::MODE.with(|v|v.get()) {
                2=>Err(crate::ThreadUpcallError::Active),3=>Err(crate::ThreadUpcallError::InvalidContext),
                _=>{crate::COMMITS.with(|v|v.set(v.get()+1));Ok(())}
            }
        }
    }
    pub fn with_thread_mut<T>(id:u64,body:impl FnOnce(&mut Thread)->T)->Option<T>{
        assert_eq!(id,7);Some(body(&mut Thread))
    }
}
"#);
    program.push_str("mod actual { use super::*;\n");
    for name in ["restore_context", "return_context", "valid_user_return"] {
        let start = source.find(&format!("fn {name}(")).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str("pub ");
        program.push_str(&source[start..end]);
    }
    program.push_str("}\nuse actual::restore_context;\n");
    program.push_str(
        r#"
fn main(){
    let mut good=unsafe{core::mem::zeroed::<mnu_abi::ThreadUpcallSnapshot>()};
    good.instruction=0x4000;good.stack_pointer=0x8000;good.rflags=0x202;
    good.registers.rcx=0x1234;good.fx_state[160]=0x5b;
    let size=core::mem::size_of_val(&good) as u64;
    assert_eq!(restore_context(0,size),INVALID_ADDRESS);assert_eq!(restore_context(1,size),INVALID_ADDRESS);
    assert_eq!(restore_context(&good as *const _ as u64,size-1),INVALID_ARGUMENT);
    for (field,value) in [(0,0),(0,0x800000000000),(0,0xffff800000000000),
        (1,0),(1,15),(1,0xffff800000000000),(2,0),(2,0x3202),(2,0x202|(1<<63))] {
        let mut bad=good;
        match field {0=>bad.instruction=value,1=>bad.stack_pointer=value,_=>bad.rflags=value}
        assert_eq!(restore_context(&bad as *const _ as u64,size),INVALID_ARGUMENT);
        assert_eq!(COMMITS.with(|v|v.get()),0);
    }
    for (mode,error) in [(1,NOT_READY),(2,NOT_READY),(3,INVALID_ARGUMENT)] {
        MODE.with(|v|v.set(mode));assert_eq!(restore_context(&good as *const _ as u64,size),error);
        assert_eq!(COMMITS.with(|v|v.get()),0);
    }
    MODE.with(|v|v.set(0));assert_eq!(restore_context(&good as *const _ as u64,size),0);
    assert_eq!(COMMITS.with(|v|v.get()),1);
}
"#,
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-context-restore-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-", "-o"])
        .arg(&binary)
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
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_probe_and_dispatch_use_the_current_primitive() {
    let probe = include_str!("native_context_restore.c");
    let number = mnu_abi::SyscallNumber::ThreadContextRestore as u64;
    assert!(probe.contains(&format!("RESTORE = {number}")));
    assert!(probe.contains(&format!("mov ${number},%eax")));
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    assert!(dispatch.contains(
        "SyscallNumber::ThreadContextRestore as u64 => upcall::restore_context(arg0, arg1)"
    ));
}
