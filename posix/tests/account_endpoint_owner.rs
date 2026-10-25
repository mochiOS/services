use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn transferred_account_endpoint_must_belong_to_the_retained_user_process() {
    let source = include_str!("../../service-manager/src/readiness.rs");
    let start = source
        .find("    pub(crate) fn take_user_endpoint(")
        .unwrap();
    let end = start + source[start..].find("\n    fn token_for(").unwrap();
    let mut program = String::from(
        r#"
use std::cell::RefCell;
thread_local!{static CLOSED:RefCell<Vec<u32>>=const{RefCell::new(Vec::new())};}
mod platform{pub mod handle{pub type Handle=u32;pub fn close(handle:u32)->Result<(),()>{super::super::CLOSED.with_borrow_mut(|v|v.push(handle));Ok(())}}}
#[derive(Debug,PartialEq)]enum ReadyError{InvalidMessage,ProcessStatus(u32)}
struct ProcessWatchTarget(u32);impl From<u32> for ProcessWatchTarget{fn from(v:u32)->Self{Self(v)}}
struct ProcessWatch(u32);impl ProcessWatch{
fn open(target:impl Into<ProcessWatchTarget>)->Result<Self,u32>{let h=target.into().0;if h==0{Err(1)}else{Ok(Self(h))}}
fn process_id(&self)->Result<u64,u32>{if self.0==2{Err(2)}else{Ok(100)}}}
struct ReadyHandshake{user_endpoint:Option<u32>,user_endpoint_process:Option<u64>}
impl ReadyHandshake{
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
}
fn main(){
 for (owner,target,expected) in [(Some(100),1,Ok(Some(41))),
   (Some(999),1,Err(ReadyError::InvalidMessage)),(None,1,Err(ReadyError::InvalidMessage)),
   (Some(100),0,Err(ReadyError::ProcessStatus(1))),(Some(100),2,Err(ReadyError::ProcessStatus(2)))] {
   CLOSED.with_borrow_mut(Vec::clear);
   let valid=expected.is_ok();
   let mut ready=ReadyHandshake{user_endpoint:Some(41),user_endpoint_process:owner};
   assert_eq!(ready.take_user_endpoint(target),expected);
   assert_eq!(ready.take_user_endpoint(target),Ok(None));
   assert!(ready.user_endpoint_process.is_none());
   CLOSED.with_borrow(|v|assert_eq!(v.as_slice(),if valid{&[][..]}else{&[41][..]}));
 }
}
"#);
    let directory =
        std::env::temp_dir().join(format!("mochios-account-owner-{}", std::process::id()));
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
