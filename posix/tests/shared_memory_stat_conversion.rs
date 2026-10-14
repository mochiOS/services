use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_shm_stat_rejects_truncated_malformed_and_unrepresentable_identity() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/shared_memory.rs");
    let start = source.find("pub(super) fn stat(").unwrap();
    let end = source[start..]
        .find("pub(super) fn get_status_flags(")
        .unwrap()
        + start;
    let mut program = String::from(
        r#"
use std::ffi::c_int;
const EIO:i32=5;const EBADF:i32=9;const EOVERFLOW:i32=75;
#[derive(Clone,Copy,Debug,Default)]struct FileStatus{device:u64,inode:u64,link_count:u32,uid:u32,gid:u32,special_device:u64}
#[derive(Debug,PartialEq)]struct NewlibStat;
struct Handle{lower_handle:u64}struct FdEntry{handle:Handle}
thread_local!{
static STATUS:std::cell::Cell<FileStatus>=const{std::cell::Cell::new(FileStatus{device:0,inode:0,link_count:0,uid:0,gid:0,special_device:0})};
static MODE:std::cell::Cell<u32>=const{std::cell::Cell::new(0)};
static TRANSLATED:std::cell::Cell<u32>=const{std::cell::Cell::new(0)};}
mod wire{pub const CONTROL_STAT:u64=7;}
mod posix_protocol{pub const FILE_STATUS_LEN:usize=112;
pub fn decode_file_status(_: &[u8])->Result<super::FileStatus,()> {
if super::MODE.with(|v|v.get())==2{Err(())}else{Ok(super::STATUS.with(|v|v.get()))}}}
mod syscall{pub enum SyscallNumber{HandleControl}
pub fn raw_syscall6(_:SyscallNumber,handle:u64,code:u64,input:u64,input_len:u64,output:u64,output_len:u64)->Result<u64,i32>{
assert_eq!((code,input,input_len,output_len),(7,0,0,112));assert_ne!(output,0);
if handle==0{return Err(super::EBADF)}Ok(if super::MODE.with(|v|v.get())==1{111}else{112})}}
fn syscall_errno(v:Result<u64,i32>)->Result<u64,i32>{v}
fn translate_posix_stat(_: &FileStatus)->NewlibStat{TRANSLATED.with(|v|v.set(v.get()+1));NewlibStat}
"#,
    );
    program.push_str(&source[start..end].replace("pub(super) fn stat", "fn stat"));
    program.push_str(r#"
fn run()->Result<NewlibStat,i32>{stat(FdEntry{handle:Handle{lower_handle:1}})}
fn main(){
for field in 0..6{for value in [65535u64,65536]{
let mut status=FileStatus::default();match field{0=>status.device=value,1=>status.inode=value,
2=>status.link_count=value as u32,3=>status.uid=value as u32,4=>status.gid=value as u32,_=>status.special_device=value}
STATUS.with(|v|v.set(status));TRANSLATED.with(|v|v.set(0));
if value==65535{assert_eq!(run(),Ok(NewlibStat));assert_eq!(TRANSLATED.with(|v|v.get()),1)}
else{assert_eq!(run(),Err(EOVERFLOW));assert_eq!(TRANSLATED.with(|v|v.get()),0)}}}
for mode in [1,2]{MODE.with(|v|v.set(mode));TRANSLATED.with(|v|v.set(0));
assert_eq!(run(),Err(EIO));assert_eq!(TRANSLATED.with(|v|v.get()),0)}
assert_eq!(stat(FdEntry{handle:Handle{lower_handle:0}}),Err(EBADF));}
"#);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("mochios-shm-stat-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=shm_stat", "-", "-o"])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compile
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let output = compile.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
