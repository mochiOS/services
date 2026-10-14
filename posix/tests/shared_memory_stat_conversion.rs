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
type PosixFileStatus=FileStatus;type CLong=i64;
#[derive(Debug,PartialEq)]struct NewlibTimespec{tv_sec:i64,tv_nsec:i64}
struct Handle{lower_handle:u64}struct FdEntry{handle:Handle}
thread_local!{
static STATUS:std::cell::Cell<FileStatus>=std::cell::Cell::new(FileStatus::default());
static MODE:std::cell::Cell<u32>=const{std::cell::Cell::new(0)};
}
mod wire{pub const CONTROL_STAT:u64=7;}
mod posix_protocol{pub const FILE_STATUS_LEN:usize=112;
pub fn decode_file_status(_: &[u8])->Result<super::FileStatus,()> {
if super::MODE.with(|v|v.get())==2{Err(())}else{Ok(super::STATUS.with(|v|v.get()))}}}
mod syscall{pub enum SyscallNumber{HandleControl}
pub fn raw_syscall6(_:SyscallNumber,handle:u64,code:u64,input:u64,input_len:u64,output:u64,output_len:u64)->Result<u64,i32>{
assert_eq!((code,input,input_len,output_len),(7,0,0,112));assert_ne!(output,0);
if handle==0{return Err(super::EBADF)}Ok(if super::MODE.with(|v|v.get())==1{111}else{112})}}
fn syscall_errno(v:Result<u64,i32>)->Result<u64,i32>{v}
"#,
    );
    let protocol = include_str!("../../../user/crates/posix-protocol/src/lib.rs");
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for (source, marker, derive) in [
        (
            protocol,
            "pub struct FileStatus {",
            "#[derive(Clone,Copy,Debug,Default)]\n",
        ),
        (
            runtime,
            "struct NewlibStat {",
            "#[derive(Debug,PartialEq)]\n",
        ),
        (runtime, "fn translate_posix_stat(", ""),
    ] {
        let begin = source.find(marker).unwrap();
        let finish = begin + source[begin..].find("\n}\n").unwrap() + 3;
        program.push_str(derive);
        program.push_str(&source[begin..finish]);
    }
    program.push_str(&source[start..end].replace("pub(super) fn stat", "fn stat"));
    program.push_str(r#"
fn run()->Result<NewlibStat,i32>{stat(FdEntry{handle:Handle{lower_handle:1}})}
fn main(){
for field in 0..6{for value in [65535u64,65536]{
let mut status=FileStatus::default();match field{0=>status.device=value,1=>status.inode=value,
2=>status.link_count=value as u32,3=>status.uid=value as u32,4=>status.gid=value as u32,_=>status.special_device=value}
STATUS.with(|v|v.set(status));
if value==65535{let converted=run().unwrap();
assert_eq!([converted.st_dev,converted.st_ino,converted.st_nlink,converted.st_uid,converted.st_gid,converted.st_rdev][field],65535)}
else{assert_eq!(run(),Err(EOVERFLOW))}}
STATUS.with(|v|v.set(FileStatus::default()));assert!(run().is_ok());}
STATUS.with(|v|v.set(FileStatus{device:1,inode:2,link_count:3,uid:4,gid:5,special_device:6,
mode:0o100644,size:i64::MAX,block_size:4096,blocks:7,access_time_seconds:-11,access_time_nanoseconds:22,
modification_time_seconds:33,modification_time_nanoseconds:44,change_time_seconds:55,change_time_nanoseconds:66}));
let converted=run().unwrap();assert_eq!((converted.st_size,converted.st_blksize,converted.st_blocks),(i64::MAX,4096,7));
assert_eq!((converted.st_atim.tv_sec,converted.st_atim.tv_nsec,converted.st_mtim.tv_sec,converted.st_mtim.tv_nsec,
converted.st_ctim.tv_sec,converted.st_ctim.tv_nsec),(-11,22,33,44,55,66));assert_eq!(converted.st_mode,0o100644);
for mode in [1,2]{MODE.with(|v|v.set(mode));assert_eq!(run(),Err(EIO));}
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
