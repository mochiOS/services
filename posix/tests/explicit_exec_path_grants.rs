use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn kernel_exec_path_authority_requires_explicit_grants_not_identity_storage_policy() {
    let source = include_str!("../../../core/src/syscall/fs.rs");
    let config = include_str!("../../../core/src/config.rs");
    assert!(!config.contains("identity_storage_root"));
    for retired in [
        "identity_storage_path_allows",
        "path_is_in_identity_storage",
        "identity_storage_root",
        "security_identity()",
        "fn normalize_path(",
    ] {
        assert!(
            !source.contains(retired),
            "kernel retains identity storage policy: {retired}"
        );
    }
    let start = source
        .find("fn ensure_fs_capability_access_for_process(")
        .unwrap();
    let end = source[start..]
        .find("pub(crate) fn file_handle_options(")
        .unwrap()
        + start;
    let mut program = String::from(
        r#"
const EACCES:u64=13;
#[derive(Clone,Copy,PartialEq)]enum Capability{FsReadAll,FsWriteAll,FsReadTmp}
#[derive(Clone,Copy)]enum PathOwner{Any,System,Service(u64),Application(u64)}
const PATH_READ:u32=1;const PATH_LIST:u32=2;const PATH_EXEC:u32=4;
const PATH_WRITE:u32=8;const PATH_CREATE:u32=16;const PATH_DELETE:u32=32;
mod path {
pub struct Rights{pub bits:u32}pub struct Entry{pub owner:super::PathOwner,pub rights:Rights,pub read_capability:super::Capability,pub write_capability:super::Capability}
pub fn scoped_path_allows(pid:u64,path:&str,rights:u32)->bool{
path=="/explicit-scope/executable"&&pid==7&&rights & !super::PATH_EXEC==0}
pub fn lookup_path(path:&str)->Option<Entry>{
use super::{PathOwner as O,Capability as C};
let (owner,bits)=match path{"/owned"=>(O::Service(7),super::PATH_EXEC),"/app-owned"=>(O::Application(7),super::PATH_EXEC),
"/system"=>(O::System,super::PATH_EXEC),"/required"=>(O::Any,0),_=>return None};
Some(Entry{owner,rights:Rights{bits},read_capability:C::FsReadTmp,write_capability:C::FsWriteAll})}}
mod task{pub mod ids{pub struct ProcessId(pub u64);impl ProcessId{pub fn from_u64(v:u64)->Self{Self(v)}}}}
mod syscall{pub mod security{
pub fn process_has_any_capability(pid:crate::task::ids::ProcessId,caps:&[crate::Capability])->bool{
caps.iter().any(|c|match (pid.0,c){(8,crate::Capability::FsReadTmp)|(9,crate::Capability::FsReadAll)=>true,_=>false})}}}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main(){
for path in ["/identity/app.example/executable","/identity/app.example/../other/executable","/unknown"]{
assert_eq!(ensure_fs_capability_access_for_process(path,PATH_EXEC,7),Err(EACCES));
assert_eq!(ensure_fs_capability_access_for_process(path,PATH_EXEC,9),Ok(()));}
assert_eq!(ensure_fs_capability_access_for_process("/explicit-scope/executable",PATH_EXEC,7),Ok(()));
assert_eq!(ensure_fs_capability_access_for_process("/explicit-scope/executable",PATH_WRITE,7),Err(EACCES));
for path in ["/owned","/app-owned"]{
assert_eq!(ensure_fs_capability_access_for_process(path,PATH_EXEC,7),Ok(()));
assert_eq!(ensure_fs_capability_access_for_process(path,PATH_EXEC,9),Err(EACCES));}
assert_eq!(ensure_fs_capability_access_for_process("/system",PATH_EXEC,9),Err(EACCES));
for pid in [8,9]{assert_eq!(ensure_fs_capability_access_for_process("/required",PATH_EXEC,pid),Ok(()));}
assert_eq!(ensure_fs_capability_access_for_process("/required",PATH_EXEC,7),Err(EACCES));
assert_eq!(ensure_fs_capability_access_for_process("/required",PATH_WRITE,9),Err(EACCES));}
"#);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mochios-explicit-exec-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=explicit_exec", "-", "-o"])
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
