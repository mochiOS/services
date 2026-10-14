use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn bootstrap_loads_only_initfs_and_preserves_explicit_label_and_loader_errors() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let begin = source
        .find("pub(crate) fn launch_bootstrap_image(")
        .unwrap();
    let end = begin + source[begin..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
type CapabilitySet = u64;
type KernelAuthoritySet = u64;
static PRESENT: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicU64 = AtomicU64::new(77);
mod task { #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum PrivilegeLevel { Service } }
mod syscall { pub mod types { pub const ENOENT:u64=(-2i64) as u64; } }
mod init { pub mod fs {
    pub fn read_initfs(path:&str)->Option<Vec<u8>> {
        assert_eq!(path,"/chosen/image");
        crate::PRESENT.load(crate::Ordering::Relaxed).then(||vec![1,2,3])
    }
}}
mod performance {
    pub enum CounterMetric { ExecutableBytesRead }
    pub fn increment(_:CounterMetric,bytes:u64) { crate::BYTES.fetch_add(bytes,crate::Ordering::Relaxed); }
}
mod util { pub mod log { pub fn release_boot_marker(_:std::fmt::Arguments<'_>){} } }
struct ExecMeasurement;
enum ImageLaunch { Bootstrap }
impl ExecMeasurement {
    fn start()->Self { Self }
    fn finish(self,result:u64)->u64 { result }
}
fn exec_with_data(data:&[u8],name:&str,path:&str,args:&[&str],env:&[&str],
    caps:Option<u64>,authorities:Option<u64>,privilege:Option<task::PrivilegeLevel>,
    identity:Option<()>,handles:&[()],values:&[()],launch:ImageLaunch,_:&mut ExecMeasurement)->u64 {
    assert_eq!(data,[1,2,3]); assert_eq!(path,"/chosen/image");
    assert!(["Compiler worker","/opaque/label","任意の名前",""].contains(&name));
    assert!(args.is_empty()&&env.is_empty()&&handles.is_empty()&&values.is_empty());
    assert_eq!((caps,authorities,privilege),(Some(7),Some(9),Some(task::PrivilegeLevel::Service)));
    assert!(identity.is_none()&&matches!(launch,ImageLaunch::Bootstrap));
    CALLS.fetch_add(1,Ordering::Relaxed);
    RESULT.load(Ordering::Relaxed)
}
"#,
    );
    program.push_str(&source[begin..end]);
    program.push_str(r#"
fn main(){
    assert_eq!(launch_bootstrap_image("/chosen/image","Compiler worker",7,9,task::PrivilegeLevel::Service),syscall::types::ENOENT);
    assert_eq!(CALLS.load(Ordering::Relaxed),0);
    assert_eq!(BYTES.load(Ordering::Relaxed),0);
    PRESENT.store(true,Ordering::Relaxed);
    for label in ["Compiler worker","/opaque/label","任意の名前",""] {
        assert_eq!(launch_bootstrap_image("/chosen/image",label,7,9,task::PrivilegeLevel::Service),77);
    }
    assert_eq!(CALLS.load(Ordering::Relaxed),4);
    assert_eq!(BYTES.load(Ordering::Relaxed),12);
    RESULT.store((-12i64) as u64,Ordering::Relaxed);
    assert_eq!(launch_bootstrap_image("/chosen/image","Compiler worker",7,9,task::PrivilegeLevel::Service),(-12i64) as u64);
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-exec-authority-{}-{}",
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
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(executable).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
