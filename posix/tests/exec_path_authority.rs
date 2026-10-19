use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn bootstrap_loads_selected_bytes_and_preserves_grants_measurement_and_loader_errors() {
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
mod init { pub mod fs {
    static MODULE:std::sync::OnceLock<Vec<u8>>=std::sync::OnceLock::new();
    pub fn boot_module_bytes()->&'static [u8] {
        if !crate::PRESENT.load(crate::Ordering::Relaxed) {return &[]}
        MODULE.get_or_init(||{
            let mut bytes=vec![0;67];
            bytes[..8].copy_from_slice(&crate::mnu_abi::boot_module::MAGIC);
            bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
            bytes[12..16].copy_from_slice(&64u32.to_le_bytes());
            bytes[16..24].copy_from_slice(&64u64.to_le_bytes());
            bytes[24..32].copy_from_slice(&64u64.to_le_bytes());
            bytes[32..40].copy_from_slice(&3u64.to_le_bytes());
            bytes[64..].copy_from_slice(&[1,2,3]);bytes
        }).as_slice()
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
fn exec_with_data(data:&[u8],name:&str,path:&str,
    caps:Option<u64>,authorities:Option<u64>,privilege:Option<task::PrivilegeLevel>,
    identity:Option<()>,handles:&[()],values:&[()],launch:ImageLaunch,_:&mut ExecMeasurement)->u64 {
    assert_eq!(data,[1,2,3]); assert!(name.is_empty()&&path.is_empty());
    assert!(handles.is_empty()&&values.is_empty());
    assert_eq!((caps,authorities,privilege),(Some(7),Some(9),Some(task::PrivilegeLevel::Service)));
    assert!(identity.is_none()&&matches!(launch,ImageLaunch::Bootstrap));
    CALLS.fetch_add(1,Ordering::Relaxed);
    RESULT.load(Ordering::Relaxed)
}
"#,
    );
    program.push_str("mod mnu_abi {pub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\npub mod boot_module {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/boot_module.rs"));
    program.push_str("}}\n");
    program.push_str(&source[begin..end]);
    program.push_str(r#"
fn main(){
    assert_eq!(launch_bootstrap_image(7,9,task::PrivilegeLevel::Service),mnu_abi::status::Error::InvalidArgument.into_raw());
    assert_eq!(CALLS.load(Ordering::Relaxed),0);
    assert_eq!(BYTES.load(Ordering::Relaxed),0);
    PRESENT.store(true,Ordering::Relaxed);
    for _ in 0..4 {
        assert_eq!(launch_bootstrap_image(7,9,task::PrivilegeLevel::Service),77);
    }
    assert_eq!(CALLS.load(Ordering::Relaxed),4);
    assert_eq!(BYTES.load(Ordering::Relaxed),12);
    let failure=mnu_abi::status::Error::ResourceUnavailable.into_raw();
    RESULT.store(failure,Ordering::Relaxed);
    assert_eq!(launch_bootstrap_image(7,9,task::PrivilegeLevel::Service),failure);
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
