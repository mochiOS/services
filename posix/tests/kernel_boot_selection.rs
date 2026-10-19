#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn kernel_launches_only_the_boot_selected_bytes_and_rejects_legacy_or_invalid_modules() {
    let mut program = String::from("#![allow(dead_code)]\nmod mnu_abi {pub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\npub mod boot_module {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/boot_module.rs"));
    program.push_str("}\n}\n");
    program.push_str(
        r#"
use std::sync::atomic::{AtomicUsize, Ordering};
static STARTS:AtomicUsize=AtomicUsize::new(0);
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct CapabilitySet;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct KernelAuthoritySet;
mod task {#[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum PrivilegeLevel {Service}}
mod init {pub mod fs {
pub static BYTES:std::sync::Mutex<&'static [u8]>=std::sync::Mutex::new(&[]);
pub fn boot_module_bytes()->&'static [u8]{*BYTES.lock().unwrap()}
}}
mod performance {
pub enum CounterMetric{ExecutableBytesRead}
pub fn increment(_:CounterMetric,bytes:u64){assert_eq!(bytes,8);}
}
mod util {pub mod log {pub fn release_boot_marker(_:std::fmt::Arguments){}}}
struct ExecMeasurement;
impl ExecMeasurement {
fn start()->Self{STARTS.fetch_add(1,Ordering::Relaxed);Self}
fn finish(self,result:u64)->u64{result}
}
enum ImageLaunch{Bootstrap}
fn exec_with_data(data:&[u8],name:&str,identity:&str,caps:Option<CapabilitySet>,
authorities:Option<KernelAuthoritySet>,privilege:Option<task::PrivilegeLevel>,
application:Option<()>,handles:&[()],values:&[()],launch:ImageLaunch,_:&mut ExecMeasurement)->u64 {
assert_eq!(data,b"selected");assert!(name.is_empty()&&identity.is_empty());
assert_eq!(caps,Some(CapabilitySet));assert_eq!(authorities,Some(KernelAuthoritySet));
assert_eq!(privilege,Some(task::PrivilegeLevel::Service));assert_eq!(application,None);
assert!(handles.is_empty()&&values.is_empty());assert!(matches!(launch,ImageLaunch::Bootstrap));37
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/exec.rs"),
        "pub(crate) fn launch_bootstrap_image(",
        "pub(crate) fn map_initial_tls(",
    ));
    program.push_str(r#"
fn launch(bytes:Vec<u8>)->u64{
*init::fs::BYTES.lock().unwrap()=Box::leak(bytes.into_boxed_slice());
launch_bootstrap_image(CapabilitySet,KernelAuthoritySet,task::PrivilegeLevel::Service)
}
fn main(){
use mnu_abi::status::Error;
for bytes in [vec![],vec![0;8192],b"/init\0".to_vec()] {
assert_eq!(launch(bytes),Error::InvalidArgument.into_raw());
assert_eq!(STARTS.load(Ordering::Relaxed),0);
}
let mut bytes=vec![0;136];
bytes[..8].copy_from_slice(&mnu_abi::boot_module::MAGIC);
bytes[8..12].copy_from_slice(&1u32.to_le_bytes());bytes[12..16].copy_from_slice(&64u32.to_le_bytes());
bytes[16..24].copy_from_slice(&128u64.to_le_bytes());bytes[24..32].copy_from_slice(&128u64.to_le_bytes());
bytes[32..40].copy_from_slice(&8u64.to_le_bytes());
// A pathname in the opaque resources does not select executable bytes.
bytes[64..70].copy_from_slice(b"/init\0");bytes[128..].copy_from_slice(b"selected");
let mut invalid=bytes.clone();invalid[32..40].copy_from_slice(&(64*1024*1024+1u64).to_le_bytes());
assert_eq!(launch(invalid),Error::LimitExceeded.into_raw());
let mut invalid=bytes.clone();invalid[24..32].copy_from_slice(&64u64.to_le_bytes());
assert_eq!(launch(invalid),Error::InvalidArgument.into_raw());
assert_eq!(STARTS.load(Ordering::Relaxed),0);
assert_eq!(launch(bytes),37);assert_eq!(STARTS.load(Ordering::Relaxed),1);
}
"#);
    probe::run(&program);
}

#[test]
fn initial_process_policy_does_not_choose_a_userspace_name_or_path() {
    let policy = include_str!("../../../core/src/policy/mod.rs");
    let kernel = include_str!("../../../core/src/kernel.rs");
    for source in [policy, kernel] {
        for obsolete in ["BootLaunch", "init_launch()", "\"/init\"", "\"init\""] {
            assert!(
                !source.contains(obsolete),
                "kernel selection policy: {obsolete}"
            );
        }
    }
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let launch = probe::between(
        source,
        "pub(crate) fn launch_bootstrap_image(",
        "pub(crate) fn map_initial_tls(",
    );
    assert!(launch.contains("mnu_abi::boot_module::decode"));
    assert!(!launch.contains("read_initfs"));
    assert!(!launch.contains("rootfs"));
}
