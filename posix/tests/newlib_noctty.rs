#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn noctty_is_accepted_without_forwarding_a_kernel_or_filesystem_flag() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
extern crate self as mnu_abi;
#[path={:?}] mod abi;pub use abi::*;pub use abi::status;
#[path={:?}] mod posix_protocol;pub use posix_protocol::*;
#[allow(non_camel_case_types)] type c_int=i32;
const EINVAL:i32=22;const O_CLOEXEC:i32=0x40000;
"#,
        root.join("core/crates/abi/src/lib.rs"),
        root.join("user/crates/posix-protocol/src/lib.rs")
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/newlib-runtime/src/lib.rs"),
        "fn posix_open_options(",
        "fn posix_mutable_status_flags(",
    ));
    program.push_str(
        r#"
fn main(){
 for access in [0,1,2]{
  for flags in [0,8,0x200,0x400,0x800,0x4000,0x40000,0x100000,0x200000,0x244e08]{
   assert_eq!(posix_open_options(access|flags|0x8000),posix_open_options(access|flags));
   assert!(posix_open_options(access|flags|0x8000).is_ok());
  }
 }
 assert_eq!(posix_open_options(3|0x8000),Err(EINVAL));
 assert_eq!(posix_open_options(0x10000000|0x8000),Err(EINVAL));
}
"#,
    );
    probe::run(&program);
}
