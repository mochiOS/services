//! Opaque boot ranges replace the retired kernel pathname/ext2 backend.
extern crate self as spin;
pub struct Once<T>(std::sync::OnceLock<T>);
impl<T> Once<T> {
    pub const fn new() -> Self {
        Self(std::sync::OnceLock::new())
    }
    pub fn call_once(&self, initialize: impl FnOnce() -> T) -> &T {
        self.0.get_or_init(initialize)
    }
    pub fn get(&self) -> Option<&T> {
        self.0.get()
    }
}
#[path = "../../../core/src/init/boot_data.rs"]
mod actual;
use mnu_abi::{boot_module as module, status::Error};
use std::path::{Path, PathBuf};
use std::process::Command;

fn descriptor(platform: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; module::HEADER_LEN];
    bytes[..8].copy_from_slice(&module::MAGIC);
    bytes[8..12].copy_from_slice(&module::VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&(module::HEADER_LEN as u32).to_le_bytes());
    for (at, value) in [(16, 64), (24, 67 + platform.len() as u64), (32, 8), (40, 3)] {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[56..60].copy_from_slice(&(platform.len() as u32).to_le_bytes());
    bytes.extend_from_slice(b"cfg");
    bytes.extend_from_slice(platform);
    bytes.extend_from_slice(b"selected");
    bytes
}

#[test]
fn selected_platform_data_is_borrowed_once_without_filesystem_interpretation() {
    assert!(actual::boot_module_bytes().is_empty());
    assert_eq!(actual::platform_data(), None);
    for (address, length) in [(0, 0), (0, 1), (1, 0), (u64::MAX, 1), (1, usize::MAX)] {
        assert_eq!(
            unsafe { actual::install(address, length) },
            Err(Error::InvalidArgument)
        );
    }
    let data: &'static [u8] = Box::leak(descriptor(&[0x5a; 32]).into_boxed_slice());
    assert_eq!(
        unsafe { actual::install(data.as_ptr() as u64, data.len()) },
        Ok(())
    );
    assert!(std::ptr::eq(actual::boot_module_bytes(), data));
    let selected = actual::platform_data().unwrap();
    assert_eq!(selected, [0x5a; 32]);
    assert_eq!(selected.as_ptr(), data[67..].as_ptr());
    assert_eq!(
        unsafe { actual::install(data.as_ptr() as u64, data.len()) },
        Ok(())
    );
    let other: &'static [u8] = Box::leak(descriptor(&[0x73; 32]).into_boxed_slice());
    assert_eq!(
        unsafe { actual::install(other.as_ptr() as u64, other.len()) },
        Err(Error::AlreadyExists)
    );
    assert_eq!(actual::platform_data().unwrap(), [0x5a; 32]);
    assert_eq!(
        mnu_abi::performance::BootMilestone::BootModuleAvailable as usize,
        6
    );
    assert_eq!(mnu_abi::performance::BootMilestone::COUNT, 12);
}

#[test]
fn platform_range_is_bounded_adjacent_and_reserved_bits_cannot_select_data() {
    for size in [0, 1, 32, module::MAX_PLATFORM_DATA_BYTES as usize] {
        let bytes = descriptor(&vec![0x39; size]);
        let decoded = module::decode(&bytes).unwrap();
        assert_eq!(decoded.platform_data, vec![0x39; size]);
        assert_eq!(decoded.kernel_configuration, b"cfg");
        assert_eq!(decoded.initial_image, b"selected");
    }
    let valid = descriptor(&[0x5a; 32]);
    for offset in [0u64, 66, 98, 100, u64::MAX] {
        let mut bytes = valid.clone();
        bytes[24..32].copy_from_slice(&offset.to_le_bytes());
        assert_eq!(module::decode(&bytes), Err(module::Error::InvalidRange));
    }
    let mut bytes = valid.clone();
    bytes[56..60].copy_from_slice(&(module::MAX_PLATFORM_DATA_BYTES + 1).to_le_bytes());
    assert_eq!(
        module::decode(&bytes),
        Err(module::Error::PlatformDataTooLarge)
    );
    for index in 60..64 {
        let mut bytes = valid.clone();
        bytes[index] = 1;
        assert_eq!(module::decode(&bytes), Err(module::Error::InvalidHeader));
    }
}

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mochios-platform-data-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/mmake")
        .join(name)
}

#[test]
fn real_image_pipeline_selects_install_metadata_and_failed_repacking_is_atomic() {
    let temporary = Temporary::new();
    let stage = temporary.0.join("stage");
    std::fs::create_dir(&stage).unwrap();
    std::fs::create_dir(stage.join("install")).unwrap();
    let mut elf = vec![0; 72];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    std::fs::write(stage.join("init"), &elf).unwrap();
    let config = temporary.0.join("config");
    std::fs::write(&config, "IMAGE_INITFS_SIZE_MB=4\n").unwrap();
    let image = temporary.0.join("module.img");
    for byte in [0x5a, 0x73] {
        std::fs::write(stage.join("install/rootfs.sha256"), [byte; 32]).unwrap();
        let result = Command::new("bash")
            .arg(script("make-ext2-image.sh"))
            .arg(&stage)
            .arg(&image)
            .arg("initfs")
            .arg(&config)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let bytes = std::fs::read(&image).unwrap();
        let decoded = module::decode(&bytes).unwrap();
        assert_eq!(decoded.platform_data, [byte; 32]);
        assert_eq!(decoded.initial_image, elf);
    }
    let complete = std::fs::read(&image).unwrap();
    let too_large = temporary.0.join("caller-selected metadata");
    std::fs::File::create(&too_large)
        .unwrap()
        .set_len(u64::from(module::MAX_PLATFORM_DATA_BYTES) + 1)
        .unwrap();
    let result = Command::new("perl")
        .arg(script("pack-boot-module.pl"))
        .arg("pack")
        .arg(&image)
        .arg((4 * 1024 * 1024).to_string())
        .arg(stage.join("init"))
        .arg("-")
        .arg(&stage)
        .arg(&too_large)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("at most 64 KiB"));
    assert_eq!(std::fs::read(&image).unwrap(), complete);
}

#[test]
fn kernel_has_no_ext2_path_lookup_or_false_filesystem_boot_milestone() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(!root.join("core/src/init/fs.rs").exists());
    let init = std::fs::read_to_string(root.join("core/src/init/mod.rs")).unwrap();
    assert!(!init.contains("fs::init()"));
    assert!(!init.contains("FilesystemMounted"));
    let backend = include_str!("../../../boot/src/mdriver.rs");
    assert!(!backend.contains("kernel_read_initfs"));
    assert!(!backend.contains("/install/rootfs.sha256"));
    assert!(backend.contains("mnu::init::boot_data::platform_data()"));
}

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_platform_backend_uses_only_selected_metadata_and_keeps_read_only_grant_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
#[path={:?}]mod abi;pub use abi::*;
#[path={:?}]mod protocol;pub use protocol::*;
use abi::hypervisor::{{HypercallNumber,GRANT_REF_INVALID}};
use protocol::{{INSTALL_METADATA_PAGE as MDRIVER_INSTALL_METADATA_PAGE,DOMAIN_ID as MDRIVER_DOMAIN_ID}};
use std::{{cell::Cell,ptr::copy_nonoverlapping}};
thread_local!{{
 static DATA:Cell<Option<&'static[u8]>>=const{{Cell::new(None)}};
 static RESULT:Cell<u64>=const{{Cell::new(73)}};
 static CALLS:Cell<usize>=const{{Cell::new(0)}};
 static ADDRESS:Cell<u64>=const{{Cell::new(0)}};
}}
mod mnu{{pub mod init{{pub mod boot_data{{pub fn platform_data()->Option<&'static[u8]>{{crate::DATA.get()}}}}}}}}
mod hypervisor_guest{{
 pub fn invoke(number:crate::HypercallNumber,address:u64,domain:u64,flags:u64)->u64{{
  assert_eq!(number as u64,crate::HypercallNumber::GrantCreate as u64);
  assert_eq!(address,crate::ADDRESS.get());assert_eq!(domain,u64::from(crate::MDRIVER_DOMAIN_ID));assert_eq!(flags,0);
  let bytes=unsafe{{std::slice::from_raw_parts(address as *const u8,4096)}};
  assert_eq!(&bytes[..32],&[0x5a;32]);assert!(bytes[32..].iter().all(|byte|*byte==0));
  crate::CALLS.set(crate::CALLS.get()+1);crate::RESULT.get()
 }}
}}
#[derive(Debug,PartialEq)]enum Error{{Protocol,Hypercall}}
struct Client{{ring_address:u64,install_metadata_reference:Option<u32>}}
"#,
        root.join("core/crates/abi/src/lib.rs"),
        root.join("boot/crates/mdriver-protocol/src/lib.rs")
    );
    program.push_str(probe::between(
        include_str!("../../../boot/src/mdriver.rs"),
        "fn install_metadata_reference(",
        "pub fn block_candidates(",
    ));
    program.push_str(r#"
fn main(){
 let mut page=vec![0xa5u8;((MDRIVER_INSTALL_METADATA_PAGE+1)*4096)as usize];
 let mut client=Client{ring_address:page.as_mut_ptr()as u64,install_metadata_reference:None};
 ADDRESS.set(client.ring_address+MDRIVER_INSTALL_METADATA_PAGE*4096);
 for data in [None,Some(&[0x5a;31][..]),Some(&[0x5a;33][..])]{
  DATA.set(data);assert_eq!(install_metadata_reference(&mut client),Err(Error::Protocol));
  assert_eq!(CALLS.get(),0);assert!(page.iter().all(|byte|*byte==0xa5));
 }
 DATA.set(Some(&[0x5a;32]));
 for failure in [GRANT_REF_INVALID,u64::MAX,u64::from(u32::MAX)+1]{
  RESULT.set(failure);assert_eq!(install_metadata_reference(&mut client),Err(Error::Hypercall));assert!(client.install_metadata_reference.is_none());
 }
 RESULT.set(73);assert_eq!(install_metadata_reference(&mut client),Ok(73));assert_eq!(CALLS.get(),4);
 DATA.set(None);RESULT.set(0);assert_eq!(install_metadata_reference(&mut client),Ok(73));assert_eq!(CALLS.get(),4);
 assert!(page[..(MDRIVER_INSTALL_METADATA_PAGE*4096)as usize].iter().all(|byte|*byte==0xa5));
}
"#);
    probe::run(&program);
}
