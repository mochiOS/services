//! Native range validation and the real distribution-side TOML selector.
use mnu_abi::{boot_extensions as index, boot_module};
use std::path::{Path, PathBuf};
use std::process::Command;

fn table(payloads: &[(&[u8], bool)]) -> Vec<u8> {
    let mut bytes = vec![0; index::HEADER_LEN + index::ENTRY_LEN * payloads.len()];
    bytes[..8].copy_from_slice(&index::MAGIC);
    bytes[8..12].copy_from_slice(&index::VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&(index::ENTRY_LEN as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&(payloads.len() as u64).to_le_bytes());
    for (number, (payload, required)) in payloads.iter().enumerate() {
        let at = index::HEADER_LEN + index::ENTRY_LEN * number;
        let offset = bytes.len() as u64;
        bytes[at..at + 8].copy_from_slice(&offset.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes[at + 16..at + 20].copy_from_slice(&index::ADAPTER_BLOCK.to_le_bytes());
        bytes[at + 20..at + 24].copy_from_slice(&u32::from(*required).to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    bytes
}

#[test]
fn index_ranges_are_complete_disjoint_bounded_and_validated_before_iteration() {
    assert_eq!(index::decode(&[]).unwrap().len(), 0);
    let valid = table(&[(b"one", true), (b"two", false)]);
    let decoded = index::decode(&valid).unwrap();
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded.get(0).unwrap().bytes, b"one");
    assert!(decoded.get(0).unwrap().required);
    assert!(!decoded.get(1).unwrap().required);
    assert_eq!(decoded.get(2), None);
    for end in 1..valid.len() {
        assert!(index::decode(&valid[..end]).is_err(), "truncation {end}");
    }
    for (at, value) in [
        (24, 0),
        (24, u64::MAX),
        (32, 0),
        (32, u64::MAX),
        (48, 72),
        (56, 99),
    ] {
        let mut invalid = valid.clone();
        invalid[at..at + 8].copy_from_slice(&value.to_le_bytes());
        assert!(index::decode(&invalid).is_err(), "invalid range at {at}");
    }
    for (at, value) in [(8, 2u32), (12, 23), (40, 0), (40, 2), (44, 2)] {
        let mut invalid = valid.clone();
        invalid[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert!(index::decode(&invalid).is_err());
    }
    let mut invalid = valid.clone();
    invalid[16..24].copy_from_slice(&(index::MAX_ENTRIES as u64 + 1).to_le_bytes());
    assert_eq!(
        index::decode(&invalid).err(),
        Some(index::Error::LimitExceeded)
    );
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        index::decode(&trailing).err(),
        Some(index::Error::InvalidRange)
    );
}

fn module(extensions: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; boot_module::HEADER_LEN];
    bytes[..8].copy_from_slice(&boot_module::MAGIC);
    bytes[8..12].copy_from_slice(&boot_module::VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&(boot_module::HEADER_LEN as u32).to_le_bytes());
    for (at, value) in [
        (16, 64),
        (24, 64 + 3 + extensions.len() as u64),
        (32, 5),
        (40, 3),
        (48, extensions.len() as u64),
    ] {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(b"cfg");
    bytes.extend_from_slice(extensions);
    bytes.extend_from_slice(b"image");
    bytes
}

#[test]
fn boot_module_v3_separates_config_modules_and_image_and_rejects_legacy_descriptors() {
    let selected = table(&[(b"module", true)]);
    let bytes = module(&selected);
    let decoded = boot_module::decode(&bytes).unwrap();
    assert_eq!(decoded.kernel_configuration, b"cfg");
    assert_eq!(decoded.native_modules, selected);
    assert_eq!(decoded.initial_image, b"image");
    for version in [1u32, 2, 4] {
        let mut bad = bytes.clone();
        bad[8..12].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            boot_module::decode(&bad),
            Err(boot_module::Error::UnsupportedVersion)
        );
    }
    for length in [0, u64::MAX, boot_module::MAX_NATIVE_MODULE_BYTES + 1] {
        let mut bad = bytes.clone();
        bad[48..56].copy_from_slice(&length.to_le_bytes());
        assert!(boot_module::decode(&bad).is_err());
    }
}

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mochios-boot-extensions-{}-{}",
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

fn package(name: &str) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(b"MCEX");
    bytes[4..6].copy_from_slice(&4u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&(name.len() as u16).to_le_bytes());
    bytes[12..16].copy_from_slice(&(32u32 + name.len() as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&72u64.to_le_bytes());
    bytes.extend_from_slice(name.as_bytes());
    let mut elf = vec![0; 72];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[64..].copy_from_slice(b"selected");
    bytes.extend_from_slice(&elf);
    bytes
}

#[test]
fn real_builder_resolves_manifests_and_packer_preserves_atomic_replacement() {
    let temporary = Temporary::new();
    let stage = temporary.0.join("arbitrary resources");
    std::fs::create_dir(&stage).unwrap();
    let bundle = stage.join("renamed.cext");
    std::fs::create_dir(&bundle).unwrap();
    let manifest = "[cext]\nid='custom.bundle'\nname='opaque # name'\nversion=1\nabi=4\nentry='code with spaces'\n[load]\nstage='boot'\nrequired=true\n[provides]\ninterfaces=['block.device']\n[requires]\ninterfaces=[]\n";
    std::fs::write(bundle.join("manifest.toml"), manifest).unwrap();
    let code = package("opaque # name");
    std::fs::write(bundle.join("code with spaces"), &code).unwrap();
    let select = || {
        Command::new("python3")
            .arg(script("pack-boot-extensions.py"))
            .arg(&stage)
            .output()
            .unwrap()
    };
    let selected = select();
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert_eq!(
        index::decode(&selected.stdout)
            .unwrap()
            .get(0)
            .unwrap()
            .bytes,
        code
    );
    let image = temporary.0.join("module.img");
    std::fs::File::create(&image)
        .unwrap()
        .set_len(4 * 1024 * 1024)
        .unwrap();
    assert!(
        Command::new("mke2fs")
            .args(["-q", "-t", "ext2", "-F"])
            .arg(&image)
            .output()
            .unwrap()
            .status
            .success()
    );
    let initial = temporary.0.join("first.elf");
    std::fs::write(&initial, &code[code.len() - 72..]).unwrap();
    let pack = || {
        Command::new("perl")
            .arg(script("pack-boot-module.pl"))
            .arg("pack")
            .arg(&image)
            .arg((4 * 1024 * 1024).to_string())
            .arg(&initial)
            .arg("-")
            .arg(&stage)
            .output()
            .unwrap()
    };
    let result = pack();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let complete = std::fs::read(&image).unwrap();
    assert_eq!(
        boot_module::decode(&complete).unwrap().native_modules,
        selected.stdout
    );
    for invalid in [
        manifest.replace("block.device", "filesystem.ext4"),
        manifest.replace("required=true", "required=1"),
        manifest.replace("version=1", "version=2"),
        manifest.replace("code with spaces", "../../outside"),
        manifest.replace("interfaces=[]", "interfaces=['missing']"),
    ] {
        std::fs::write(bundle.join("manifest.toml"), invalid).unwrap();
        assert!(!pack().status.success());
        assert_eq!(std::fs::read(&image).unwrap(), complete);
    }
}

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn kernel_loads_only_selected_bytes_and_rejects_the_whole_bad_index_before_code_execution() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let source = include_str!("../../../core/src/cext/mod.rs");
    let valid = module(&table(&[(&package("opaque"), true)]));
    let invalid_required = module(&table(&[(b"bad", true), (&package("opaque"), true)]));
    let optional = module(&table(&[(b"bad", false), (&package("opaque"), true)]));
    let mut invalid_range = table(&[(&package("opaque"), true), (&package("opaque"), true)]);
    invalid_range[48..56].copy_from_slice(&0u64.to_le_bytes());
    let invalid_range = module(&invalid_range);
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;
#[path={:?}]mod abi;pub use abi::*;
#[path={:?}]mod provider;use provider::{{CextKind,provider_kind}};
const MCX_CEXT_ABI:u16=4;
#[macro_export]macro_rules! warn{{($($x:tt)*)=>{{}}}}
#[macro_export]macro_rules! info{{($($x:tt)*)=>{{}}}}
mod util{{pub mod log{{pub fn release_boot_marker(_:std::fmt::Arguments){{}}}}}}
mod init{{pub mod fs{{pub static BYTES:std::sync::Mutex<&'static[u8]>=std::sync::Mutex::new(&[]);pub fn boot_module_bytes()->&'static[u8]{{*BYTES.lock().unwrap()}}}}}}
use std::sync::atomic::{{AtomicU32,Ordering}};
static CALLS:AtomicU32=AtomicU32::new(0);static KEPT:AtomicU32=AtomicU32::new(0);
struct LoadedSymbol{{address:u64}}
impl LoadedSymbol{{fn keep_mapped(&mut self){{KEPT.fetch_add(1,Ordering::Relaxed);}}}}
fn load_elf_symbol(bytes:&[u8],symbol:&str)->Option<LoadedSymbol>{{assert_eq!(symbol,"mnu_module_init");assert_eq!(&bytes[64..],b"selected");CALLS.fetch_add(1,Ordering::Relaxed);Some(LoadedSymbol{{address:37}})}}
fn register_provider(kind:CextKind,address:u64,version:u16)->bool{{assert_eq!(kind,CextKind::BlockDevice);assert_eq!(address,37);assert_eq!(version,1);true}}
fn load_cext(name:&str,kind:CextKind,pid:Option<u64>){{assert_eq!(name,"opaque");assert_eq!(kind,CextKind::BlockDevice);assert!(pid.is_none());}}
"#,
        root.join("core/crates/abi/src/lib.rs"),
        root.join("core/src/cext/provider.rs")
    );
    program.push_str(probe::between(
        source,
        "struct CextHeader {",
        "fn register_provider(",
    ));
    program.push_str(probe::between(
        source,
        "fn load_boot_modules()",
        "struct LoadedElf {",
    ));
    program.push_str(&format!(r#"
fn main(){{
 for (bytes,expected,calls) in [(vec!{:?},true,1),(vec!{:?},false,0),(vec!{:?},true,1),(vec!{:?},false,0)]{{
  CALLS.store(0,Ordering::Relaxed);KEPT.store(0,Ordering::Relaxed);
  *init::fs::BYTES.lock().unwrap()=Box::leak(bytes.into_boxed_slice());
  assert_eq!(load_boot_modules(),expected);assert_eq!(CALLS.load(Ordering::Relaxed),calls);assert_eq!(KEPT.load(Ordering::Relaxed),calls);
 }}
}}
"#, valid, invalid_required, optional, invalid_range));
    probe::run(&program);
}
