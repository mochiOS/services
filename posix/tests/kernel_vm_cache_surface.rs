use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn unused_inode_cache_commands_are_not_a_kernel_filesystem_interface() {
    let source = include_str!("../../../core/src/mem/vm_object.rs");
    for removed in [
        "invalidate_inode",
        "invalidate_range",
        "truncate_inode",
        "contiguous_uncached_pages",
    ] {
        assert!(
            !source.contains(&format!("fn {removed}(")),
            "{removed} returned to the kernel"
        );
    }
    for retained in [
        "update_provider_range",
        "overlay_provider_range",
        "lock_provider_io",
        "invalidate_object",
        "read_lower_until",
        "write_lower",
    ] {
        assert!(
            source.contains(&format!("fn {retained}(")),
            "active object cache operation {retained} was removed"
        );
    }
    let filesystem = include_str!("../../filesystem/src/service.rs");
    assert!(filesystem.contains("protocol::OP_TRUNCATE_HANDLE"));
    assert!(filesystem.contains("protocol::OP_TRUNCATE_AT"));
}

#[test]
fn actual_vm_object_cache_keys_keep_provider_identity_separate_from_memory_objects() {
    let source = include_str!("../../../core/src/mem/vm_object.rs");
    let mut program = String::from(
        r#"
extern crate alloc;
use std::sync::Arc;
mod syscall {pub const ENOMEM:u64=(-12i64) as u64;}
mod mem {pub mod object_io_native {
    pub fn new_lock()->Result<crate::object_io::IoLock,u64>{
        Ok(crate::object_io::IoLock::from_allocated(std::sync::Arc::new(crate::object_io::State::new())))
    }
}}
struct ProviderObject { endpoint_thread_id: u64, endpoint_slot: u16, endpoint_generation: u64 }
mod shared_memory {
    pub struct SharedMemory(pub u64);
    impl SharedMemory { pub fn id(&self) -> u64 { self.0 } }
}
"#,
    );
    program.push_str(&format!(
        "#[path={:?}] mod object_io;\n",
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/src/mem/object_io.rs")
            .canonicalize()
            .unwrap()
    ));
    program.push_str(r#"
mod actual {
    use super::*;
    struct RegistryLock(std::sync::Mutex<object_io::Registry<ObjectKey>>);
    impl RegistryLock { fn lock(&self)->std::sync::MutexGuard<'_,object_io::Registry<ObjectKey>>{self.0.lock().unwrap()} }
    static PROVIDER_IO:RegistryLock=RegistryLock(std::sync::Mutex::new(object_io::Registry::new()));
"#);
    for entry in [
        "enum ObjectKey {",
        "enum VmObjectSource {",
        "pub struct VmObject {",
    ] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        if entry == "enum ObjectKey {" {
            program.push_str("#[derive(Debug, PartialEq, Eq)]\n");
        }
        program.push_str(&source[start..end]);
    }
    program.push_str("impl VmObject {\n");
    for entry in [
        "    pub fn shared_memory(",
        "    pub fn provider(",
        "    pub(crate) fn object_key(",
    ] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n    }\n").unwrap() + 7;
        program.push_str(&source[start..end]);
    }
    program.push_str(r#"
}
pub fn verify() {
    let object = Arc::new(ProviderObject { endpoint_thread_id: 7, endpoint_slot: 2, endpoint_generation: 3 });
    let first = VmObject::provider(Arc::clone(&object), 11).unwrap();
    let duplicate = VmObject::provider(Arc::clone(&object), 11).unwrap();
    assert_eq!(first.object_key(), duplicate.object_key());
    assert_eq!(first.object_key(), ObjectKey::Provider {
        endpoint_thread_id: 7, endpoint_slot: 2, endpoint_generation: 3, identity: 11,
    });
    assert_ne!(first.object_key(), VmObject::provider(Arc::clone(&object), 12).unwrap().object_key());
    for replacement in [
        ProviderObject { endpoint_thread_id: 8, endpoint_slot: 2, endpoint_generation: 3 },
        ProviderObject { endpoint_thread_id: 7, endpoint_slot: 4, endpoint_generation: 3 },
        ProviderObject { endpoint_thread_id: 7, endpoint_slot: 2, endpoint_generation: 4 },
    ] {
        assert_ne!(first.object_key(), VmObject::provider(Arc::new(replacement), 11).unwrap().object_key());
    }
    let memory = VmObject::shared_memory(Arc::new(shared_memory::SharedMemory(11)));
    assert_ne!(first.object_key(), memory.object_key());
}
}
fn main() { actual::verify(); }
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-vm-cache-surface-{}-{}",
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
