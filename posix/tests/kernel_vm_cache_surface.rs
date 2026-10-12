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
fn actual_vm_object_cache_keys_keep_provider_identity_separate_from_legacy_inodes() {
    let source = include_str!("../../../core/src/mem/vm_object.rs");
    let mut program = String::from(
        r#"
use std::sync::Arc;
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct MountId(u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct InodeId(u64);
struct Inode { mount_id: MountId, inode_id: InodeId }
struct Vnode { inode: Inode }
struct ProviderObject { endpoint_thread_id: u64, endpoint_slot: u16, endpoint_generation: u64 }
mod shared_memory {
    pub struct SharedMemory(pub u64);
    impl SharedMemory { pub fn id(&self) -> u64 { self.0 } }
}
mod actual {
    use super::*;
"#,
    );
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
        "    pub fn file(",
        "    pub fn provider(",
        "    fn object_key(",
    ] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n    }\n").unwrap() + 7;
        program.push_str(&source[start..end]);
    }
    program.push_str(r#"
}
pub fn verify() {
    let object = Arc::new(ProviderObject { endpoint_thread_id: 7, endpoint_slot: 2, endpoint_generation: 3 });
    let first = VmObject::provider(Arc::clone(&object), 11);
    let duplicate = VmObject::provider(Arc::clone(&object), 11);
    assert_eq!(first.object_key(), duplicate.object_key());
    assert_eq!(first.object_key(), ObjectKey::Provider {
        endpoint_thread_id: 7, endpoint_slot: 2, endpoint_generation: 3, identity: 11,
    });
    assert_ne!(first.object_key(), VmObject::provider(Arc::clone(&object), 12).object_key());
    for replacement in [
        ProviderObject { endpoint_thread_id: 8, endpoint_slot: 2, endpoint_generation: 3 },
        ProviderObject { endpoint_thread_id: 7, endpoint_slot: 4, endpoint_generation: 3 },
        ProviderObject { endpoint_thread_id: 7, endpoint_slot: 2, endpoint_generation: 4 },
    ] {
        assert_ne!(first.object_key(), VmObject::provider(Arc::new(replacement), 11).object_key());
    }
    let memory = VmObject::shared_memory(Arc::new(shared_memory::SharedMemory(11)));
    let legacy = VmObject::file(Arc::new(Vnode { inode: Inode { mount_id: MountId(7), inode_id: InodeId(11) } }));
    assert_ne!(first.object_key(), memory.object_key());
    assert_ne!(first.object_key(), legacy.object_key());
    assert_ne!(memory.object_key(), legacy.object_key());
    assert_eq!(legacy.object_key(), ObjectKey::Vnode { mount_id: MountId(7), inode_id: InodeId(11) });
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
