extern crate alloc;

#[path = "../../../core/src/cext/provider.rs"]
mod actual;

#[test]
fn only_the_explicit_numeric_block_adapter_selects_a_kernel_abi() {
    use actual::{CextKind, provider_kind};
    assert_eq!(
        provider_kind(mnu_abi::boot_extensions::ADAPTER_BLOCK),
        Some(CextKind::BlockDevice)
    );
    for rejected in [0, 2, u32::MAX] {
        assert_eq!(provider_kind(rejected), None);
    }
}

#[test]
fn filesystem_code_cannot_register_or_mount_inside_the_kernel() {
    let cext = include_str!("../../../core/src/cext/mod.rs");
    let init = include_str!("../../../core/src/init/mod.rs");
    let disk = include_str!("../../../core/src/cext/disk.rs");
    for source in [cext, init, disk] {
        for retired in [
            "McxFsOps",
            "McxPath",
            "McxBuffer",
            "FsInitFn",
            "register_filesystem_provider",
            "cext::fs::",
            "CextKind::Filesystem",
            "serialized_ops_ptr",
            "filesystem.ext2",
            "filesystem.ext4",
        ] {
            assert!(
                !source.contains(retired),
                "retired kernel filesystem ABI returned: {retired}"
            );
        }
    }
    assert!(!cext.contains("pub mod fs;"));
    assert!(
        !std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/src/cext/fs.rs")
            .exists()
    );
    let loader = cext.split("fn load_boot_modules()").nth(1).unwrap();
    assert!(
        loader
            .find("boot_extensions::decode(module.native_modules)")
            .unwrap()
            < loader.find("load_elf_symbol(&meta.elf").unwrap()
    );
    for removed in [
        "manifest.toml",
        "parse_bundle_manifest",
        "initfs_readdir_path",
        "read_initfs(",
        "block.device",
        "ends_with(\".cext\")",
    ] {
        assert!(
            !cext.contains(removed),
            "kernel retains userspace bundle policy: {removed}"
        );
    }
    assert!(loader.contains("register_provider(kind, module.address, meta.module_version)"));
    // Native block operations still serialize access to the surviving provider.
    assert!(disk.contains("let _guard = DISK_IO_LOCK.lock();"));
}

#[test]
fn userspace_filesystem_requires_a_real_backend_before_reporting_ready() {
    let source = include_str!("../../filesystem/src/main.rs");
    let discovery = source
        .split("match find_data_partition(0)")
        .nth(1)
        .unwrap()
        .split("let partition =")
        .next()
        .unwrap();
    assert!(!discovery.contains("notify(ready_target, 0)"));
    assert!(discovery.contains("notify(ready_target, -1)"));
    assert!(discovery.contains("process::exit(1)"));
    assert!(!source.contains("retaining CExt root"));
    assert!(source.contains("Ext4::load_with_writer"));
    assert!(source.contains("Ext4::load(Box::new(ImmutableExt4Storage"));
}
