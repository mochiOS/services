extern crate alloc;

#[path = "../../../core/src/cext/provider.rs"]
mod actual;

#[test]
fn only_the_explicit_block_interface_selects_a_kernel_abi_adapter() {
    use actual::{CextKind, provider_kind};
    for valid in [vec!["block.device"], vec!["block.device", "block.device"]] {
        let interfaces = valid.into_iter().map(String::from).collect::<Vec<_>>();
        assert_eq!(provider_kind(&interfaces), Some(CextKind::BlockDevice));
    }
    for rejected in [
        vec![],
        vec![""],
        vec!["filesystem.ext2"],
        vec!["filesystem.ext4"],
        vec!["disk"],
        vec!["block.device.extra"],
        vec!["device.service"],
        vec!["block.device", "filesystem.ext2"],
        vec!["filesystem.ext4", "block.device"],
        vec!["block.device", "unknown.interface"],
    ] {
        let interfaces = rejected.into_iter().map(String::from).collect::<Vec<_>>();
        assert_eq!(provider_kind(&interfaces), None);
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
    let loader = cext.split("fn load_bundle_directories()").nth(1).unwrap();
    assert!(
        loader.find("provider_kind(&manifest.provides)").unwrap()
            < loader.find("read_initfs(&entry_path)").unwrap()
    );
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
