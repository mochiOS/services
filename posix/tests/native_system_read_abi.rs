#[test]
fn raw_read_probe_uses_native_storage_abi_and_declares_its_authority() {
    let source = include_str!("native_system_read.c");
    assert!(source.contains(&format!(
        "BLOCK_READ = {}",
        mnu_abi::SyscallNumber::BlockRead as u64
    )));
    assert!(!source.contains("BLOCK_WRITE"));
    assert!(include_str!("native-system-read-manifest.toml").contains("\"device.storage\""));
}
