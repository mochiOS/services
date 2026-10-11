#[test]
fn legacy_file_reading_has_no_abi_dispatch_or_platform_fallback() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    let package = include_str!("../../../user/crates/platform/src/package.rs");
    for (name, number) in [
        ("FileOpen", 560),
        ("FileClose", 562),
        ("FileRead", 563),
        ("FileReadDir", 569),
    ] {
        assert!(!abi.contains(&format!("{name} =")));
        assert!(!abi.contains(&format!("= {number},")));
        assert!(!dispatch.contains(&format!("SyscallNumber::{name}")));
        assert!(!platform.contains(&format!("SyscallNumber::{name}")));
    }
    assert!(!platform.contains("pub mod file {"));
    assert!(!package.contains("pub fn read_manifest("));
    assert!(platform.contains("pub mod handle {"));
    assert!(dispatch.contains("SyscallNumber::HandleRead"));
}
