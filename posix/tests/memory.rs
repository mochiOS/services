use mochios_posix_client::memory::{
    PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE, native_access,
};

#[test]
fn posix_protection_flags_translate_to_native_vm_access() {
    assert_eq!(native_access(PROT_NONE), Some(0));
    assert_eq!(native_access(PROT_READ), Some(mnu_abi::MEMORY_ACCESS_READ));
    assert_eq!(
        native_access(PROT_READ | PROT_WRITE),
        Some(mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE)
    );
    assert_eq!(
        native_access(PROT_READ | PROT_EXEC),
        Some(mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_EXECUTE)
    );
    assert_eq!(native_access(1 << 8), None);
    assert_eq!(native_access(-1), None);
}

#[test]
fn kernel_memory_protection_uses_only_native_access_flags() {
    let native = include_str!("../../../core/src/syscall/memory.rs");
    assert!(native.contains("mnu_abi::MEMORY_ACCESS_ALL"));
    assert!(native.contains("mnu_abi::MEMORY_ACCESS_WRITE"));
    assert!(native.contains("mnu_abi::MEMORY_ACCESS_EXECUTE"));
    assert!(!native.contains("const PROT_"));
    assert!(!native.contains("pub fn mprotect"));

    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("mochios_posix_client::memory::native_access(prot)"));
}
