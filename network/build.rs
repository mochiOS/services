fn main() {
    println!("cargo:rustc-check-cfg=cfg(mochios_dns_replies_probe_280)");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing");
    // Native SDKs supply the target layout, TLS, RELRO and unwind tables.
    // Keep the existing x86 build contract for the legacy static SDK only.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("mochios")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        println!("cargo:rustc-link-arg=-T{}/linker.ld", manifest_dir);
    }
    println!("cargo:rerun-if-changed={}/linker.ld", manifest_dir);
}
