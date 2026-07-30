fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("mochios") {
        println!("cargo:rustc-link-arg=-T{}/linker.ld", manifest_dir);
    }
    println!("cargo:rerun-if-changed={}/linker.ld", manifest_dir);
}
