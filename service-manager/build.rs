fn main() {
    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(path) => path,
        Err(_) => panic!("CARGO_MANIFEST_DIR missing"),
    };
    println!("cargo:rustc-link-arg=-T{}/linker.ld", manifest_dir);
    println!("cargo:rerun-if-changed={}/linker.ld", manifest_dir);
}
