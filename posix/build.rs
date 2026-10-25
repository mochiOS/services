#[path = "src/system_identity_metadata.rs"]
mod metadata;

fn main() {
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let version = manifest.join("../../version.toml");
    println!("cargo:rerun-if-changed={}", version.display());
    println!("cargo:rerun-if-changed=src/system_identity_metadata.rs");
    let text = std::fs::read_to_string(&version).expect("POSIX identity requires version.toml");
    let architecture = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let generated =
        metadata::generate(&text, &architecture).expect("invalid POSIX release metadata");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("system_identity.rs"), generated).unwrap();
}
