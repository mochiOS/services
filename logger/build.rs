use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing manifest dir"));
    // Native SDKs supply the target layout, TLS, RELRO and unwind tables.
    // Keep the existing x86 build contract for the legacy static SDK only.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("mochios")
        && env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        println!(
            "cargo:rustc-link-arg=-T{}/linker.ld",
            manifest_dir.display()
        );
    }
    println!(
        "cargo:rerun-if-changed={}/linker.ld",
        manifest_dir.display()
    );
}
