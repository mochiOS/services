use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(target_os, values(\"mochios\"))");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("mochios") {
        return;
    }
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing manifest dir"));
    println!(
        "cargo:rustc-link-arg=-T{}/linker.ld",
        manifest_dir.display()
    );
    println!(
        "cargo:rerun-if-changed={}/linker.ld",
        manifest_dir.display()
    );
}
