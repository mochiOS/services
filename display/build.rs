use std::{env, path::PathBuf};

fn main() {
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
