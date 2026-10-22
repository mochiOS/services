#[test]
fn normal_user_workspace_checks_resolve_current_local_native_and_posix_dependencies() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new(env!("CARGO"))
        .current_dir(root.join("user"))
        .args([
            "tree",
            "--offline",
            "--locked",
            "--target",
            "all",
            "--features",
            "mochi-user-platform/mboot-wifi",
            "--color",
            "never",
            "--manifest-path",
            "Cargo.toml",
            "--prefix",
            "none",
            "--format",
            "{p}",
            "-p",
            "mochi-user-newlib-runtime",
            "-p",
            "mochi-user-platform",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let graph = String::from_utf8(output.stdout).unwrap();
    for suffix in [
        "/core/crates/abi)",
        "/services/mboot-protocol)",
        "/user/crates/syscall)",
        "/user/crates/platform)",
        "/user/crates/posix-client)",
        "/user/crates/posix-protocol)",
    ] {
        assert!(
            graph.contains(suffix),
            "missing local dependency {suffix}: {graph}"
        );
    }
    for source in [
        "https://github.com/mochiOS/mnu",
        "https://github.com/mochiOS/syscalls",
        "https://github.com/mochiOS/mBoot",
        "https://github.com/mochiOS/libc",
    ] {
        assert!(
            !graph.contains(source),
            "stale remote implementation: {graph}"
        );
    }
    let libc = std::process::Command::new(env!("CARGO"))
        .current_dir(root.join("services"))
        .args([
            "tree",
            "--offline",
            "--locked",
            "--color",
            "never",
            "--prefix",
            "none",
            "-p",
            "libc",
        ])
        .output()
        .unwrap();
    assert!(
        libc.status.success(),
        "{}",
        String::from_utf8_lossy(&libc.stderr)
    );
    assert!(String::from_utf8_lossy(&libc.stdout).contains("/libraries/libc)"));
}

#[test]
fn repository_overrides_do_not_add_parent_dependencies_to_the_standalone_sdk_workspace() {
    // Source-layout contract only; this is not an SDK build or packaging test.
    let manifest = include_str!("../../../user/Cargo.toml");
    for parent in ["../core", "../services", "../libraries"] {
        assert!(
            !manifest.contains(parent),
            "SDK workspace acquired a parent dependency"
        );
    }
    let config = include_str!("../../../.cargo/config.toml");
    assert!(config.contains("services/mboot-protocol"));
    assert!(config.contains("core/crates/abi"));
}
