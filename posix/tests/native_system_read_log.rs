use sha2::{Digest, Sha256};
use std::path::PathBuf;

// Consume the retained output of the real KVM probe, without booting an OS
// during ordinary cargo test. This gate is opt-in and does not measure speed.
#[test]
#[ignore = "requires a retained KVM native_system_read log and the tested native binaries"]
fn latest_authorization_and_filesystem_builds_pass_the_native_read_probe() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let log_path = std::env::var_os("MOCHIOS_NATIVE_SYSTEM_READ_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            root.join("out/posix-host-check/capability-posix-reused-buffer.serial.log")
        });
    let log = std::fs::read_to_string(log_path).expect("missing native probe log");
    let hashes_path = std::env::var_os("MOCHIOS_NATIVE_SYSTEM_READ_BUILD_HASHES")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("out/posix-host-check/capability-posix-reused-buffer.sha256"));
    // Record these after comparing the extracted fixture files with the native
    // build, before booting it. A matching byte count alone is not identity.
    let hashes = std::fs::read_to_string(hashes_path).expect("missing tested build hashes");
    for (artifact, entry) in [
        ("capability", "capability.service"),
        ("filesystem-service", "filesystem.service"),
    ] {
        let binary = root.join(format!(
            "out/rust-std/target/x86_64-unknown-mochios/release/{artifact}"
        ));
        let bytes = std::fs::read(binary).expect("missing tested native binary");
        let length = bytes.len();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        assert!(
            hashes
                .lines()
                .any(|line| line == format!("{digest}  {artifact}")),
            "binary changed since the native run: {artifact}"
        );
        assert!(
            log.contains(&format!(
                "loaded '/system/services/{entry}' from cext ({length} bytes)"
            )),
            "stale or different native build: {entry}"
        );
    }
    let posix = log
        .find("loaded '/system/services/posix.service'")
        .expect("POSIX not launched");
    let input = log
        .find("loaded '/system/services/input.service'")
        .expect("post-handoff launch failed");
    assert!(posix < input);
    for marker in [
        "system-read: namespace ok",
        "system-read: bulk matches inline bytes and shared offset",
        "system-read: single 16MiB read in ",
        "system-read: resident 8MiB read in ",
        "system-read: shared short read and EOF ok",
        "system-read: ok",
        "input.service readiness failed: ProcessExited(0)",
    ] {
        assert!(
            log.contains(marker),
            "missing native probe result: {marker}"
        );
    }
    // The probe intentionally exits rather than becoming the desktop input
    // service. Do not mistake that expected stop for a full desktop pass.
    assert!(!log.contains("readiness failed: TimedOut"));
    assert!(!log.contains("panicked at"));
}
