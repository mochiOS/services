#![allow(dead_code)]

extern crate alloc;

mod file {
    use alloc::vec::Vec;

    pub fn read_to_end_path(_path: &str) -> Result<Vec<u8>, ()> {
        Err(())
    }
}

#[path = "../../../user/crates/platform/src/package.rs"]
mod package;

const SERVICE_MANAGER_MANIFEST: &str = include_str!("../manifest.toml");
const CAPABILITY_MANIFEST: &str = include_str!("../../capability/manifest.toml");
const DRIVERS_MANIFEST: &str = include_str!("../../drivers/manifest.toml");
const INPUT_MANIFEST: &str = include_str!("../../input/manifest.toml");
const DISPLAY_MANIFEST: &str = include_str!("../../display/manifest.toml");
const COMPOSITOR_MANIFEST: &str = include_str!("../../compositor/manifest.toml");
const TTY_MANIFEST: &str = include_str!("../../tty/manifest.toml");
const UPDATE_MANIFEST: &str = include_str!("../../update/manifest.toml");
const SERVICE_INDEX: &str = include_str!("../../index.toml");

fn assert_capabilities(manifest: &str, path: &str, expected: &[&str]) {
    let manifest = match package::parse_manifest(manifest) {
        Some(manifest) => manifest,
        None => panic!("manifest was rejected for {path}"),
    };
    let binary = match manifest.binary(path) {
        Some(binary) => binary,
        None => panic!("binary is missing for {path}"),
    };
    let actual = binary
        .requires
        .iter()
        .map(alloc::string::String::as_str)
        .collect::<alloc::vec::Vec<_>>();
    assert_eq!(actual, expected);
}

fn main() {
    let manager = match package::parse_manifest(SERVICE_MANAGER_MANIFEST) {
        Some(manifest) => manifest,
        None => panic!("service-manager manifest was rejected"),
    };
    assert_eq!(manager.package_id, "org.mochios.service-manager");
    let manager_binary = match manager.binary("/system/services/service-manager.service") {
        Some(binary) => binary,
        None => panic!("service-manager binary is missing"),
    };
    assert_eq!(manager_binary.kind.as_deref(), Some("service"));

    assert_eq!(
        manager_binary
            .requires
            .iter()
            .map(alloc::string::String::as_str)
            .collect::<alloc::vec::Vec<_>>(),
        [
            "fs.read.all",
            "process.spawn",
            "service.register",
            "capabilities.manage",
            "ipc.client",
            "ipc.server",
            "net.connect",
        ]
    );
    assert!(
        manager_binary
            .requires
            .iter()
            .any(|capability| capability == "service.register")
    );

    let capability = match package::parse_manifest(CAPABILITY_MANIFEST) {
        Some(manifest) => manifest,
        None => panic!("capability manifest was rejected"),
    };
    let capability_binary = match capability.binary("/system/services/capability.service") {
        Some(binary) => binary,
        None => panic!("capability binary is missing"),
    };
    assert!(
        capability_binary
            .requires
            .iter()
            .any(|capability| capability == "capabilities.manage")
    );
    assert!(
        capability_binary
            .requires
            .iter()
            .any(|capability| capability == "net.connect")
    );

    assert_capabilities(
        INPUT_MANIFEST,
        "/system/services/input.service",
        &["ipc.client", "ipc.server"],
    );
    assert_capabilities(
        DISPLAY_MANIFEST,
        "/system/services/display.driver",
        &[
            "device.gpu",
            "display.read",
            "dma.allocate",
            "ipc.client",
            "ipc.server",
        ],
    );
    assert_capabilities(
        COMPOSITOR_MANIFEST,
        "/system/services/compositor.service",
        &[
            "display.read",
            "fs.read.all",
            "input.keyboard",
            "input.pointer",
            "ipc.client",
            "ipc.server",
            "process.spawn",
            "window.create",
            "window.overlay",
        ],
    );
    assert_capabilities(
        TTY_MANIFEST,
        "/system/services/tty.service",
        &[
            "fs.read.all",
            "process.spawn",
            "ipc.client",
            "ipc.server",
            "net.connect",
            "net.tls.connect",
            "net.http.request",
        ],
    );
    assert_capabilities(
        UPDATE_MANIFEST,
        "/system/services/update.service",
        &[
            "fs.read.all",
            "fs.write.all",
            "ipc.client",
            "ipc.server",
            "net.http.request",
            "signature.db.write",
            "system.time.read",
        ],
    );

    let manager_index = match SERVICE_INDEX.split("[service-manager.service]").nth(1) {
        Some(section) => section,
        None => panic!("service-manager index entry is missing"),
    };
    let manager_index = manager_index
        .split('\n')
        .take(6)
        .collect::<alloc::string::String>();
    assert!(manager_index.contains("dir = \"service-manager\""));
    assert!(manager_index.contains("fs = \"rootfs\""));
    assert!(manager_index.contains("autostart = false"));
}
