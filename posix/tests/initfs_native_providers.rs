use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mochios-initfs-providers-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn stage(&self) -> std::process::Output {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/mmake/stage-initfs.sh");
        Command::new("bash")
            .arg(script)
            .arg(self.0.join("inputs with spaces"))
            .arg(self.0.join("mmake with spaces"))
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn real_stager_needs_only_the_native_provider_and_discards_stale_filesystems() {
    let fixture = Fixture::new();
    fixture.write(
        "inputs with spaces/out/rust-std/target/x86_64-unknown-mochios/release/core",
        b"core-image",
    );
    fixture.write(
        "inputs with spaces/boot/config/kernel.conf",
        b"kernel-config",
    );
    fixture.write(
        "mmake with spaces/cexts/disk.cext/entry",
        b"native-block-image",
    );
    fixture.write(
        "mmake with spaces/cexts/disk.cext/manifest.toml",
        b"native-block-manifest",
    );
    fixture.write("mmake with spaces/image/rootfs.img", b"signed-system-image");
    let stage = fixture.0.join("mmake with spaces/image/initfs");
    for stale in [false, true] {
        if stale {
            // Neither stale input artifacts nor a previous stage may reintroduce FS code.
            fixture.write(
                "mmake with spaces/cexts/ext2.cext/entry",
                b"retired-provider",
            );
            fixture.write(
                "mmake with spaces/image/initfs/ext2.cext/entry",
                b"retired-provider",
            );
            fixture.write(
                "mmake with spaces/image/initfs.new/ext2.cext/entry",
                b"retired-provider",
            );
        }
        let output = fixture.stage();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(stage.join("init")).unwrap(), b"core-image");
        assert_eq!(
            fs::read(stage.join("config/kernel.conf")).unwrap(),
            b"kernel-config"
        );
        assert_eq!(
            fs::read(stage.join("disk.cext/entry")).unwrap(),
            b"native-block-image"
        );
        assert_eq!(
            fs::read(stage.join("disk.cext/manifest.toml")).unwrap(),
            b"native-block-manifest"
        );
        assert_eq!(
            fs::read(stage.join("install/rootfs.sha256")).unwrap(),
            Sha256::digest(b"signed-system-image").as_slice()
        );
        assert!(stage.join(".ready").is_file());
        assert!(!stage.join("ext2.cext").exists());
        assert!(
            !fixture
                .0
                .join("mmake with spaces/image/initfs.new")
                .exists()
        );
    }
    fs::remove_file(fixture.0.join("mmake with spaces/cexts/disk.cext/entry")).unwrap();
    assert!(
        !fixture.stage().status.success(),
        "required block provider must not be optional"
    );
}

#[test]
fn normal_build_and_boot_gates_do_not_depend_on_a_kernel_filesystem() {
    let build = include_str!("../../../build/mmake/extensions.mk");
    let watch = include_str!("../../../build/mmake/inputs.mk");
    assert!(!build.contains("ext2.cext"));
    assert!(!build.contains("mochi-ext2-cext"));
    assert!(build.contains("-p mochi-disk-cext"));
    assert!(watch.contains("@watch cexts/modules/disk/**"));
    assert!(!watch.contains("@watch cexts/ext2.cext/**"));
    let filesystem = include_str!("../../filesystem/src/main.rs");
    let marker = filesystem
        .find("eprintln!(\"filesystem.service: native System mounted at LBA")
        .unwrap();
    assert!(filesystem.find(".map(|_| first_lba)").unwrap() < marker);
    assert!(
        filesystem
            .find("notify_handle(ready_target, 0, endpoint, delegated_rights)")
            .unwrap()
            < marker
    );
    let ab = include_str!("../../../scripts/tests/ab-layout-kvm-test.sh");
    assert!(ab.contains("native System mounted at LBA $rootfs_start (ready)"));
    assert!(!ab.contains("ext2.cext: mounted system"));
    let smoke = include_str!("../../../scripts/runner.sh");
    assert!(!smoke.contains("loaded bundle ext2"));
    assert!(smoke.contains("filesystem.service: native System mounted at LBA"));
}

#[test]
fn readiness_reports_the_mounted_system_partition_not_the_data_partition() {
    let source = include_str!("../../filesystem/src/main.rs");
    let pipeline = source
        .split("let system = find_system_partition(0)")
        .nth(1)
        .unwrap()
        .split("let system_first_lba =")
        .next()
        .unwrap();
    let fixture = Fixture::new();
    let code = format!(
        r#"
use std::sync::Arc;
struct MochiDisk;
impl MochiDisk {{ fn new(_: u32) -> Self {{ Self }} }}
struct PartitionIo {{ first: u64 }}
impl PartitionIo {{ fn new(_: MochiDisk, first: u64, _: u64) -> Self {{ Self {{ first }} }} }}
struct ImmutableExt4Storage(Arc<PartitionIo>);
impl ImmutableExt4Storage {{ fn new(partition: Arc<PartitionIo>) -> Self {{ Self(partition) }} }}
struct Ext4(u64);
impl Ext4 {{ fn load(storage: Box<ImmutableExt4Storage>) -> Result<Self, &'static str> {{ Ok(Self(storage.0.first)) }} }}
struct Service;
impl Service {{ fn mount_named_volume(&mut self, root: &[u8], name: &[u8], system: Ext4, path: &[u8]) -> Result<(), i32> {{
    assert_eq!((root, name, path), (&b"/"[..], &b"system"[..], &b"/system"[..]));
    assert_eq!(system.0, 202); Ok(())
}} }}
fn find_system_partition(_: u32) -> Result<(u64, u64), &'static str> {{ Ok((202, 303)) }}
fn main() {{
    let first_lba = 999; // Data: must never become the System readiness identity.
    let mut service = Service;
    let system = find_system_partition(0){pipeline}
    assert_eq!(system.unwrap(), 202);
    assert_eq!(first_lba, 999);
}}
"#
    );
    let input = fixture.0.join("system_partition.rs");
    let binary = fixture.0.join("system_partition");
    fs::write(&input, code).unwrap();
    let built = Command::new("rustc")
        .args(["--edition=2024", "-o"])
        .arg(&binary)
        .arg(input)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let result = Command::new(binary).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn ab_boot_probe_selects_named_system_volumes_and_rejects_ambiguity() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.write(
        "bin/sfdisk",
        b"#!/bin/sh\nexec cat \"$MOCHIOS_TEST_PARTITIONS\"\n",
    );
    let stub = fixture.0.join("bin/sfdisk");
    fs::set_permissions(stub, fs::Permissions::from_mode(0o755)).unwrap();
    let source = include_str!("../../../scripts/tests/ab-layout-kvm-test.sh");
    let prefix = source.split("artifact_dir=").next().unwrap();
    let probe = format!("{prefix}\nprintf '%s %s\\n' \"$rootfs_start\" \"$rootfs_size\"\n");
    let system_a = r#"{"name":"mochiOS System A","start":3000,"size":500}"#;
    let system_b = r#"{"name":"mochiOS System B","start":7000,"size":900}"#;
    let data = r#"{"name":"mochiOS Data","start":9000,"size":100}"#;
    let boot_a = r#"{"name":"mochiOS Boot A","start":2000,"size":80}"#;
    let boot_b = r#"{"name":"mochiOS Boot B","start":6000,"size":80}"#;
    for (parts, valid) in [
        (vec![boot_a, system_a, boot_b, system_b, data], true),
        (vec![system_b, data, boot_b, system_a, boot_a], true),
        (vec![system_a, system_a, system_b, data], false),
        (vec![boot_a, system_b, data], false),
    ] {
        fixture.write(
            "partitions.json",
            format!(
                "{{\"partitiontable\":{{\"partitions\":[{}]}}}}",
                parts.join(",")
            )
            .as_bytes(),
        );
        for (slot, expected) in [("A", "3000 500\n"), ("B", "7000 900\n")] {
            let result = Command::new("bash")
                .args(["-c", &probe, "ab-probe"])
                .arg(&fixture.0)
                .arg("unused.img")
                .arg(slot)
                .env(
                    "PATH",
                    format!(
                        "{}:{}",
                        fixture.0.join("bin").display(),
                        std::env::var("PATH").unwrap()
                    ),
                )
                .env("MOCHIOS_TEST_PARTITIONS", fixture.0.join("partitions.json"))
                .output()
                .unwrap();
            if valid || slot == "B" {
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                assert_eq!(result.stdout, expected.as_bytes());
            } else {
                assert!(
                    !result.status.success(),
                    "ambiguous/missing System A must be rejected"
                );
            }
        }
    }
}
