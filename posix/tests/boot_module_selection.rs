#[path = "../../../core/crates/abi/src/boot_module.rs"]
mod module;

use std::path::{Path, PathBuf};
use std::process::Command;

fn descriptor(resources: u64, offset: u64, length: u64) -> Vec<u8> {
    let mut bytes = vec![0; module::HEADER_LEN + 8];
    bytes[..8].copy_from_slice(&module::MAGIC);
    bytes[8..12].copy_from_slice(&module::VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&(module::HEADER_LEN as u32).to_le_bytes());
    for (start, value) in [(16, resources), (24, offset), (32, length)] {
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn initial_image_is_a_checked_byte_range_not_a_filename() {
    let mut bytes = descriptor(64, 64, 8);
    bytes[64..].copy_from_slice(b"selected");
    let decoded = module::decode(&bytes).unwrap();
    assert_eq!(decoded.initial_image, b"selected");
    assert_eq!(decoded.resources, &bytes[..64]);
    for length in 0..64 {
        assert_eq!(
            module::decode(&bytes[..length]),
            Err(module::Error::Truncated)
        );
    }
    for (resources, offset, length) in [
        (0, 0, 72),
        (63, 63, 9),
        (64, 63, 9),
        (64, 65, 7),
        (64, 64, 0),
        (64, 64, 7),
        (64, 64, 9),
        (u64::MAX, u64::MAX, 1),
    ] {
        assert_eq!(
            module::decode(&descriptor(resources, offset, length)),
            Err(module::Error::InvalidRange)
        );
    }
    assert_eq!(
        module::decode(&descriptor(64, 64, module::MAX_INITIAL_IMAGE_BYTES + 1)),
        Err(module::Error::ImageTooLarge)
    );
}

#[test]
fn descriptor_decoder_rejects_unknown_headers_without_guessing_ranges() {
    for byte in [0, 7, 12, 40, 63] {
        let mut bytes = descriptor(64, 64, 8);
        bytes[byte] ^= 1;
        assert_eq!(module::decode(&bytes), Err(module::Error::InvalidHeader));
    }
    let mut bytes = descriptor(64, 64, 8);
    bytes[8] = 2;
    assert_eq!(
        module::decode(&bytes),
        Err(module::Error::UnsupportedVersion)
    );
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("boot-module-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/mmake")
        .join(name)
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn elf(length: usize) -> Vec<u8> {
    let mut bytes = vec![0x59; length];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes
}

#[test]
fn packer_preserves_filesystem_blocks_and_atomically_rejects_bad_selection() {
    let fixture = Fixture::new();
    let image = fixture.0.join("resources.img");
    let selected = fixture.0.join("caller-selected.elf");
    let resource_bytes = 4 * 1024 * 1024;
    std::fs::File::create(&image)
        .unwrap()
        .set_len(resource_bytes)
        .unwrap();
    run(Command::new("mke2fs")
        .args(["-q", "-t", "ext2", "-b", "1024", "-F"])
        .arg(&image));
    let before = std::fs::read(&image).unwrap();
    for length in [128, 256, 64] {
        let payload = elf(length);
        std::fs::write(&selected, &payload).unwrap();
        run(Command::new("perl")
            .arg(script("pack-boot-module.pl"))
            .arg("pack")
            .arg(&image)
            .arg(resource_bytes.to_string())
            .arg(&selected));
        let bytes = std::fs::read(&image).unwrap();
        let decoded = module::decode(&bytes).unwrap();
        assert_eq!(decoded.resources.len() as u64, resource_bytes);
        assert_eq!(&decoded.resources[64..], &before[64..]);
        assert_eq!(decoded.initial_image, payload);
        assert_eq!(bytes.len(), resource_bytes as usize + length);
        run(Command::new("perl")
            .arg(script("pack-boot-module.pl"))
            .arg("check")
            .arg(&image)
            .arg(resource_bytes.to_string()));
        run(Command::new("e2fsck").args(["-f", "-n"]).arg(&image));
    }
    let complete = std::fs::read(&image).unwrap();
    for invalid in [b"not an ELF".to_vec(), vec![0; 64]] {
        std::fs::write(&selected, invalid).unwrap();
        assert!(
            !Command::new("perl")
                .arg(script("pack-boot-module.pl"))
                .arg("pack")
                .arg(&image)
                .arg(resource_bytes.to_string())
                .arg(&selected)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(std::fs::read(&image).unwrap(), complete);
    }
    std::fs::File::create(&selected)
        .unwrap()
        .set_len(module::MAX_INITIAL_IMAGE_BYTES + 1)
        .unwrap();
    assert!(
        !Command::new("perl")
            .arg(script("pack-boot-module.pl"))
            .arg("pack")
            .arg(&image)
            .arg(resource_bytes.to_string())
            .arg(&selected)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(std::fs::read(&image).unwrap(), complete);
}

#[test]
fn normal_initfs_builder_refreshes_selection_without_rebuilding_the_filesystem() {
    let fixture = Fixture::new();
    let stage = fixture.0.join("stage");
    std::fs::create_dir(&stage).unwrap();
    let image = fixture.0.join("initfs.img");
    let config = fixture.0.join("config");
    std::fs::write(&config, b"IMAGE_INITFS_SIZE_MB=4\n").unwrap();
    let mut uuid = Vec::new();
    for length in [128, 512] {
        let payload = elf(length);
        std::fs::write(stage.join("init"), &payload).unwrap();
        run(Command::new("bash")
            .arg(script("make-ext2-image.sh"))
            .arg(&stage)
            .arg(&image)
            .arg("initfs")
            .arg(&config));
        let bytes = std::fs::read(&image).unwrap();
        assert_eq!(module::decode(&bytes).unwrap().initial_image, payload);
        if uuid.is_empty() {
            uuid.extend_from_slice(&bytes[1128..1144]);
        } else {
            assert_eq!(&bytes[1128..1144], uuid);
        }
        run(Command::new("e2fsck").args(["-f", "-n"]).arg(&image));
    }
}
