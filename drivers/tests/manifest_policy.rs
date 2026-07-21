extern crate alloc;

mod file {
    use alloc::vec::Vec;

    pub fn read_to_end_path(_path: &str) -> Result<Vec<u8>, ()> {
        Err(())
    }
}

#[path = "../../../user/crates/platform/src/package.rs"]
mod package;

const VALID_MANIFEST: &str = r#"
[package]
id = "org.mochios.ps2.i8042"
name = "i8042 Driver"
version = "1"

[[binary]]
path = "/bin/drivers/ps2/i8042.driver/entry.elf"
kind = "driver"
driver_class = "input"
api_version = 1
match_bus = "platform"
match_class = "i8042"
"#;

fn valid_manifest_contains_expected_entry() {
    let manifest = match package::parse_manifest(VALID_MANIFEST) {
        Some(manifest) => manifest,
        None => panic!("valid manifest was rejected"),
    };
    assert!(
        manifest
            .binary("/bin/drivers/ps2/i8042.driver/entry.elf")
            .is_some()
    );
}

fn missing_manifest_is_rejected() {
    assert!(package::read_manifest("/missing/manifest.toml").is_none());
}

fn invalid_manifest_is_rejected() {
    assert!(package::parse_manifest("[package]\nid = [invalid").is_none());
}

fn missing_required_manifest_field_is_rejected() {
    let missing_version = VALID_MANIFEST.replace("version = \"1\"\n", "");
    assert!(package::parse_manifest(&missing_version).is_none());
}

fn missing_entry_is_rejected_by_entry_lookup() {
    let manifest = match package::parse_manifest(VALID_MANIFEST) {
        Some(manifest) => manifest,
        None => panic!("valid manifest was rejected"),
    };
    assert!(
        manifest
            .binary("/bin/drivers/ps2/missing.driver/entry.elf")
            .is_none()
    );
}

fn main() {
    valid_manifest_contains_expected_entry();
    missing_manifest_is_rejected();
    invalid_manifest_is_rejected();
    missing_required_manifest_field_is_rejected();
    missing_entry_is_rejected_by_entry_lookup();
}
