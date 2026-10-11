use mochi_user_platform::package;

const VALID_MANIFEST: &str = r#"
[package]
id = "org.mochios.ps2.i8042"
name = "i8042 Driver"
version = "1"

[[binary]]
path = "/system/bin/drivers/ps2/i8042.driver/entry.elf"
kind = "driver"
driver_class = "input"
api_version = 1
match_bus = "platform"
match_class = "i8042"
"#;

#[test]
fn valid_manifest_contains_expected_entry() {
    let manifest = match package::parse_manifest(VALID_MANIFEST) {
        Some(manifest) => manifest,
        None => panic!("valid manifest was rejected"),
    };
    assert!(
        manifest
            .binary("/system/bin/drivers/ps2/i8042.driver/entry.elf")
            .is_some()
    );
}

#[test]
fn invalid_manifest_is_rejected() {
    assert!(package::parse_manifest("[package]\nid = [invalid").is_none());
}

#[test]
fn missing_required_manifest_field_is_rejected() {
    let missing_version = VALID_MANIFEST.replace("version = \"1\"\n", "");
    assert!(package::parse_manifest(&missing_version).is_none());
}

#[test]
fn missing_entry_is_rejected_by_entry_lookup() {
    let manifest = match package::parse_manifest(VALID_MANIFEST) {
        Some(manifest) => manifest,
        None => panic!("valid manifest was rejected"),
    };
    assert!(
        manifest
            .binary("/system/bin/drivers/ps2/missing.driver/entry.elf")
            .is_none()
    );
}
