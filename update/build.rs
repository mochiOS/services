use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use base64::{Engine as _, engine::general_purpose::STANDARD};

const DEVELOPMENT_ROOT_PUBLIC_KEY_HEX: &str =
    "fa28925b7ff0727ba081679e31af05a87f1b3cda98dda5900c1371695cdef56b";
// Public release-manifest verification key. The private signing key must never
// be present in this repository or in an OS build environment.
const RELEASE_PUBLIC_KEYS: &str =
    "release-2026-01:MCowBQYDK2VwAyEA7Gh+xoUEQsOF3HoZXK+y4OtZcx9xa/oWhnK6+JP7Hbg=";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=MOCHIOS_DEVELOPER_ROOT_PUBLIC_KEYS_HEX");
    let configured = env::var("MOCHIOS_DEVELOPER_ROOT_PUBLIC_KEYS_HEX").ok();
    let values = configured
        .as_deref()
        .unwrap_or(DEVELOPMENT_ROOT_PUBLIC_KEY_HEX);
    let mut roots = Vec::new();
    for value in values.split(',') {
        let value = value.trim();
        if value.is_empty() {
            return Err("Developer Root public key list contains an empty entry".into());
        }
        let root = decode_public_key(value)?;
        if roots.contains(&root) {
            return Err("Developer Root public key list contains a duplicate key".into());
        }
        roots.push(root);
    }
    if roots.is_empty() {
        return Err("at least one Developer Root public key is required".into());
    }

    let key_bytes = roots
        .iter()
        .map(|key| {
            let bytes = key
                .iter()
                .map(|byte| format!("0x{byte:02x}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{bytes}]")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let domain = if configured.is_some() {
        "configured"
    } else {
        "development"
    };
    let generated = format!(
        "pub const DEVELOPER_ROOT_PUBLIC_KEYS: &[[u8; 32]] = &[{key_bytes}];\n\
         pub const DEVELOPER_TRUST_DOMAIN: &str = {domain:?};\n"
    );
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(out_dir.join("developer_root_keys.rs"), generated)?;
    println!("cargo:rerun-if-env-changed=MOCHIOS_RELEASE_PUBLIC_KEYS");
    let configured_releases = env::var("MOCHIOS_RELEASE_PUBLIC_KEYS")
        .unwrap_or_else(|_| RELEASE_PUBLIC_KEYS.to_owned());
    if configured_releases.trim().is_empty() {
        return Err("release public key list must not be empty".into());
    }
    let mut release_keys = Vec::new();
    for entry in configured_releases.split(',') {
        let (key_id, spki) = entry.split_once(':').ok_or("release key entry requires key_id:base64-SPKI")?;
        if key_id.is_empty() || key_id.len() > 64
            || !key_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || release_keys.iter().any(|(existing, _): &(String, [u8; 32])| existing == key_id)
        {
            return Err("release key ID is invalid or duplicated".into());
        }
        let der = STANDARD.decode(spki)?;
        const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        if der.len() != 44 || !der.starts_with(&ED25519_SPKI_PREFIX) {
            return Err("release key must be a 44-byte Ed25519 SPKI public key".into());
        }
        let mut key = [0; 32];
        key.copy_from_slice(&der[12..]);
        release_keys.push((key_id.to_owned(), key));
    }
    let entries = release_keys.iter().map(|(id, key)| {
        let bytes = key.iter().map(|byte| format!("0x{byte:02x}")).collect::<Vec<_>>().join(", ");
        format!("crate::os_update::TrustedKey {{ key_id: {id:?}, public_key: [{bytes}] }}")
    }).collect::<Vec<_>>().join(", ");
    fs::write(
        out_dir.join("release_public_keys.rs"),
        format!("pub const RELEASE_PUBLIC_KEYS: &[crate::os_update::TrustedKey] = &[{entries}];\n"),
    )?;
    Ok(())
}

fn decode_public_key(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(
            "Developer Root public key must contain exactly 64 hexadecimal characters".into(),
        );
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(output)
}
