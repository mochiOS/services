use std::{env, fs, path::PathBuf};

const DEVELOPMENT_ROOT_PUBLIC_KEY_HEX: &str =
    "65b3316dbc41b1fdc9a644155e3cc1eda8bd6926a6f33ec1ba2d8570abfbde27";

fn decode_public_key(value: &str) -> [u8; 32] {
    assert_eq!(
        value.len(),
        64,
        "Root public key must contain 64 hex characters"
    );
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("Root public key must be hexadecimal");
    }
    output
}

fn main() {
    println!("cargo:rerun-if-env-changed=MOCHIOS_DEVELOPER_ROOT_PUBLIC_KEYS_HEX");
    println!("cargo:rerun-if-env-changed=MOCHIOS_TRUST_DOMAIN");

    let configured_keys = env::var("MOCHIOS_DEVELOPER_ROOT_PUBLIC_KEYS_HEX").ok();
    let key_values = configured_keys
        .as_deref()
        .unwrap_or(DEVELOPMENT_ROOT_PUBLIC_KEY_HEX)
        .split([',', ':'])
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    assert!(
        !key_values.is_empty(),
        "at least one Root public key is required"
    );
    let public_keys = key_values
        .into_iter()
        .map(decode_public_key)
        .collect::<Vec<_>>();
    let trust_domain = env::var("MOCHIOS_TRUST_DOMAIN").unwrap_or_else(|_| {
        if configured_keys.is_some() {
            "custom".to_string()
        } else {
            "development".to_string()
        }
    });
    let key_bytes = public_keys
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
    let generated = format!(
        "pub const ROOT_PUBLIC_KEYS: &[[u8; 32]] = &[{key_bytes}];\n\
         pub const TRUST_DOMAIN: &str = {trust_domain:?};\n"
    );
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    fs::write(out_dir.join("trust_anchor.rs"), generated)
        .expect("failed to write embedded trust anchor");
}
