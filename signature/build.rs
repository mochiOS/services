use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

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
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing manifest dir"));
    println!(
        "cargo:rustc-link-arg=-T{}/linker.ld",
        manifest_dir.display()
    );
    println!(
        "cargo:rerun-if-changed={}/linker.ld",
        manifest_dir.display()
    );
    println!("cargo:rerun-if-env-changed=MOCHIOS_ROOT_PUBLIC_KEY_HEX");
    println!("cargo:rerun-if-env-changed=MOCHIOS_ROOT_PUBLIC_KEYS_HEX");
    println!("cargo:rerun-if-env-changed=MOCHIOS_REVOKED_CERTIFICATE_SERIALS");
    println!("cargo:rerun-if-env-changed=MOCHIOS_TRUST_DOMAIN");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let configured_keys = env::var("MOCHIOS_ROOT_PUBLIC_KEYS_HEX")
        .ok()
        .or_else(|| env::var("MOCHIOS_ROOT_PUBLIC_KEY_HEX").ok());
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
    let build_unix_time = env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before Unix epoch")
                .as_secs()
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
    let mut revoked_serials = env::var("MOCHIOS_REVOKED_CERTIFICATE_SERIALS")
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .trim()
                .parse::<u64>()
                .expect("revoked certificate serial must be an unsigned integer")
        })
        .collect::<Vec<_>>();
    revoked_serials.sort_unstable();
    revoked_serials.dedup();
    let revoked_serials = revoked_serials
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let generated = format!(
        "pub const ROOT_PUBLIC_KEYS: &[[u8; 32]] = &[{key_bytes}];\n\
         pub const REVOKED_CERTIFICATE_SERIALS: &[u64] = &[{revoked_serials}];\n\
         pub const TRUST_DOMAIN: &str = {trust_domain:?};\n\
         pub const BUILD_UNIX_TIME: u64 = {build_unix_time};\n"
    );
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    fs::write(out_dir.join("trust_anchor.rs"), generated)
        .expect("failed to write embedded trust anchor");
}
