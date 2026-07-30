use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

const DEVELOPMENT_ROOT_PUBLIC_KEY_HEX: &str =
    "65b3316dbc41b1fdc9a644155e3cc1eda8bd6926a6f33ec1ba2d8570abfbde27";

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
