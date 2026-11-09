//! Best-effort diagnostics after source authentication. Failure cannot grant
//! code authority or turn a denied launch into a successful one.
use crate::image_catalog::Catalog;
use mochi_user_platform as p;
use mochios_posix_client::{loaded_objects, pie::Pie};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn module(catalog: &Catalog, name: &[u8], bias: u64, headers: &[u8]) -> Option<Value> {
    if headers.len() / 56 > 64 {
        return None;
    }
    let (path, digest) = catalog.diagnostic_input(name)?;
    let mut ranges = Vec::new();
    for header in headers.chunks_exact(56) {
        if u32::from_le_bytes(header[..4].try_into().ok()?) != 1 {
            continue;
        }
        let address = u64::from_le_bytes(header[16..24].try_into().ok()?);
        let size = u64::from_le_bytes(header[40..48].try_into().ok()?);
        let start = bias.checked_add(address)?;
        ranges.push(json!({"start":start, "end":start.checked_add(size)?,
            "flags":u32::from_le_bytes(header[4..8].try_into().ok()?)}));
    }
    Some(json!({"path":path, "source_sha256":hex(&digest), "load_bias":bias, "ranges":ranges}))
}

pub(crate) fn publish(
    process: u32,
    revision: u64,
    catalog: &Catalog,
    source: &[u8],
    output: &[u8],
    loaded: &[u8],
    bias: u64,
) -> Result<(), p::syscall::SysError> {
    let invalid = || p::syscall::SysError::from_raw(p::syscall::EIO as i64);
    let mut modules = Vec::new();
    let mut complete = true;
    if !loaded.is_empty() {
        let objects = loaded_objects::Image::parse(loaded).map_err(|_| invalid())?;
        if objects.count() > 128 {
            return Err(invalid());
        }
        for index in 0..objects.count() {
            let object = objects.entry(index).map_err(|_| invalid())?;
            if let Some(value) = module(catalog, object.name, object.bias, object.headers) {
                modules.push(value);
            } else {
                complete = false;
            }
        }
    } else {
        let image = Pie::parse_object(source).map_err(|_| invalid())?;
        if let Some(root) = module(catalog, &[], bias, image.inspection().0) {
            modules.push(root);
        }
        // An ELF interpreter can subsequently load objects independently.
        complete = mochios_posix_client::elf_launch::interpreter(source)
            .map_err(|_| invalid())?
            .is_none();
    }
    let (name, version) = catalog.diagnostic_package();
    let body = json!({"schema_version":1, "image_revision":revision,
        "native_image_sha256":hex(&Sha256::digest(output)),
        "package_id":catalog.identity().package_id,
        "package_name":name, "package_version":version,
        "modules":modules, "initial_modules_complete":complete,
        "later_dynamic_loads_captured":false});
    let bytes = serde_json::to_vec(&body).map_err(|_| invalid())?;
    p::diagnostic::register_image(process, &bytes)
}
