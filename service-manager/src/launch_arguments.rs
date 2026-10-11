use alloc::{string::String, vec, vec::Vec};

// Bounds of the existing native manifest-launch metadata block. This encoder
// must never drop security identity or inherited-handle entries to fit it.
const MAX_BYTES: usize = 4096;
const MAX_ENTRIES: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EncodeError {
    TooLarge,
    InvalidEntry,
    Startup(mochios_posix_client::process_image::EncodeError),
    Creation(mnu_abi::process_create::Error),
}

/// Convert launcher policy into opaque native creation metadata. Authorization
/// identity is supplied separately; untrusted argv cannot set security policy.
/// The kernel checks source ownership, TRANSFER and rights attenuation later.
pub(crate) fn encode_native_launch(
    identity: &str,
    argument_zero: &str,
    items: &[String],
    random: [u8; 16],
) -> Result<Vec<u8>, EncodeError> {
    use mnu_abi::exec::{ENVIRONMENT_PREFIX, INHERITED_HANDLE_PREFIX, INHERITED_VALUE_PREFIX};
    use mnu_abi::process_create::{self, HandleGrant, Value};

    if argument_zero.is_empty() || argument_zero.as_bytes().contains(&0) {
        return Err(EncodeError::InvalidEntry);
    }
    let mut arguments = vec![argument_zero.as_bytes()];
    let mut environment = Vec::new();
    let mut handles: Vec<HandleGrant> = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    for item in items {
        if item.as_bytes().contains(&0) {
            return Err(EncodeError::InvalidEntry);
        }
        if let Some(entry) = item.strip_prefix(ENVIRONMENT_PREFIX) {
            let (name, _) = entry.split_once('=').ok_or(EncodeError::InvalidEntry)?;
            if name.is_empty() {
                return Err(EncodeError::InvalidEntry);
            }
            environment.push(entry.as_bytes());
        } else if let Some(entry) = item.strip_prefix(INHERITED_HANDLE_PREFIX) {
            let mut fields = entry.split(':');
            let key = decimal(fields.next())?;
            let source =
                u32::try_from(decimal(fields.next())?).map_err(|_| EncodeError::InvalidEntry)?;
            let rights = decimal(fields.next())?;
            if fields.next().is_some()
                || source == 0
                || rights & !mnu_abi::HANDLE_RIGHT_ALL != 0
                || handles.iter().any(|previous| previous.key == key)
            {
                return Err(EncodeError::InvalidEntry);
            }
            if handles.len() >= process_create::MAX_HANDLES {
                return Err(EncodeError::TooLarge);
            }
            handles.push(HandleGrant {
                key,
                source,
                rights,
            });
        } else if let Some(entry) = item.strip_prefix(INHERITED_VALUE_PREFIX) {
            let mut fields = entry.split(':');
            let key = decimal(fields.next())?;
            let value = decimal(fields.next())?;
            if fields.next().is_some() || values.iter().any(|previous| previous.key == key) {
                return Err(EncodeError::InvalidEntry);
            }
            if values.len() >= process_create::MAX_VALUES {
                return Err(EncodeError::TooLarge);
            }
            values.push(Value { key, value });
        } else if item.starts_with("__MNU_EXEC_") {
            // Legacy identity/digest fields must not become ordinary argv or
            // grant authorization. Native creation consumes a separate permit.
            return Err(EncodeError::InvalidEntry);
        } else {
            // Empty argv entries are legal, unlike legacy metadata delimiters.
            arguments.push(item.as_bytes());
        }
    }
    let mut startup = vec![0; process_create::MAX_REQUEST_BYTES];
    let length = mochios_posix_client::process_image::encode_initial_stack(
        &arguments,
        &environment,
        identity.as_bytes(),
        random,
        &mut startup,
    )
    .map_err(EncodeError::Startup)?;
    let mut metadata = vec![0; process_create::MAX_REQUEST_BYTES];
    let length = process_create::encode(
        identity,
        argument_zero,
        &startup[..length],
        &handles,
        &values,
        &mut metadata,
    )
    .map_err(EncodeError::Creation)?;
    metadata.truncate(length);
    Ok(metadata)
}

fn decimal(field: Option<&str>) -> Result<u64, EncodeError> {
    let field = field.ok_or(EncodeError::InvalidEntry)?;
    if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EncodeError::InvalidEntry);
    }
    field.parse().map_err(|_| EncodeError::InvalidEntry)
}

pub(crate) fn encode_spawn_args(items: &[String]) -> Result<Vec<u8>, EncodeError> {
    if items.len() > MAX_ENTRIES {
        return Err(EncodeError::TooLarge);
    }
    let mut length = 1usize; // Additional NUL terminates the entire list.
    for item in items {
        if item.is_empty() || item.as_bytes().contains(&0) {
            return Err(EncodeError::InvalidEntry);
        }
        length = length
            .checked_add(item.len())
            .and_then(|length| length.checked_add(1))
            .filter(|length| *length <= MAX_BYTES)
            .ok_or(EncodeError::TooLarge)?;
    }
    let mut output = vec![0; MAX_BYTES];
    let mut cursor = 0;
    for item in items {
        output[cursor..cursor + item.len()].copy_from_slice(item.as_bytes());
        cursor += item.len() + 1;
    }
    Ok(output)
}
