use alloc::{string::String, vec, vec::Vec};

// Bounds of the existing native manifest-launch metadata block. This encoder
// must never drop security identity or inherited-handle entries to fit it.
const MAX_BYTES: usize = 4096;
const MAX_ENTRIES: usize = 64;

pub(crate) use mochios_posix_client::launch_arguments::{EncodeError, encode_native_launch};

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
