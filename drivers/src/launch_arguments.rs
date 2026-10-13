use alloc::{string::String, vec, vec::Vec};

const MAX_BYTES: usize = 4096;
const MAX_ENTRIES: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EncodeError {
    TooLarge,
    InvalidEntry,
}

/// Preserve the whole launch transaction or reject it. Security identity and
/// ordinary arguments share the legacy block; truncation can drop either.
pub(crate) fn encode_spawn_args(items: &[String]) -> Result<Vec<u8>, EncodeError> {
    if items.len() > MAX_ENTRIES {
        return Err(EncodeError::TooLarge);
    }
    let mut length = 1usize;
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
    // ExecManifest reads its fixed-size block, not the used payload length.
    let mut output = vec![0; MAX_BYTES];
    let mut cursor = 0;
    for item in items {
        output[cursor..cursor + item.len()].copy_from_slice(item.as_bytes());
        cursor += item.len() + 1;
    }
    Ok(output)
}
