//! Exact, per-user remembered execution consent. Records never authenticate
//! code: every lookup follows the normal immutable-source/manifest selection.
use alloc::vec::Vec;
use mochi_user_platform::syscall::{NativeError, SysError};
use sha2::{Digest, Sha256};

use crate::{consent_peer::Peer, resolver::ApplicationIdentity};

#[cfg(not(test))]
#[path = "execution_grant/native.rs"]
mod io;
#[cfg(test)]
use crate::execution_grant_io as io;

const MAGIC: &[u8; 8] = b"MEXGRNT1";
const HEADER: usize = 16;
const RECORD: usize = 104;
const CHECKSUM: usize = 32;
const MAX_RECORDS: usize = 4096;
pub(crate) const MAX_BYTES: usize = HEADER + MAX_RECORDS * RECORD + CHECKSUM;

fn error(value: NativeError) -> SysError {
    SysError::from(value.into_raw())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Key {
    uid: u32,
    source: [u8; 32],
    requirements: [u8; 32],
    identity: [u8; 32],
}
impl Key {
    pub(crate) fn new(
        uid: u32,
        identity: &ApplicationIdentity,
        capabilities: &[alloc::string::String],
        source: [u8; 32],
    ) -> Result<Self, SysError> {
        let mut digest = Sha256::new();
        digest.update(b"mochiOS remembered execution subject v1\0");
        for field in [
            identity.package_id.as_bytes(),
            identity.developer_id.as_bytes(),
        ] {
            if field.is_empty() || field.len() > mnu_abi::APPLICATION_ID_FIELD_LEN {
                return Err(error(NativeError::InvalidArgument));
            }
            digest.update((field.len() as u32).to_le_bytes());
            digest.update(field);
        }
        digest.update(identity.subject_key_id);
        digest.update([identity.provenance as u8]);
        Ok(Self {
            uid,
            source,
            // An invocation's opaque exec key is deliberately excluded. It
            // remains bound separately by the native one-shot authorization.
            requirements: crate::execution_approval::requirements("", capabilities)?,
            identity: digest.finalize().into(),
        })
    }
    pub(crate) fn uid(self) -> u32 {
        self.uid
    }
}

pub(crate) fn requester_uid(peer: &Peer) -> Result<u32, SysError> {
    io::requester_uid(peer)
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"mochiOS remembered execution database v1\0");
    digest.update(bytes);
    digest.finalize().into()
}

/// Strict canonical records and a whole-file checksum reject partial writes,
/// unknown formats and accidental corruption; only the broker may write it.
pub(crate) fn decode(bytes: &[u8]) -> Result<Vec<Key>, SysError> {
    let invalid = || error(NativeError::InvalidFormat);
    if bytes.len() < HEADER + CHECKSUM
        || bytes.len() > MAX_BYTES
        || &bytes[..8] != MAGIC
        || bytes[12..16] != [0; 4]
    {
        return Err(invalid());
    }
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if count > MAX_RECORDS || HEADER + count * RECORD + CHECKSUM != bytes.len() {
        return Err(invalid());
    }
    let end = bytes.len() - CHECKSUM;
    if bytes[end..] != checksum(&bytes[..end]) {
        return Err(invalid());
    }
    let mut keys = Vec::new();
    keys.try_reserve_exact(count)
        .map_err(|_| error(NativeError::ResourceUnavailable))?;
    for record in bytes[HEADER..end].chunks_exact(RECORD) {
        if record[4..8] != [0; 4] {
            return Err(invalid());
        }
        let key = Key {
            uid: u32::from_le_bytes(record[..4].try_into().unwrap()),
            source: record[8..40].try_into().unwrap(),
            requirements: record[40..72].try_into().unwrap(),
            identity: record[72..104].try_into().unwrap(),
        };
        if keys.last().is_some_and(|previous| previous >= &key) {
            return Err(invalid());
        }
        keys.push(key);
    }
    Ok(keys)
}

fn encode(keys: &[Key]) -> Result<Vec<u8>, SysError> {
    if keys.len() > MAX_RECORDS || keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(error(NativeError::LimitExceeded));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(HEADER + keys.len() * RECORD + CHECKSUM)
        .map_err(|_| error(NativeError::ResourceUnavailable))?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    for key in keys {
        bytes.extend_from_slice(&key.uid.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&key.source);
        bytes.extend_from_slice(&key.requirements);
        bytes.extend_from_slice(&key.identity);
    }
    let digest = checksum(&bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn load() -> Result<Vec<Key>, SysError> {
    match io::read()? {
        Some(bytes) => decode(&bytes),
        None => Ok(Vec::new()),
    }
}

pub(crate) fn contains(key: Key) -> Result<bool, SysError> {
    Ok(load()?.binary_search(&key).is_ok())
}

/// Only a consumed Always approval reaches this function. Failure is returned
/// to the original caller; it never degrades into a successful Allow Once.
pub(crate) fn remember(key: Key) -> Result<(), SysError> {
    let mut keys = load()?;
    let index = match keys.binary_search(&key) {
        Ok(_) => return Ok(()),
        Err(index) => index,
    };
    if keys.len() == MAX_RECORDS {
        return Err(error(NativeError::LimitExceeded));
    }
    keys.try_reserve(1)
        .map_err(|_| error(NativeError::ResourceUnavailable))?;
    keys.insert(index, key);
    io::replace(&encode(&keys)?)
}
