//! Bounded, incremental payload verification. Not wired to the current HTTP
//! service: it buffers whole responses and must be replaced before downloads.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};
use crate::os_update::VerifiedManifest;

#[derive(Debug)]
pub enum StageError {
    Io(io::Error),
    InvalidSize,
    Truncated,
    TooLarge,
    Checksum,
    DestinationExists,
}

impl From<io::Error> for StageError {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

pub fn decode_sha256_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        return None;
    }
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(result)
}

/// Consume exactly `size` bytes, then require EOF. RAM use is bounded by one
/// small buffer regardless of the artifact size.
pub fn copy_verified<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    size: u64,
    expected_sha256: &[u8; 32],
) -> Result<(), StageError> {
    if size == 0 { return Err(StageError::InvalidSize); }
    let mut digest = Sha256::new();
    let mut remaining = size;
    let mut buffer = [0u8; 16 * 1024];
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = source.read(&mut buffer[..wanted])?;
        if read == 0 { return Err(StageError::Truncated); }
        destination.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    if source.read(&mut buffer[..1])? != 0 { return Err(StageError::TooLarge); }
    let actual = digest.finalize();
    let difference = actual.iter().zip(expected_sha256).fold(0u8, |difference, (a, b)| difference | (a ^ b));
    if difference != 0 { return Err(StageError::Checksum); }
    Ok(())
}

/// Atomically publish a verified temporary payload on the same filesystem.
/// The caller must still have verified the signed manifest before invoking it.
pub(crate) fn stage_verified<R: Read>(
    source: &mut R,
    destination: &Path,
    size: u64,
    expected_sha256: &[u8; 32],
) -> Result<(), StageError> {
    if destination.exists() { return Err(StageError::DestinationExists); }
    let temporary = destination.with_extension("partial");
    let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
    let result = (|| {
        copy_verified(source, &mut file, size, expected_sha256)?;
        file.sync_all()?;
        // The update service is single-instance. Recheck before publication;
        // the OS filesystem currently exposes rename but not hard-link.
        if destination.exists() { return Err(StageError::DestinationExists); }
        fs::rename(&temporary, destination)?;
        if let Some(parent) = destination.parent() {
            OpenOptions::new().read(true).open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

/// Stage only bytes described by an already-verified release manifest. The
/// artifact filename is never used as a local path.
pub fn stage_signed_update<R: Read>(
    source: &mut R,
    destination: &Path,
    manifest: &VerifiedManifest,
) -> Result<(), StageError> {
    stage_verified(source, destination, manifest.size_bytes(), manifest.sha256())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_and_verifies_exact_bytes() {
        let bytes = b"ordinary-update-payload";
        let expected: [u8; 32] = Sha256::digest(bytes).into();
        let mut output = Vec::new();
        assert!(copy_verified(&mut bytes.as_slice(), &mut output, bytes.len() as u64, &expected).is_ok());
        assert_eq!(output, bytes);
        assert!(matches!(copy_verified(&mut b"short".as_slice(), &mut Vec::new(), 6, &expected), Err(StageError::Truncated)));
        assert!(matches!(copy_verified(&mut b"long".as_slice(), &mut Vec::new(), 3, &expected), Err(StageError::TooLarge)));
        assert!(matches!(copy_verified(&mut bytes.as_slice(), &mut Vec::new(), bytes.len() as u64, &[0; 32]), Err(StageError::Checksum)));
    }

    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::Error::other("disk full")) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn write_failure_is_not_accepted() {
        let bytes = b"payload";
        let expected: [u8; 32] = Sha256::digest(bytes).into();
        assert!(matches!(copy_verified(&mut bytes.as_slice(), &mut FailingWriter, bytes.len() as u64, &expected), Err(StageError::Io(_))));
        assert!(decode_sha256_hex(&"a".repeat(64)).is_some());
        assert!(decode_sha256_hex(&"A".repeat(64)).is_none());
    }

    #[test]
    fn rejected_payload_does_not_leave_a_published_file() {
        let directory = std::env::temp_dir().join(format!(
            "mochios-update-stage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        ));
        fs::create_dir(&directory).unwrap();
        let destination = directory.join("payload.bin");
        let mut bytes = b"tampered".as_slice();
        assert!(matches!(stage_verified(&mut bytes, &destination, 8, &[0; 32]), Err(StageError::Checksum)));
        assert!(!destination.exists());
        assert!(!directory.join("payload.partial").exists());
        fs::remove_dir(&directory).unwrap();
    }
}
