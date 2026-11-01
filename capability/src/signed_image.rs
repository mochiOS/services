//! Bounded integrity verification of explicitly delegated native RAM images.
use alloc::vec::Vec;
use mochi_user_platform as p;
use mochi_user_syscall::{EACCES, EINVAL, NativeError, SysError};
use mochios_elf_signature::{
    PublicKeyResolver, SignatureKind, SuppliedPublicKey, VerificationLimits, verify_image,
};

const MAX_IMAGE: usize = mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES;
const MAX_HEADERS: usize = 4096;
const MAX_SCAN: usize = 1024 * 1024;
const CHUNK: usize = 256 * 1024;

pub(crate) fn authorize(
    sender: u64,
    bytes: &[u8],
    attached: &p::ipc::IpcObjectHandles,
) -> Result<(), SysError> {
    let request = p::capability::signed_image::decode(bytes)
        .map_err(|_| SysError::from_raw(EINVAL as i64))?;
    if !attached.is_user_delivery() || attached.count != 1 {
        return Err(SysError::from_raw(EINVAL as i64));
    }
    let object = attached.handles[0];
    if object.handle == 0 || object.reserved != 0 {
        return Err(SysError::from_raw(EINVAL as i64));
    }
    if object.rights != p::memory_object::READONLY_BUFFER_RIGHTS
        || p::capability::check_thread(sender, "process.spawn") != Ok(1)
    {
        return Err(SysError::from_raw(EACCES as i64));
    }
    let length = usize::try_from(request.source_length)
        .ok()
        .filter(|n| *n != 0 && *n <= MAX_IMAGE)
        .ok_or_else(|| SysError::from_raw(EINVAL as i64))?;
    // This generic native query accepts RAM backing only. In particular it
    // rejects both ordinary Providers and Provider-backed VM objects without
    // invoking their owner. Never read an untrusted Provider in this broker.
    if p::memory::object_length(object.handle as u64)? != request.source_length {
        return Err(SysError::from_raw(EINVAL as i64));
    }
    let mut snapshot = Vec::new();
    snapshot
        .try_reserve_exact(length)
        .map_err(|_| SysError::from(NativeError::ResourceUnavailable.into_raw()))?;
    snapshot.resize(length, 0);
    let mut offset = 0;
    while offset < length {
        let end = length.min(offset + CHUNK);
        let count = p::handle::read_at(object.handle, &mut snapshot[offset..end], offset as u64)?;
        if count == 0 || count > end - offset {
            return Err(SysError::from(NativeError::BackingFailure.into_raw()));
        }
        offset += count;
    }
    let mut extra = [0];
    if p::handle::read_at(object.handle, &mut extra, length as u64)? != 0
        || p::memory::object_length(object.handle as u64)? != request.source_length
    {
        return Err(SysError::from(NativeError::BackingFailure.into_raw()));
    }
    let key = request
        .public_key
        .map(SuppliedPublicKey::new)
        .transpose()
        .map_err(|_| SysError::from_raw(EACCES as i64))?;
    let evidence = verify_image(
        &snapshot,
        key.as_ref().map(|k| k as &dyn PublicKeyResolver),
        &VerificationLimits {
            max_image_bytes: MAX_IMAGE,
            max_section_headers: MAX_HEADERS,
            max_program_headers: MAX_HEADERS,
            max_note_scan_bytes: MAX_SCAN,
            max_name_scan_bytes: MAX_SCAN,
        },
    )
    .map_err(|_| SysError::from_raw(EACCES as i64))?;
    // A supplied key must actually have verified the signature. Neither kind
    // establishes developer trust, an identity override, or additional grants.
    if key.is_some() && evidence.signature().kind != SignatureKind::Ed25519 {
        return Err(SysError::from_raw(EACCES as i64));
    }
    crate::object_image::authorize_inherited_digest(
        sender,
        request.identity,
        evidence.source_digest(),
    )
}
