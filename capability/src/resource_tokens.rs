//! Startup-scoped resource authority. Text is never a grant, and a token is
//! useful only to the measured code and publisher for which it was issued.
use crate::{
    image_catalog::{Catalog, ResourceSet},
    resolver::ApplicationIdentity,
};
use mochi_user_platform as p;
use mochios_posix_client::{ObjectHandleAttachment, OpenAtBase};
use p::capability::resources as wire;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};
type Error = p::syscall::SysError;
const RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
struct Grant {
    identity: ApplicationIdentity,
    image: [u8; 32],
    sets: Vec<ResourceSet>,
    executable_owner: Option<(crate::resolver::VerifiedManifest, String)>,
}
struct Registry {
    endpoint: u32,
    next: u64,
    grants: BTreeMap<u64, Grant>,
}
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
fn error(code: i64) -> Error {
    Error::from_raw(code)
}
pub(crate) fn initialize(endpoint: u32) -> Result<(), Error> {
    REGISTRY
        .set(Mutex::new(Registry {
            endpoint,
            next: 1,
            grants: BTreeMap::new(),
        }))
        .map_err(|_| error(-5))
}
pub(crate) struct Token {
    handle: u32,
    endpoint: u32,
}
impl Drop for Token {
    fn drop(&mut self) {
        let _ = p::handle::close(self.handle);
    }
}
impl Token {
    pub(crate) fn handles(&self) -> [mnu_abi::process_create::HandleGrant; 2] {
        use mnu_abi::process_create::HandleGrant;
        [
            HandleGrant {
                key: wire::ROOT_KEY,
                source: self.handle,
                target: 0,
                rights: RIGHTS,
            },
            HandleGrant {
                key: wire::CONTROL_KEY,
                source: self.endpoint,
                target: 0,
                rights: mnu_abi::HANDLE_RIGHT_SEND | RIGHTS,
            },
        ]
    }
}
/// Called only by the trusted launcher after catalog verification. No public
/// request can issue a token from arbitrary manifest or digest text.
pub(crate) fn issue(catalog: &Catalog, prepared: &[u8]) -> Result<Option<Token>, Error> {
    let sets = catalog.resource_sets();
    if sets.is_empty() {
        return Ok(None);
    }
    let mutex = REGISTRY.get().ok_or_else(|| error(-11))?;
    let mut registry = mutex.lock().map_err(|_| error(-5))?;
    if registry.grants.len() >= 256
        || registry
            .grants
            .values()
            .map(|g| g.sets.iter().map(|s| s.files.len()).sum::<usize>())
            .sum::<usize>()
            + sets.iter().map(|s| s.files.len()).sum::<usize>()
            > 65536
    {
        return Err(error(-28));
    }
    let id = registry.next;
    registry.next = id
        .checked_add(1)
        .filter(|next| *next < 1u64 << 62)
        .ok_or_else(|| error(-28))?;
    let handle = p::handle::create_provider_object(registry.endpoint, id, RIGHTS)?;
    let endpoint = registry.endpoint;
    registry.grants.insert(
        id,
        Grant {
            identity: catalog.identity().clone(),
            image: Sha256::digest(prepared).into(),
            sets,
            executable_owner: catalog.executable_owner(),
        },
    );
    Ok(Some(Token { handle, endpoint }))
}
fn matches(
    grant: &Grant,
    context: &p::syscall::ThreadSecurityContext,
    image: &p::syscall::ProcessImageInfo,
) -> bool {
    matches_identity(&grant.identity, &grant.image, context, image)
}
pub(crate) fn matches_identity(
    identity: &ApplicationIdentity,
    digest: &[u8; 32],
    context: &p::syscall::ThreadSecurityContext,
    image: &p::syscall::ProcessImageInfo,
) -> bool {
    let provenance = match identity.provenance {
        mochios_signature_protocol::InstallProvenance::BuiltIn => 1,
        mochios_signature_protocol::InstallProvenance::VerifiedPackage => 2,
        mochios_signature_protocol::InstallProvenance::Development => 3,
    };
    image.digest_kind == p::syscall::PROCESS_IMAGE_DIGEST_SHA256
        && image.digest == *digest
        && context.package_id.get(..context.package_id_len as usize)
            == Some(identity.package_id.as_bytes())
        && context
            .developer_id
            .get(..context.developer_id_len as usize)
            == Some(identity.developer_id.as_bytes())
        && context.subject_key_id == identity.subject_key_id
        && context.provenance == provenance
}
/// Validate native startup authority before exposing its retained signed plan.
pub(crate) fn executable_owner(
    sender: u64,
    attached: &p::ipc::IpcObjectHandles,
) -> Result<(crate::resolver::VerifiedManifest, String), Error> {
    if !attached.is_user_delivery() || attached.count != 1 {
        return Err(error(-13));
    }
    let token = attached.handles[0];
    if token.handle == 0 || token.reserved != 0 || token.rights != mnu_abi::HANDLE_RIGHT_TRANSFER {
        return Err(error(-13));
    }
    let id = p::handle::identify_provider_object(token.handle)?;
    let peer = p::execution_peer::capture(sender)?;
    let registry = REGISTRY
        .get()
        .ok_or_else(|| error(-13))?
        .lock()
        .map_err(|_| error(-5))?;
    let grant = registry.grants.get(&id).ok_or_else(|| error(-13))?;
    if !matches(grant, &peer.context, &peer.image) {
        return Err(error(-13));
    }
    grant.executable_owner.clone().ok_or_else(|| error(-13))
}

/// Receiver-only native release is the sole authority to retire a grant.
pub(crate) fn release(bytes: &[u8], attached: &p::ipc::IpcObjectHandles) -> bool {
    let Ok((header, payload)) = mnu_abi::provider::RequestHeader::decode(bytes) else {
        return false;
    };
    if attached.delivery_flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
        || attached.count != 0
        || header.opcode != mnu_abi::provider::OP_RELEASE
        || !payload.is_empty()
    {
        return false;
    }
    if let Some(registry) = REGISTRY.get()
        && let Ok(mut registry) = registry.lock()
    {
        registry.grants.remove(&header.object_id);
    }
    true
}
/// Returns an owned normal filesystem reference, or no reference for CHECK.
pub(crate) fn request(
    sender: u64,
    bytes: &[u8],
    attached: &p::ipc::IpcObjectHandles,
) -> Result<Option<ObjectHandleAttachment<u32>>, Error> {
    if !attached.is_user_delivery() || attached.count != 1 {
        return Err(error(-13));
    }
    let token = attached.handles[0];
    if token.handle == 0 || token.reserved != 0 || token.rights != mnu_abi::HANDLE_RIGHT_TRANSFER {
        return Err(error(-13));
    }
    let id = p::handle::identify_provider_object(token.handle)?;
    let request = wire::decode(bytes).map_err(|_| error(-22))?;
    let peer = p::execution_peer::capture(sender)?;
    let set = {
        let registry = REGISTRY
            .get()
            .ok_or_else(|| error(-13))?
            .lock()
            .map_err(|_| error(-5))?;
        let grant = registry.grants.get(&id).ok_or_else(|| error(-13))?;
        if !matches(grant, &peer.context, &peer.image) {
            return Err(error(-13));
        }
        grant
            .sets
            .iter()
            .find(|set| set.alias == request.alias)
            .ok_or_else(|| error(-13))?
            .clone()
    };
    if request.operation == wire::CHECK {
        return Ok(None);
    }
    let mut tree = mochios_filesystem_protocol::readonly_tree::begin();
    let mut count = 0;
    for file in &set.files {
        if request.operation == wire::OPEN && file.name != request.name {
            continue;
        }
        let limit = usize::try_from(file.size).map_err(|_| error(-27))?;
        if limit > 128 * 1024 * 1024 {
            return Err(error(-27));
        }
        let bytes = read_asset(&file.path, limit)?;
        // Use the retained snapshot, never a later package-index lookup.
        if bytes.len() != limit
            || !file
                .digest
                .eq_ignore_ascii_case(&alloc::format!("sha256:{:x}", Sha256::digest(&bytes)))
        {
            return Err(error(-13));
        }
        mochios_filesystem_protocol::readonly_tree::append(&mut tree, &file.name, &bytes)
            .map_err(|_| error(-27))?;
        count += 1;
    }
    if request.operation == wire::OPEN && count != 1 {
        return Err(error(-2));
    }
    let ram = crate::app_image::readonly(&tree)?;
    let root = crate::persistent_grant::with_client(|client| {
        client.create_readonly_tree(
            ObjectHandleAttachment {
                handle: ram.handle(),
                rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
            },
            tree.len(),
        )
    })?;
    struct Reference(u32);
    impl Drop for Reference {
        fn drop(&mut self) {
            let _ = p::handle::close(self.0);
        }
    }
    let owner = Reference(root.handle);
    let result = if request.operation == wire::DIRECTORY {
        root
    } else {
        crate::persistent_grant::with_client(|client| {
            client.open_at(
                OpenAtBase::Directory(root),
                mochios_posix_protocol::OPEN_READ,
                0,
                request.name,
            )
        })?
    };
    let result_owner = (result.handle != root.handle).then(|| Reference(result.handle));
    let after = p::execution_peer::capture(sender)?;
    if peer.image != after.image || peer.context != after.context {
        return Err(error(-13));
    }
    if let Some(owner) = result_owner {
        core::mem::forget(owner);
    } else {
        core::mem::forget(owner);
    }
    Ok(Some(result))
}

/// Walk canonical components through explicit directory references. Reject
/// symlinks at every step and nonregular final objects before any data read.
pub(crate) fn read_asset(path: &str, limit: usize) -> Result<Vec<u8>, Error> {
    read_with_mode(path, limit, 0)
}
pub(crate) fn read_code(path: &str, limit: usize, executable: bool) -> Result<Vec<u8>, Error> {
    read_with_mode(path, limit, if executable { 0o555 } else { 0o444 })
}
fn read_with_mode(path: &str, limit: usize, required_mode: u32) -> Result<Vec<u8>, Error> {
    use mochios_posix_protocol as flags;
    struct Reference(u32);
    impl Drop for Reference {
        fn drop(&mut self) {
            let _ = p::handle::close(self.0);
        }
    }
    let relative = path.strip_prefix('/').ok_or_else(|| error(-13))?;
    if !p::package::resources::valid_resource_name(relative) {
        return Err(error(-13));
    }
    let mut directory = crate::persistent_grant::with_client(|client| {
        client.open_at(
            OpenAtBase::ProcessRoot,
            flags::OPEN_READ | flags::OPEN_DIRECTORY | flags::OPEN_NOFOLLOW | flags::OPEN_NONBLOCK,
            0,
            "/",
        )
    })?;
    let mut owner = Reference(directory.handle);
    let parts: Vec<_> = relative.split('/').collect();
    let mut file = None;
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        let options = flags::OPEN_READ
            | flags::OPEN_NOFOLLOW
            | flags::OPEN_NONBLOCK
            | if last { 0 } else { flags::OPEN_DIRECTORY };
        let opened = crate::persistent_grant::with_client(|client| {
            client.open_at(OpenAtBase::Directory(directory), options, 0, part)
        })?;
        let opened_owner = Reference(opened.handle);
        if last {
            file = Some((opened, opened_owner));
            break;
        }
        directory = opened;
        owner = opened_owner;
    }
    let (file, _file_owner) = file.ok_or_else(|| error(-13))?;
    let status = crate::persistent_grant::with_client(|client| client.fstat(file))?;
    if status.mode & 0o170000 != 0o100000
        || status.mode & required_mode != required_mode
        || status.size != limit as i64
    {
        return Err(error(-13));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(limit).map_err(|_| error(-12))?;
    bytes.resize(limit, 0);
    let mut offset = 0;
    while offset < limit {
        let end = limit.min(offset + mnu_abi::provider::MAX_SHARED_READ_LEN);
        let n = p::handle::read_at(file.handle, &mut bytes[offset..end], offset as u64)?;
        if n == 0 || n > end - offset {
            return Err(error(-5));
        }
        offset += n;
    }
    // Detect appended bytes as well as truncation; the hash below binds the
    // captured content even when a privileged package update races this read.
    let mut probe = [0];
    if p::handle::read_at(file.handle, &mut probe, limit as u64)? != 0 {
        return Err(error(-13));
    }
    drop(owner);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn grant() -> Grant {
        Grant {
            identity: ApplicationIdentity {
                package_id: "org.example.app".into(),
                developer_id: "org.example.publisher".into(),
                subject_key_id: [7; 32],
                provenance: mochios_signature_protocol::InstallProvenance::VerifiedPackage,
            },
            image: [3; 32],
            sets: Vec::new(),
            executable_owner: None,
        }
    }
    fn peer() -> (
        p::syscall::ThreadSecurityContext,
        p::syscall::ProcessImageInfo,
    ) {
        let mut context = p::syscall::ThreadSecurityContext::default();
        context.provenance = 2;
        context.subject_key_id = [7; 32];
        let package = b"org.example.app";
        let developer = b"org.example.publisher";
        context.package_id_len = package.len() as u16;
        context.package_id[..package.len()].copy_from_slice(package);
        context.developer_id_len = developer.len() as u16;
        context.developer_id[..developer.len()].copy_from_slice(developer);
        (
            context,
            p::syscall::ProcessImageInfo {
                process_id: 10,
                image_revision: 0,
                digest_kind: p::syscall::PROCESS_IMAGE_DIGEST_SHA256,
                reserved: 0,
                digest: [3; 32],
            },
        )
    }
    #[test]
    fn token_requires_exact_measured_image_and_publisher_identity() {
        let grant = grant();
        let (context, image) = peer();
        assert!(matches(&grant, &context, &image));
        let mut changed = image;
        changed.digest[0] ^= 1;
        assert!(!matches(&grant, &context, &changed));
        changed = image;
        changed.digest_kind = 0;
        assert!(!matches(&grant, &context, &changed));
        for n in 0..5 {
            let mut changed = context;
            match n {
                0 => changed.subject_key_id[0] ^= 1,
                1 => changed.package_id_len -= 1,
                2 => changed.developer_id_len -= 1,
                3 => changed.provenance = 1,
                _ => changed.package_id[0] ^= 1,
            };
            assert!(!matches(&grant, &changed, &image));
        }
    }
    #[test]
    fn only_native_last_reference_release_can_retire_tokens() {
        initialize(0).unwrap();
        REGISTRY
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .grants
            .insert(42, grant());
        let header = mnu_abi::provider::RequestHeader {
            opcode: mnu_abi::provider::OP_RELEASE,
            object_id: 42,
            argument: 0,
            basis: 0,
            length: 0,
            data_length: 0,
        };
        let mut bytes = [0; mnu_abi::provider::REQUEST_HEADER_LEN];
        let n = header.encode(&[], &mut bytes).unwrap();
        let mut delivery = p::ipc::IpcObjectHandles::default();
        assert!(!release(&bytes[..n], &delivery));
        delivery.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
        assert!(!release(&bytes[..n], &delivery));
        assert!(
            REGISTRY
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .grants
                .contains_key(&42)
        );
        delivery.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
        assert!(release(&bytes[..n], &delivery));
        assert!(
            !REGISTRY
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .grants
                .contains_key(&42)
        );
    }
}
