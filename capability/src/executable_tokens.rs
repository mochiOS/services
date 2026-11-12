//! Native references to captured, signed code. No ambient pathname authority
//! is delegated, and code acquisition is separate from execution permission.
use crate::{
    app_image,
    image_catalog::Catalog,
    resolver::{ApplicationIdentity, VerifiedManifest},
};
use mochi_user_platform as p;
use mochios_posix_client::ObjectHandleAttachment;
use p::capability::executables as wire;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};
type Error = p::syscall::SysError;
const TOKEN_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
const IMAGE_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER;
const CODE_NAMESPACE: u64 = 1 << 62;
const MAX_BYTES: usize = 256 * 1024 * 1024;
struct Captured {
    path: String,
    image: p::memory_object::MemoryObject,
}
struct Grant {
    identity: ApplicationIdentity,
    caller_image: [u8; 32],
    inputs: Vec<Captured>,
    bytes: usize,
}
struct Registry {
    endpoint: u32,
    next: u64,
    grants: BTreeMap<u64, Grant>,
}
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
fn error(n: i64) -> Error {
    Error::from_raw(n)
}
pub(crate) fn initialize(endpoint: u32) -> Result<(), Error> {
    REGISTRY
        .set(Mutex::new(Registry {
            endpoint,
            next: CODE_NAMESPACE,
            grants: BTreeMap::new(),
        }))
        .map_err(|_| error(-5))
}
fn load(state: &crate::state::CapabilityServiceState, id: &str) -> Result<VerifiedManifest, Error> {
    if state.package_index.duplicate {
        return Err(error(-13));
    }
    let entry = state
        .package_index
        .by_package
        .get(id)
        .ok_or_else(|| error(-2))?;
    crate::resolver::verified_manifest(&entry.manifest_path, crate::persistent_grant::read_file)
}
fn select(
    state: &crate::state::CapabilityServiceState,
    sender: u64,
    request: wire::Request<'_>,
    attached: &p::ipc::IpcObjectHandles,
) -> Result<ObjectHandleAttachment<u32>, Error> {
    let peer = p::execution_peer::capture(sender)?;
    if p::capability::check_thread(sender, "process.spawn")? != 1 {
        return Err(error(-13));
    }
    let (owner, path) = crate::resource_tokens::executable_owner(sender, attached)?;
    let (provider, entry) = if request.alias.is_empty() {
        let binary = p::package::executables::own(&owner.manifest, &path, request.name)
            .ok_or_else(|| error(-13))?;
        let entry = binary.path.clone();
        (owner.clone(), entry)
    } else {
        let dependency = p::package::executables::dependency(&owner.manifest, &path, request.alias)
            .ok_or_else(|| error(-13))?;
        let provider = load(state, &dependency.provider.package)?;
        let architecture = owner
            .manifest
            .package_architecture
            .as_deref()
            .ok_or_else(|| error(-13))?;
        Catalog::matches_provider(&dependency.provider, &provider, architecture)?;
        let entry = p::package::executables::exported(&provider.manifest, &dependency.export)
            .ok_or_else(|| error(-13))?
            .path
            .clone();
        (provider, entry)
    };
    // Selection never promotes the caller or implicitly obtains user consent.
    let capabilities = provider.decide_capabilities(&entry)?.into_allowed()?;
    for capability in &capabilities {
        if !crate::policy::is_known_capability(capability)
            || p::capability::check_thread(sender, capability)? != 1
        {
            return Err(error(-13));
        }
    }
    let catalog = Catalog::resolve(provider, &entry, |id| load(state, id))?;
    let declarations = catalog.code_inputs();
    let mut total = 0usize;
    for (_, size, _) in &declarations {
        let size = usize::try_from(*size).map_err(|_| error(-7))?;
        if size > 128 * 1024 * 1024 {
            return Err(error(-7));
        }
        total = total
            .checked_add(size)
            .filter(|n| *n <= MAX_BYTES)
            .ok_or_else(|| error(-7))?;
    }
    // Check the budget before filesystem I/O. This broker admits requests serially; no
    // registry lock is held while contacting POSIX/filesystem services.
    {
        let registry = REGISTRY
            .get()
            .ok_or_else(|| error(-5))?
            .lock()
            .map_err(|_| error(-5))?;
        if registry.grants.len() >= 64
            || registry.grants.values().map(|g| g.bytes).sum::<usize>() + total > 512 * 1024 * 1024
        {
            return Err(error(-28));
        }
    }
    let mut inputs = Vec::new();
    for (index, (path, size, digest)) in declarations.into_iter().enumerate() {
        let bytes = crate::resource_tokens::read_code(&path, size as usize, index == 0)?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != digest {
            return Err(error(-13));
        }
        inputs.push(Captured {
            path,
            image: app_image::readonly_duplicable(&bytes)?,
        });
    }
    let after = p::execution_peer::capture(sender)?;
    if peer.context != after.context || peer.image != after.image {
        return Err(error(-13));
    }
    let mut registry = REGISTRY
        .get()
        .ok_or_else(|| error(-5))?
        .lock()
        .map_err(|_| error(-5))?;
    let id = registry.next;
    if registry.grants.len() >= 64
        || registry.grants.values().map(|g| g.bytes).sum::<usize>() + total > 512 * 1024 * 1024
    {
        return Err(error(-28));
    }
    registry.next = id
        .checked_add(1)
        .filter(|next| *next < 1u64 << 63)
        .ok_or_else(|| error(-28))?;
    let handle = p::handle::create_provider_object(registry.endpoint, id, TOKEN_RIGHTS)?;
    registry.grants.insert(
        id,
        Grant {
            identity: owner.identity,
            caller_image: peer.image.digest,
            inputs,
            bytes: total,
        },
    );
    Ok(ObjectHandleAttachment {
        handle,
        rights: TOKEN_RIGHTS,
    })
}
pub(crate) fn request(
    state: &crate::state::CapabilityServiceState,
    sender: u64,
    bytes: &[u8],
    attached: &p::ipc::IpcObjectHandles,
) -> Result<ObjectHandleAttachment<u32>, Error> {
    let request = wire::decode(bytes).map_err(|_| error(-22))?;
    if !attached.is_user_delivery() || attached.count != 1 {
        return Err(error(-13));
    }
    let token = attached.handles[0];
    if token.handle == 0 || token.reserved != 0 || token.rights != mnu_abi::HANDLE_RIGHT_TRANSFER {
        return Err(error(-13));
    }
    if request.operation == wire::SELECT {
        return select(state, sender, request, attached);
    }
    let id = p::handle::identify_provider_object(token.handle)?;
    let before = p::execution_peer::capture(sender)?;
    let object = {
        let registry = REGISTRY
            .get()
            .ok_or_else(|| error(-13))?
            .lock()
            .map_err(|_| error(-5))?;
        let grant = registry.grants.get(&id).ok_or_else(|| error(-13))?;
        if !crate::resource_tokens::matches_identity(
            &grant.identity,
            &grant.caller_image,
            &before.context,
            &before.image,
        ) {
            return Err(error(-13));
        }
        let input = if request.operation == wire::ROOT {
            grant.inputs.first()
        } else {
            grant
                .inputs
                .iter()
                .skip(1)
                .find(|input| input.path == request.name)
        }
        .ok_or_else(|| error(-2))?;
        p::handle::duplicate(input.image.handle(), IMAGE_RIGHTS)?
    };
    let after = p::execution_peer::capture(sender);
    if !after.is_ok_and(|after| before.image == after.image && before.context == after.context) {
        let _ = p::handle::close(object);
        return Err(error(-13));
    }
    Ok(ObjectHandleAttachment {
        handle: object,
        rights: IMAGE_RIGHTS,
    })
}
/// Only the kernel's last-reference notification retires a captured grant.
pub(crate) fn release(bytes: &[u8], attached: &p::ipc::IpcObjectHandles) -> bool {
    let Ok((header, payload)) = mnu_abi::provider::RequestHeader::decode(bytes) else {
        return false;
    };
    if attached.delivery_flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
        || attached.count != 0
        || header.opcode != mnu_abi::provider::OP_RELEASE
        || !payload.is_empty()
        || header.object_id & CODE_NAMESPACE == 0
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
