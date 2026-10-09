use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::sync::Mutex;

use mochi_user_platform as platform;
use mochios_posix_client::directory::DirectoryEntries;
use mochios_posix_client::{Client, ClientError, EndpointTransport, OpenAtBase, StatAtBase};
use mochios_posix_protocol as posix;

use crate::dynamic_grant::{read_request_str, transfer_scoped_path_grant, transfer_user_grant};
use crate::package_index::PackageIndex;
use crate::policy::is_known_capability;
use crate::resolver::application_identity;

const GRANTS_PATH: &str = "/var/lib/security/capability-grants.db";
const GRANTS_NEW_PATH: &str = "/var/lib/security/capability-grants.db.new";
const GRANTS_OLD_PATH: &str = "/var/lib/security/capability-grants.db.old";
const POLICY_DIR: &str = "/var/lib/security";
const FILE_MODE_644: u32 = 0o644;

type PosixClient = Client<EndpointTransport>;

static POSIX_CLIENT: Mutex<Option<PosixClient>> = Mutex::new(None);

fn sys_error(errno: u64) -> mochi_user_syscall::SysError {
    mochi_user_syscall::SysError::from_raw(errno as i64)
}

fn client_error(error: ClientError<mochi_user_syscall::SysError>) -> mochi_user_syscall::SysError {
    match error {
        ClientError::Transport(error) => error,
        ClientError::Remote(status) => mochi_user_syscall::SysError::from_raw(status as i64),
        ClientError::Protocol(_)
        | ClientError::RequestTooLarge
        | ClientError::ResponseTooLarge
        | ClientError::MismatchedResponse => sys_error(mochi_user_syscall::EIO),
    }
}

fn with_client<T>(
    operation: impl FnOnce(&PosixClient) -> Result<T, ClientError<mochi_user_syscall::SysError>>,
) -> Result<T, mochi_user_syscall::SysError> {
    let client = POSIX_CLIENT
        .lock()
        .map_err(|_| sys_error(mochi_user_syscall::EIO))?;
    let client = client
        .as_ref()
        .ok_or_else(|| sys_error(mochi_user_syscall::EAGAIN))?;
    operation(client).map_err(client_error)
}

pub(crate) fn install_posix_endpoint(
    endpoint: platform::handle::Handle,
) -> Result<(), mochi_user_syscall::SysError> {
    let client = Client::new(EndpointTransport::new(endpoint));
    if let Err(error) = client.register_session() {
        let _ = platform::handle::close(endpoint);
        return Err(client_error(error));
    }
    let mut installed = POSIX_CLIENT
        .lock()
        .map_err(|_| sys_error(mochi_user_syscall::EIO))?;
    if let Some(previous) = installed.replace(client) {
        let _ = platform::handle::close(previous.into_transport().endpoint());
    }
    Ok(())
}

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn ensure_policy_dir() -> Result<(), mochi_user_syscall::SysError> {
    for path in ["/var", "/var/lib", POLICY_DIR] {
        let result = with_client(|client| client.mkdir_at(OpenAtBase::ProcessRoot, 0o755, path));
        if let Err(error) = result
            && error.raw() != mochi_user_syscall::EEXIST as i64
        {
            return Err(error);
        }
    }
    Ok(())
}

fn write_file(path: &str, bytes: &[u8]) -> Result<(), mochi_user_syscall::SysError> {
    let file = with_client(|client| {
        client.open_at(
            OpenAtBase::ProcessRoot,
            posix::OPEN_WRITE | posix::OPEN_CREATE | posix::OPEN_TRUNCATE,
            FILE_MODE_644,
            path,
        )
    })?;
    let mut written = 0usize;
    while written < bytes.len() {
        let n = match platform::handle::write(file.handle, &bytes[written..]) {
            Ok(length) => length,
            Err(error) => {
                let _ = platform::handle::close(file.handle);
                return Err(error);
            }
        };
        if n == 0 {
            let _ = platform::handle::close(file.handle);
            return Err(sys_error(mochi_user_syscall::EIO));
        }
        written += n;
    }
    let sync_result = with_client(|client| client.fsync(file));
    let close_result = platform::handle::close(file.handle);
    sync_result?;
    close_result
}

pub(crate) fn read_file(path: &str) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    let file =
        with_client(|client| client.open_at(OpenAtBase::ProcessRoot, posix::OPEN_READ, 0, path))?;
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match platform::handle::read(file.handle, &mut buffer) {
            Ok(0) => break,
            Ok(length) => output.extend_from_slice(&buffer[..length]),
            Err(error) => {
                let _ = platform::handle::close(file.handle);
                return Err(error);
            }
        }
    }
    platform::handle::close(file.handle)?;
    Ok(output)
}

pub(crate) fn read_dir_names(path: &str) -> Result<Vec<String>, mochi_user_syscall::SysError> {
    let directory = with_client(|client| {
        client.open_at(
            OpenAtBase::ProcessRoot,
            posix::OPEN_READ | posix::OPEN_DIRECTORY,
            0,
            path,
        )
    })?;
    let result = (|| {
        let mut names = Vec::new();
        let mut bytes = [0u8; 4096];
        loop {
            let length = platform::handle::read(directory.handle, &mut bytes)?;
            if length == 0 {
                return Ok(names);
            }
            for entry in DirectoryEntries::new(&bytes[..length]) {
                let entry = entry.map_err(|_| sys_error(mochi_user_syscall::EIO))?;
                if entry.name != "." && entry.name != ".." {
                    names.push(entry.name.to_string());
                }
            }
        }
    })();
    let closed = platform::handle::close(directory.handle);
    result.and_then(|names| closed.map(|_| names))
}

fn path_exists(path: &str) -> Result<bool, mochi_user_syscall::SysError> {
    match with_client(|client| client.stat_at(StatAtBase::ProcessRoot, 0, path)) {
        Ok(_) => Ok(true),
        Err(error) if error.raw() == mochi_user_syscall::ENOENT as i64 => Ok(false),
        Err(error) => Err(error),
    }
}

fn sync_policy_dir() -> Result<(), mochi_user_syscall::SysError> {
    let directory = with_client(|client| {
        client.open_at(
            OpenAtBase::ProcessRoot,
            posix::OPEN_READ | posix::OPEN_DIRECTORY,
            0,
            POLICY_DIR,
        )
    })?;
    let sync_result = with_client(|client| client.fsync(directory));
    let close_result = platform::handle::close(directory.handle);
    sync_result?;
    close_result
}

fn rename(old_path: &str, new_path: &str) -> Result<(), mochi_user_syscall::SysError> {
    with_client(|client| {
        client.rename_at(
            StatAtBase::ProcessRoot,
            old_path,
            StatAtBase::ProcessRoot,
            new_path,
        )
    })
}

fn remove(path: &str) -> Result<(), mochi_user_syscall::SysError> {
    with_client(|client| client.unlink_at(StatAtBase::ProcessRoot, 0, path))
}

fn recover_grant_db() -> Result<(), mochi_user_syscall::SysError> {
    let current = path_exists(GRANTS_PATH)?;
    let old = path_exists(GRANTS_OLD_PATH)?;
    if !current && old {
        rename(GRANTS_OLD_PATH, GRANTS_PATH)?;
        sync_policy_dir()?;
    } else if current && old {
        remove(GRANTS_OLD_PATH)?;
        sync_policy_dir()?;
    }
    if path_exists(GRANTS_NEW_PATH)? {
        remove(GRANTS_NEW_PATH)?;
        sync_policy_dir()?;
    }
    Ok(())
}

fn replace_grant_db(bytes: &[u8]) -> Result<(), mochi_user_syscall::SysError> {
    recover_grant_db()?;
    write_file(GRANTS_NEW_PATH, bytes)?;
    sync_policy_dir()?;
    let had_current = path_exists(GRANTS_PATH)?;
    if had_current {
        rename(GRANTS_PATH, GRANTS_OLD_PATH)?;
    }
    if let Err(error) = rename(GRANTS_NEW_PATH, GRANTS_PATH) {
        if had_current {
            let _ = rename(GRANTS_OLD_PATH, GRANTS_PATH);
        }
        let _ = sync_policy_dir();
        return Err(error);
    }
    sync_policy_dir()?;
    if had_current {
        remove(GRANTS_OLD_PATH)?;
        sync_policy_dir()?;
    }
    Ok(())
}

pub(crate) fn append_persistent_grant(
    context: &mochi_user_syscall::ThreadSecurityContext,
    capability: &str,
    resource: Option<&str>,
    all_user_grantable: bool,
) -> Result<(), mochi_user_syscall::SysError> {
    ensure_policy_dir()?;
    recover_grant_db()?;
    if capability
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'\t' | b'\n' | 0))
        || resource.is_some_and(|value| {
            value
                .as_bytes()
                .iter()
                .any(|byte| matches!(byte, b'\t' | b'\n' | 0))
        })
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let mut data = match read_file(GRANTS_PATH) {
        Ok(data) => data,
        Err(error) if error.raw() == mochi_user_syscall::ENOENT as i64 => alloc::vec::Vec::new(),
        Err(error) => return Err(error),
    };
    data.extend_from_slice(b"v2\t");
    data.extend_from_slice(context.effective_uid.to_string().as_bytes());
    data.push(b'\t');
    data.extend_from_slice(&context.package_id[..context.package_id_len as usize]);
    data.push(b'\t');
    data.extend_from_slice(&context.developer_id[..context.developer_id_len as usize]);
    data.push(b'\t');
    data.extend_from_slice(hex_digest(&context.subject_key_id).as_bytes());
    data.push(b'\t');
    data.extend_from_slice(context.provenance.to_string().as_bytes());
    data.push(b'\t');
    data.extend_from_slice(capability.as_bytes());
    data.push(b'\t');
    data.extend_from_slice(if all_user_grantable {
        b"all-user"
    } else {
        b"single"
    });
    data.push(b'\t');
    if let Some(resource) = resource {
        data.extend_from_slice(resource.as_bytes());
    }
    data.push(b'\n');
    replace_grant_db(&data)
}

fn grant_db_matches(
    context: &mochi_user_syscall::ThreadSecurityContext,
    capability: &str,
    resource: Option<&str>,
) -> bool {
    if recover_grant_db().is_err() {
        return false;
    }
    let Ok(data) = read_file(GRANTS_PATH) else {
        return false;
    };
    let key_hex = hex_digest(&context.subject_key_id);
    let uid = context.effective_uid.to_string();
    let provenance = context.provenance.to_string();
    let package = &context.package_id[..context.package_id_len as usize];
    let developer = &context.developer_id[..context.developer_id_len as usize];
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(|b| *b == b'\t');
        if fields.next() != Some(b"v2".as_slice()) {
            continue;
        }
        let Some(grant_uid) = fields.next() else {
            continue;
        };
        let Some(grant_package) = fields.next() else {
            continue;
        };
        let Some(grant_developer) = fields.next() else {
            continue;
        };
        let Some(grant_key) = fields.next() else {
            continue;
        };
        let Some(grant_provenance) = fields.next() else {
            continue;
        };
        let Some(grant_cap) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let Some(scope) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let grant_resource = fields
            .next()
            .and_then(|v| core::str::from_utf8(v).ok())
            .unwrap_or("");
        if grant_uid != uid.as_bytes()
            || grant_package != package
            || grant_developer != developer
            || grant_key != key_hex.as_bytes()
            || grant_provenance != provenance.as_bytes()
        {
            continue;
        }
        if scope == "all-user" {
            return true;
        }
        if scope == "single" && grant_cap == capability {
            let resource_matches = match resource {
                Some(resource) => grant_resource == resource,
                None => grant_resource.is_empty(),
            };
            if resource_matches {
                return true;
            }
        }
    }
    false
}

pub(crate) fn has_persistent_grant(
    context: &mochi_user_syscall::ThreadSecurityContext,
    capability: &str,
    resource: Option<&str>,
) -> bool {
    if context.package_id_len as usize > context.package_id.len()
        || context.developer_id_len as usize > context.developer_id.len()
    {
        return false;
    }
    grant_db_matches(context, capability, resource)
}

pub(crate) fn authorize_persistent_capability(
    index: &PackageIndex,
    requester_thread: u64,
    request: &platform::capability::CapabilityRequest,
) -> Result<(), mochi_user_syscall::SysError> {
    if request.opcode != platform::capability::CAPABILITY_PERSISTENT_QUERY_OPCODE
        || request.process_id == 0
        || requester_thread == 0
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    if request.capability_class != platform::capability::CapabilityClass::UserGrantable {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let context = platform::process::thread_security_context(requester_thread)?;
    if context.process_id != request.process_id {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let executable = read_request_str(&request.executable.path, request.executable.path_len)?;
    let record = index
        .by_binary
        .get(executable)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    let expected = application_identity(&record.manifest, &record.manifest_path)?;
    if context.package_id_len as usize != expected.package_id.len()
        || context.developer_id_len as usize != expected.developer_id.len()
        || &context.package_id[..context.package_id_len as usize] != expected.package_id.as_bytes()
        || &context.developer_id[..context.developer_id_len as usize]
            != expected.developer_id.as_bytes()
        || context.subject_key_id != expected.subject_key_id
        || context.provenance != expected.provenance as u8
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let capability = read_request_str(&request.capability, request.capability_len)?;
    if !is_known_capability(capability)
        || platform::capability::capability_from_string(capability)
            != platform::capability::CapabilityClass::UserGrantable
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let resource = if request.resource.path_len == 0 {
        None
    } else {
        Some(read_request_str(
            &request.resource.path,
            request.resource.path_len,
        )?)
    };
    if !grant_db_matches(&context, capability, resource) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    match (capability, resource) {
        ("fs.read.user", Some(path)) => {
            transfer_scoped_path_grant(requester_thread, path, false, executable)
        }
        ("fs.write.user", Some(path)) => {
            transfer_scoped_path_grant(requester_thread, path, true, executable)
        }
        _ => transfer_user_grant(requester_thread, capability, executable),
    }
}
