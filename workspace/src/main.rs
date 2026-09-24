use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use mochi_user_platform as platform;
use mochios_workspace_protocol as protocol;

const CLIPBOARD_READ: &str = "clipboard.read";
const CLIPBOARD_WRITE: &str = "clipboard.write";
const ASSOCIATIONS_READ: &str = "file-association.read";
const ASSOCIATIONS_WRITE: &str = "file-association.write";
const DATABASE_MAGIC: &[u8; 8] = b"MWASSOC1";
const APPLICATIONS_ROOT: &str = "/applications";
const CAPABILITY_SERVICE_NAME: &str = "capability.service";
const SPAWN_APP_OPCODE: u32 = 0x4150_5053;
const SPAWN_APP_HEADER_LEN: usize = 24;
const EXEC_MANIFEST_ENV_PREFIX: &str = "__MNU_EXEC_ENV=";
const SESSION_ENVIRONMENT_NAMES: [&str; 4] = ["HOME", "USER", "LOGNAME", "SHELL"];

#[derive(Clone, Debug, PartialEq, Eq)]
struct Association {
    extension: String,
    content_type: String,
    bundle_id: String,
    roles: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InstalledApplication {
    name: String,
    bundle_id: String,
    entry_path: String,
    associations: Vec<Association>,
}

#[derive(Debug)]
struct ClipboardTransaction {
    id: u64,
    owner_process: u64,
    content_type: String,
    expected: usize,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct WorkspaceService {
    clipboard_generation: u64,
    clipboard_content_type: String,
    clipboard: Vec<u8>,
    transaction: Option<ClipboardTransaction>,
    next_transaction: u64,
    associations: Vec<Association>,
    association_path: PathBuf,
}

impl WorkspaceService {
    fn load() -> Self {
        let association_path = association_path();
        let associations = fs::read(&association_path)
            .ok()
            .and_then(|bytes| decode_associations(&bytes).ok())
            .unwrap_or_default();
        Self {
            clipboard_generation: 0,
            clipboard_content_type: String::new(),
            clipboard: Vec::new(),
            transaction: None,
            next_transaction: 1,
            associations,
            association_path,
        }
    }

    fn handle(&mut self, sender: u64, request: protocol::Message<'_>) {
        let capability = match request.opcode {
            protocol::OP_CLIPBOARD_SNAPSHOT | protocol::OP_CLIPBOARD_READ => CLIPBOARD_READ,
            protocol::OP_CLIPBOARD_SET_BEGIN
            | protocol::OP_CLIPBOARD_SET_CHUNK
            | protocol::OP_CLIPBOARD_SET_COMMIT => CLIPBOARD_WRITE,
            protocol::OP_ASSOCIATION_RESOLVE
            | protocol::OP_ASSOCIATION_HANDLERS
            | protocol::OP_DOCUMENT_OPEN => ASSOCIATIONS_READ,
            protocol::OP_ASSOCIATION_SET | protocol::OP_ASSOCIATION_REMOVE => ASSOCIATIONS_WRITE,
            _ => {
                self.reply_status(
                    sender,
                    request.request_id,
                    -(mochi_user_syscall::EINVAL as i32),
                    0,
                );
                return;
            }
        };
        if platform::capability::check_thread(sender, capability) != Ok(1) {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EACCES as i32),
                0,
            );
            return;
        }

        match request.opcode {
            protocol::OP_CLIPBOARD_SET_BEGIN => self.clipboard_begin(sender, request),
            protocol::OP_CLIPBOARD_SET_CHUNK => self.clipboard_chunk(sender, request),
            protocol::OP_CLIPBOARD_SET_COMMIT => self.clipboard_commit(sender, request),
            protocol::OP_CLIPBOARD_SNAPSHOT => self.clipboard_snapshot(sender, request),
            protocol::OP_CLIPBOARD_READ => self.clipboard_read(sender, request),
            protocol::OP_ASSOCIATION_SET => self.association_set(sender, request),
            protocol::OP_ASSOCIATION_REMOVE => self.association_remove(sender, request),
            protocol::OP_ASSOCIATION_RESOLVE => self.association_resolve(sender, request),
            protocol::OP_ASSOCIATION_HANDLERS => self.association_handlers(sender, request),
            protocol::OP_DOCUMENT_OPEN => self.document_open(sender, request),
            _ => unreachable!(),
        }
    }

    fn clipboard_begin(&mut self, sender: u64, request: protocol::Message<'_>) {
        let Some((total, content_type)) = decode_clipboard_begin(request.payload) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let Ok(owner_process) = platform::ipc::endpoint_owner_process(sender) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EPERM as i32),
                0,
            );
            return;
        };
        let transaction_id = self.next_transaction;
        self.next_transaction = self.next_transaction.wrapping_add(1).max(1);
        self.transaction = Some(ClipboardTransaction {
            id: transaction_id,
            owner_process,
            content_type,
            expected: total,
            bytes: Vec::with_capacity(total),
        });
        self.reply_status(sender, request.request_id, 0, transaction_id);
    }

    fn clipboard_chunk(&mut self, sender: u64, request: protocol::Message<'_>) {
        let owner_process = platform::ipc::endpoint_owner_process(sender).ok();
        let transaction_id = protocol::read_u64(request.payload, 0).ok();
        let offset = protocol::read_u64(request.payload, 8)
            .ok()
            .and_then(|value| usize::try_from(value).ok());
        let bytes = request.payload.get(16..);
        let Some(transaction) = self.transaction.as_mut() else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::ENOENT as i32),
                0,
            );
            return;
        };
        if transaction_id != Some(transaction.id)
            || owner_process != Some(transaction.owner_process)
            || offset != Some(transaction.bytes.len())
            || bytes.is_none_or(|bytes| bytes.is_empty() || bytes.len() > protocol::MAX_CHUNK_BYTES)
        {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }
        let bytes = bytes.unwrap_or_default();
        if transaction.bytes.len().saturating_add(bytes.len()) > transaction.expected {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::ENOSPC as i32),
                0,
            );
            return;
        }
        transaction.bytes.extend_from_slice(bytes);
        let written = transaction.bytes.len() as u64;
        self.reply_status(sender, request.request_id, 0, written);
    }

    fn clipboard_commit(&mut self, sender: u64, request: protocol::Message<'_>) {
        let owner_process = platform::ipc::endpoint_owner_process(sender).ok();
        let transaction_id = protocol::read_u64(request.payload, 0).ok();
        if request.payload.len() != 8
            || self.transaction.as_ref().map(|transaction| transaction.id) != transaction_id
            || self
                .transaction
                .as_ref()
                .map(|transaction| transaction.owner_process)
                != owner_process
        {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }
        let transaction = self.transaction.take().expect("validated transaction");
        if transaction.bytes.len() != transaction.expected {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }
        self.clipboard = transaction.bytes;
        self.clipboard_content_type = transaction.content_type;
        self.clipboard_generation = self.clipboard_generation.wrapping_add(1).max(1);
        self.reply_status(sender, request.request_id, 0, self.clipboard.len() as u64);
    }

    fn clipboard_snapshot(&self, sender: u64, request: protocol::Message<'_>) {
        if !request.payload.is_empty() {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }
        let content_type = self.clipboard_content_type.as_bytes();
        let mut payload = Vec::with_capacity(24 + content_type.len());
        payload.extend_from_slice(&self.clipboard_generation.to_le_bytes());
        payload.extend_from_slice(&(self.clipboard.len() as u64).to_le_bytes());
        payload.extend_from_slice(&(content_type.len() as u16).to_le_bytes());
        payload.extend_from_slice(&[0; 6]);
        payload.extend_from_slice(content_type);
        self.reply(
            sender,
            protocol::OP_CLIPBOARD_METADATA,
            request.request_id,
            &payload,
        );
    }

    fn clipboard_read(&self, sender: u64, request: protocol::Message<'_>) {
        let generation = protocol::read_u64(request.payload, 0).ok();
        let offset = protocol::read_u64(request.payload, 8)
            .ok()
            .and_then(|value| usize::try_from(value).ok());
        let length = protocol::read_u32(request.payload, 16)
            .ok()
            .map(|value| value as usize);
        if request.payload.len() != 24
            || generation != Some(self.clipboard_generation)
            || offset.is_none()
            || length.is_none()
        {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }
        let offset = offset.unwrap_or(usize::MAX);
        let length = length.unwrap_or(0).min(protocol::MAX_CHUNK_BYTES);
        if offset > self.clipboard.len() {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::ERANGE as i32),
                0,
            );
            return;
        }
        let end = offset.saturating_add(length).min(self.clipboard.len());
        let mut payload = Vec::with_capacity(16 + end - offset);
        payload.extend_from_slice(&self.clipboard_generation.to_le_bytes());
        payload.extend_from_slice(&(offset as u64).to_le_bytes());
        payload.extend_from_slice(&self.clipboard[offset..end]);
        self.reply(
            sender,
            protocol::OP_CLIPBOARD_CHUNK,
            request.request_id,
            &payload,
        );
    }

    fn association_set(&mut self, sender: u64, request: protocol::Message<'_>) {
        let Some(candidate) = decode_association_request(request.payload) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let mut associations = self.associations.clone();
        associations.retain(|association| {
            association.extension != candidate.extension
                || association.content_type != candidate.content_type
                || association.roles != candidate.roles
        });
        associations.push(candidate);
        let status = match persist_associations(&self.association_path, &associations) {
            Ok(()) => {
                self.associations = associations;
                0
            }
            Err(error) => errno(error),
        };
        self.reply_status(sender, request.request_id, -(status as i32), 0);
    }

    fn association_remove(&mut self, sender: u64, request: protocol::Message<'_>) {
        let Some((extension, content_type, roles)) = decode_association_key(request.payload) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let mut associations = self.associations.clone();
        associations.retain(|association| {
            association.extension != extension
                || association.content_type != content_type
                || association.roles != roles
        });
        let status = match persist_associations(&self.association_path, &associations) {
            Ok(()) => {
                self.associations = associations;
                0
            }
            Err(error) => errno(error),
        };
        self.reply_status(sender, request.request_id, -(status as i32), 0);
    }

    fn association_resolve(&self, sender: u64, request: protocol::Message<'_>) {
        let Some((extension, content_type, roles)) = decode_association_key(request.payload) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let applications = installed_applications();
        let Some(bundle_id) = resolve_bundle(
            &self.associations,
            &applications,
            &extension,
            &content_type,
            roles,
        ) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::ENOENT as i32),
                0,
            );
            return;
        };
        let bundle = bundle_id.as_bytes();
        let mut payload = Vec::with_capacity(8 + bundle.len());
        payload.extend_from_slice(&roles.to_le_bytes());
        payload.extend_from_slice(&(bundle.len() as u16).to_le_bytes());
        payload.extend_from_slice(&[0; 4]);
        payload.extend_from_slice(bundle);
        self.reply(
            sender,
            protocol::OP_ASSOCIATION_RESULT,
            request.request_id,
            &payload,
        );
    }

    fn association_handlers(&self, sender: u64, request: protocol::Message<'_>) {
        let Some((extension, content_type, roles)) = decode_association_key(request.payload) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let applications = installed_applications();
        let mut handlers = matching_handlers(
            &self.associations,
            &applications,
            &extension,
            &content_type,
            roles,
        );
        handlers.truncate(protocol::MAX_ASSOCIATION_HANDLERS);
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&[0; 6]);
        let mut encoded_count = 0u16;
        for application in handlers {
            let bundle = application.bundle_id.as_bytes();
            let name = application.name.as_bytes();
            let record_len = 4usize
                .saturating_add(bundle.len())
                .saturating_add(name.len());
            if protocol::HEADER_LEN
                .saturating_add(payload.len())
                .saturating_add(record_len)
                > protocol::MAX_MESSAGE_LEN
            {
                break;
            }
            payload.extend_from_slice(&(bundle.len() as u16).to_le_bytes());
            payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
            payload.extend_from_slice(bundle);
            payload.extend_from_slice(name);
            encoded_count += 1;
        }
        payload[..2].copy_from_slice(&encoded_count.to_le_bytes());
        self.reply(
            sender,
            protocol::OP_ASSOCIATION_HANDLERS_RESULT,
            request.request_id,
            &payload,
        );
    }

    fn document_open(&self, sender: u64, request: protocol::Message<'_>) {
        let Some((path, content_type, requested_bundle, roles)) =
            decode_document_open(request.payload)
        else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let canonical = match fs::canonicalize(&path) {
            Ok(path) if path.is_file() => path,
            Ok(_) => {
                self.reply_status(
                    sender,
                    request.request_id,
                    -(mochi_user_syscall::EISDIR as i32),
                    0,
                );
                return;
            }
            Err(error) => {
                self.reply_status(sender, request.request_id, -(errno(error) as i32), 0);
                return;
            }
        };
        let Some(path) = canonical.to_str() else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let extension = canonical
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let applications = installed_applications();
        let handlers = matching_handlers(
            &self.associations,
            &applications,
            &extension,
            &content_type,
            roles,
        );
        let application = if requested_bundle.is_empty() {
            resolve_bundle(
                &self.associations,
                &applications,
                &extension,
                &content_type,
                roles,
            )
            .and_then(|bundle| handlers.iter().find(|app| app.bundle_id == bundle).copied())
        } else {
            handlers
                .iter()
                .find(|application| application.bundle_id == requested_bundle)
                .copied()
        };
        let Some(application) = application else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::ENOENT as i32),
                0,
            );
            return;
        };
        match launch_application(application, path) {
            Ok(process_id) => self.reply_status(sender, request.request_id, 0, process_id),
            Err(status) => self.reply_status(sender, request.request_id, -(status as i32), 0),
        }
    }

    fn reply_status(&self, sender: u64, request_id: u64, status: i32, value: u64) {
        let mut output = [0u8; protocol::HEADER_LEN + 24];
        if let Ok(length) = protocol::encode_status(
            request_id,
            status,
            self.clipboard_generation,
            value,
            &mut output,
        ) {
            let _ = platform::ipc::reply(sender, &output[..length]);
        }
    }

    fn reply(&self, sender: u64, opcode: u16, request_id: u64, payload: &[u8]) {
        let mut output = vec![0u8; protocol::HEADER_LEN + payload.len()];
        if let Ok(length) = protocol::encode(opcode, request_id, 0, payload, &mut output) {
            let _ = platform::ipc::reply(sender, &output[..length]);
        }
    }
}

fn valid_content_type(value: &str) -> bool {
    value.is_ascii()
        && value.contains('/')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'-' | b'.' | b';' | b'=')
        })
}

fn decode_clipboard_begin(payload: &[u8]) -> Option<(usize, String)> {
    let total = usize::try_from(protocol::read_u64(payload, 0).ok()?).ok()?;
    let content_type_len = protocol::read_u16(payload, 8).ok()? as usize;
    if total > protocol::MAX_CLIPBOARD_BYTES || payload.len() != 16 + content_type_len {
        return None;
    }
    let content_type = protocol::validate_utf8_field(
        payload,
        16,
        content_type_len,
        protocol::MAX_CONTENT_TYPE_LEN,
    )
    .ok()?;
    valid_content_type(content_type).then(|| (total, content_type.to_owned()))
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn decode_association_request(payload: &[u8]) -> Option<Association> {
    let roles = protocol::read_u16(payload, 0).ok()?;
    let extension_len = protocol::read_u16(payload, 2).ok()? as usize;
    let content_type_len = protocol::read_u16(payload, 4).ok()? as usize;
    let bundle_len = protocol::read_u16(payload, 6).ok()? as usize;
    let expected = 8usize
        .checked_add(extension_len)?
        .checked_add(content_type_len)?
        .checked_add(bundle_len)?;
    if expected != payload.len() || roles == 0 || roles & !protocol::ASSOCIATION_ROLE_ALL != 0 {
        return None;
    }
    let extension = std::str::from_utf8(payload.get(8..8 + extension_len)?)
        .ok()?
        .to_ascii_lowercase();
    let content_start = 8 + extension_len;
    let content_type =
        std::str::from_utf8(payload.get(content_start..content_start + content_type_len)?)
            .ok()?
            .to_ascii_lowercase();
    let bundle_start = content_start + content_type_len;
    let bundle_id = std::str::from_utf8(payload.get(bundle_start..expected)?)
        .ok()?
        .to_owned();
    if (!extension.is_empty() && !valid_identifier(&extension, protocol::MAX_EXTENSION_LEN))
        || (!content_type.is_empty() && !valid_content_type(&content_type))
        || (extension.is_empty() && content_type.is_empty())
        || !valid_identifier(&bundle_id, protocol::MAX_BUNDLE_ID_LEN)
    {
        return None;
    }
    Some(Association {
        extension,
        content_type,
        bundle_id,
        roles,
    })
}

fn decode_association_key(payload: &[u8]) -> Option<(String, String, u16)> {
    let roles = protocol::read_u16(payload, 0).ok()?;
    let extension_len = protocol::read_u16(payload, 2).ok()? as usize;
    let content_type_len = protocol::read_u16(payload, 4).ok()? as usize;
    let expected = 8usize
        .checked_add(extension_len)?
        .checked_add(content_type_len)?;
    if expected != payload.len() || roles == 0 || roles & !protocol::ASSOCIATION_ROLE_ALL != 0 {
        return None;
    }
    let extension = std::str::from_utf8(payload.get(8..8 + extension_len)?)
        .ok()?
        .to_ascii_lowercase();
    let content_start = 8 + extension_len;
    let content_type = std::str::from_utf8(payload.get(content_start..expected)?)
        .ok()?
        .to_ascii_lowercase();
    if extension.len() > protocol::MAX_EXTENSION_LEN
        || content_type.len() > protocol::MAX_CONTENT_TYPE_LEN
        || (extension.is_empty() && content_type.is_empty())
        || (!extension.is_empty() && !valid_identifier(&extension, protocol::MAX_EXTENSION_LEN))
        || (!content_type.is_empty() && !valid_content_type(&content_type))
    {
        return None;
    }
    Some((extension, content_type, roles))
}

fn decode_document_open(payload: &[u8]) -> Option<(String, String, String, u16)> {
    let roles = protocol::read_u16(payload, 0).ok()?;
    let path_len = protocol::read_u16(payload, 2).ok()? as usize;
    let content_type_len = protocol::read_u16(payload, 4).ok()? as usize;
    let bundle_len = protocol::read_u16(payload, 6).ok()? as usize;
    let expected = 8usize
        .checked_add(path_len)?
        .checked_add(content_type_len)?
        .checked_add(bundle_len)?;
    if expected != payload.len()
        || path_len == 0
        || path_len > protocol::MAX_PATH_LEN
        || content_type_len == 0
        || content_type_len > protocol::MAX_CONTENT_TYPE_LEN
        || bundle_len > protocol::MAX_BUNDLE_ID_LEN
        || roles == 0
        || roles & !protocol::ASSOCIATION_ROLE_ALL != 0
    {
        return None;
    }
    let path = std::str::from_utf8(payload.get(8..8 + path_len)?).ok()?;
    let content_start = 8 + path_len;
    let content_type =
        std::str::from_utf8(payload.get(content_start..content_start + content_type_len)?)
            .ok()?
            .to_ascii_lowercase();
    let bundle_start = content_start + content_type_len;
    let bundle = std::str::from_utf8(payload.get(bundle_start..expected)?).ok()?;
    if !path.starts_with('/')
        || path.as_bytes().contains(&0)
        || !valid_content_type(&content_type)
        || (!bundle.is_empty() && !valid_identifier(bundle, protocol::MAX_BUNDLE_ID_LEN))
    {
        return None;
    }
    Some((path.to_owned(), content_type, bundle.to_owned(), roles))
}

fn association_matches(
    association: &Association,
    extension: &str,
    content_type: &str,
    roles: u16,
) -> bool {
    association.roles & roles != 0
        && ((!content_type.is_empty() && association.content_type == content_type)
            || (!extension.is_empty() && association.extension == extension))
}

fn application_by_bundle<'a>(
    applications: &'a [InstalledApplication],
    bundle_id: &str,
) -> Option<&'a InstalledApplication> {
    applications
        .iter()
        .find(|application| application.bundle_id == bundle_id)
}

fn resolve_bundle(
    user_associations: &[Association],
    applications: &[InstalledApplication],
    extension: &str,
    content_type: &str,
    roles: u16,
) -> Option<String> {
    for prefer_content_type in [true, false] {
        if let Some(application) = user_associations.iter().rev().find_map(|association| {
            let matches_kind = if prefer_content_type {
                !content_type.is_empty() && association.content_type == content_type
            } else {
                !extension.is_empty() && association.extension == extension
            };
            (association.roles & roles != 0 && matches_kind)
                .then(|| application_by_bundle(applications, &association.bundle_id))
                .flatten()
        }) {
            return Some(application.bundle_id.clone());
        }
    }
    for prefer_content_type in [true, false] {
        if let Some(application) = applications.iter().find(|application| {
            application.associations.iter().any(|association| {
                association.roles & roles != 0
                    && if prefer_content_type {
                        !content_type.is_empty() && association.content_type == content_type
                    } else {
                        !extension.is_empty() && association.extension == extension
                    }
            })
        }) {
            return Some(application.bundle_id.clone());
        }
    }
    None
}

fn matching_handlers<'a>(
    user_associations: &[Association],
    applications: &'a [InstalledApplication],
    extension: &str,
    content_type: &str,
    roles: u16,
) -> Vec<&'a InstalledApplication> {
    let mut bundles = Vec::new();
    if let Some(default) = resolve_bundle(
        user_associations,
        applications,
        extension,
        content_type,
        roles,
    ) {
        bundles.push(default);
    }
    for association in user_associations.iter().rev() {
        if association_matches(association, extension, content_type, roles)
            && !bundles.contains(&association.bundle_id)
        {
            bundles.push(association.bundle_id.clone());
        }
    }
    for application in applications {
        if application
            .associations
            .iter()
            .any(|association| association_matches(association, extension, content_type, roles))
            && !bundles.contains(&application.bundle_id)
        {
            bundles.push(application.bundle_id.clone());
        }
    }
    bundles
        .iter()
        .filter_map(|bundle| application_by_bundle(applications, bundle))
        .collect()
}

fn installed_applications() -> Vec<InstalledApplication> {
    let mut applications = fs::read_dir(APPLICATIONS_ROOT)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| read_installed_application(&entry.path()))
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for application in &applications {
        if !seen.insert(application.bundle_id.clone()) {
            duplicates.insert(application.bundle_id.clone());
        }
    }
    applications.retain(|application| !duplicates.contains(&application.bundle_id));
    applications.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
            .then_with(|| left.bundle_id.cmp(&right.bundle_id))
    });
    applications
}

fn read_installed_application(root: &Path) -> Option<InstalledApplication> {
    if !root.is_dir() {
        return None;
    }
    let about = fs::read_to_string(root.join("about.toml")).ok()?;
    let name = parse_string_field(&about, "name")?;
    let bundle_id = parse_string_field(&about, "bundle_id")
        .or_else(|| parse_string_field(&about, "bundle-id"))?;
    let entry = parse_string_field(&about, "entry")?;
    if name.is_empty()
        || name.len() > protocol::MAX_HANDLER_NAME_LEN
        || name.chars().any(char::is_control)
        || !valid_identifier(&bundle_id, protocol::MAX_BUNDLE_ID_LEN)
        || !valid_relative_entry(&entry)
    {
        return None;
    }
    let entry_path = root.join(&entry).to_str()?.to_owned();
    if !Path::new(&entry_path).is_file() {
        return None;
    }
    let roles = parse_document_roles(&parse_string_array_field(&about, "document_roles"));
    if roles == 0 {
        return None;
    }
    let mut associations = Vec::new();
    let mut seen = BTreeSet::new();
    for extension in parse_string_array_field(&about, "document_extensions") {
        let extension = extension.trim_start_matches('.').to_ascii_lowercase();
        if valid_identifier(&extension, protocol::MAX_EXTENSION_LEN)
            && seen.insert((extension.clone(), String::new()))
        {
            associations.push(Association {
                extension,
                content_type: String::new(),
                bundle_id: bundle_id.clone(),
                roles,
            });
        }
    }
    for content_type in parse_string_array_field(&about, "document_content_types") {
        let content_type = content_type.to_ascii_lowercase();
        if valid_content_type(&content_type) && seen.insert((String::new(), content_type.clone())) {
            associations.push(Association {
                extension: String::new(),
                content_type,
                bundle_id: bundle_id.clone(),
                roles,
            });
        }
    }
    (!associations.is_empty()).then_some(InstalledApplication {
        name,
        bundle_id,
        entry_path,
        associations,
    })
}

fn valid_relative_entry(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn parse_document_roles(values: &[String]) -> u16 {
    values.iter().fold(0, |roles, value| {
        roles
            | match value.as_str() {
                "view" => protocol::ASSOCIATION_ROLE_VIEW,
                "edit" => protocol::ASSOCIATION_ROLE_EDIT,
                _ => 0,
            }
    })
}

fn parse_string_field(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let (field, value) = line.trim().split_once('=')?;
        (field.trim() == key)
            .then(|| parse_string_literals(value).into_iter().next())
            .flatten()
    })
}

fn parse_string_array_field(content: &str, key: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut in_array = false;
    for line in content.lines().map(str::trim) {
        if in_array {
            values.extend(parse_string_literals(line));
            in_array = !line.contains(']');
            continue;
        }
        let Some((field, value)) = line.split_once('=') else {
            continue;
        };
        if field.trim() != key {
            continue;
        }
        values.extend(parse_string_literals(value));
        in_array = value.contains('[') && !value.contains(']');
    }
    values
}

fn parse_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for character in text.chars() {
        if !in_string {
            if character == '"' {
                in_string = true;
                current.clear();
            }
            continue;
        }
        if escaped {
            current.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            values.push(current.clone());
            current.clear();
            in_string = false;
        } else {
            current.push(character);
        }
    }
    values
}

fn launch_application(application: &InstalledApplication, document: &str) -> Result<u64, u64> {
    let service = platform::process::find_by_name(CAPABILITY_SERVICE_NAME)
        .map_err(|error| error.errno().unwrap_or(mochi_user_syscall::ENOENT as u64))?;
    if service == 0 {
        return Err(mochi_user_syscall::ENOENT as u64);
    }
    let mut items = vec![application.entry_path.clone(), document.to_owned()];
    for name in SESSION_ENVIRONMENT_NAMES {
        if let Ok(value) = std::env::var(name)
            && !value.as_bytes().contains(&0)
        {
            items.push(format!("{EXEC_MANIFEST_ENV_PREFIX}{name}={value}"));
        }
    }
    if items.iter().any(|item| item.as_bytes().contains(&0)) {
        return Err(mochi_user_syscall::EINVAL as u64);
    }
    let payload_len = items.iter().map(|item| item.len() + 1).sum::<usize>();
    let mut request = vec![0u8; SPAWN_APP_HEADER_LEN + payload_len];
    request[0..4].copy_from_slice(&SPAWN_APP_OPCODE.to_le_bytes());
    let mut cursor = SPAWN_APP_HEADER_LEN;
    for item in items {
        request[cursor..cursor + item.len()].copy_from_slice(item.as_bytes());
        cursor += item.len() + 1;
    }
    let mut reply = [0u8; 16];
    let message = platform::ipc::call(service, &request, &mut reply)
        .map_err(|error| error.errno().unwrap_or(mochi_user_syscall::EIO as u64))?;
    if (message & 0xffff_ffff) as usize != reply.len() {
        return Err(mochi_user_syscall::EINVAL as u64);
    }
    let status = u64::from_le_bytes(reply[..8].try_into().unwrap_or_default());
    let process_id = u64::from_le_bytes(reply[8..].try_into().unwrap_or_default());
    if status != 0 {
        return Err(status);
    }
    if process_id == 0 {
        return Err(mochi_user_syscall::EINVAL as u64);
    }
    Ok(process_id)
}

fn association_path() -> PathBuf {
    let user = std::env::var("USER")
        .ok()
        .filter(|value| valid_identifier(value, 64))
        .unwrap_or_else(|| "unknown".to_owned());
    Path::new("/var/config/workspace")
        .join(user)
        .join("associations.db")
}

fn encode_associations(associations: &[Association]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(DATABASE_MAGIC);
    output.extend_from_slice(&(associations.len() as u32).to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    for association in associations {
        let extension = association.extension.as_bytes();
        let content_type = association.content_type.as_bytes();
        let bundle = association.bundle_id.as_bytes();
        if extension.len() > u16::MAX as usize
            || content_type.len() > u16::MAX as usize
            || bundle.len() > u16::MAX as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "association field too long",
            ));
        }
        output.extend_from_slice(&association.roles.to_le_bytes());
        output.extend_from_slice(&(extension.len() as u16).to_le_bytes());
        output.extend_from_slice(&(content_type.len() as u16).to_le_bytes());
        output.extend_from_slice(&(bundle.len() as u16).to_le_bytes());
        output.extend_from_slice(extension);
        output.extend_from_slice(content_type);
        output.extend_from_slice(bundle);
    }
    Ok(output)
}

fn decode_associations(bytes: &[u8]) -> io::Result<Vec<Association>> {
    if bytes.len() < 16 || bytes.get(..8) != Some(DATABASE_MAGIC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "association database header",
        ));
    }
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or_default()) as usize;
    let mut offset = 16usize;
    let mut associations = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let header = bytes
            .get(offset..offset + 8)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "association header"))?;
        let roles = u16::from_le_bytes([header[0], header[1]]);
        let extension_len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let content_len = u16::from_le_bytes([header[4], header[5]]) as usize;
        let bundle_len = u16::from_le_bytes([header[6], header[7]]) as usize;
        let end = offset
            .checked_add(8)
            .and_then(|value| value.checked_add(extension_len))
            .and_then(|value| value.checked_add(content_len))
            .and_then(|value| value.checked_add(bundle_len))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "association length"))?;
        let payload = bytes
            .get(offset..end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "association record"))?;
        let mut request = Vec::with_capacity(payload.len());
        request.extend_from_slice(&roles.to_le_bytes());
        request.extend_from_slice(&(extension_len as u16).to_le_bytes());
        request.extend_from_slice(&(content_len as u16).to_le_bytes());
        request.extend_from_slice(&(bundle_len as u16).to_le_bytes());
        request.extend_from_slice(&payload[8..]);
        let association = decode_association_request(&request)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "association record"))?;
        associations.push(association);
        offset = end;
    }
    if offset != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "association trailing data",
        ));
    }
    Ok(associations)
}

fn persist_associations(path: &Path, associations: &[Association]) -> io::Result<()> {
    let bytes = encode_associations(associations)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "association parent"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = path.with_extension("db.new");
    let backup = path.with_extension("db.old");
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    let _ = fs::remove_file(&backup);
    let had_database = fs::rename(path, &backup).is_ok();
    if let Err(error) = fs::rename(&temporary, path) {
        if had_database {
            let _ = fs::rename(&backup, path);
        }
        return Err(error);
    }
    let _ = fs::remove_file(&backup);
    Ok(())
}

fn errno(error: io::Error) -> u64 {
    error
        .raw_os_error()
        .unwrap_or(mochi_user_syscall::EIO as i32) as u64
}

fn main() {
    let _ = platform::logger::init_from_env();
    platform::logln!("workspace.service: start");
    let Some(ready_target) = platform::service_ready::take_bootstrap_target() else {
        platform::logln!("workspace.service: missing ready target");
        platform::process::exit(1);
    };
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let status = -(i32::try_from(error.raw().unsigned_abs()).unwrap_or(i32::MAX));
            let _ = platform::service_ready::notify(ready_target, status);
            platform::process::exit(1)
        }
    };
    let mut service = WorkspaceService::load();
    if platform::service_ready::notify(ready_target, 0).is_err() {
        platform::logln!("workspace.service: ready notification failed");
        platform::process::exit(1);
    }
    platform::logln!(
        "workspace.service: ready associations={}",
        service.associations.len()
    );
    let mut buffer = vec![0u8; protocol::MAX_MESSAGE_LEN];
    loop {
        let message = match platform::ipc::wait(endpoint, &mut buffer) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        let request = match protocol::decode(&buffer[..length.min(buffer.len())]) {
            Ok(request) => request,
            Err(_) => {
                let mut reply = [0u8; protocol::HEADER_LEN + 24];
                if let Ok(length) = protocol::encode_status(
                    0,
                    -(mochi_user_syscall::EINVAL as i32),
                    service.clipboard_generation,
                    0,
                    &mut reply,
                ) {
                    let _ = platform::ipc::reply(sender, &reply[..length]);
                }
                continue;
            }
        };
        service.handle(sender, request);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn associations_round_trip_without_delimiter_ambiguity() {
        let associations = vec![Association {
            extension: "txt".into(),
            content_type: "text/plain".into(),
            bundle_id: "org.mochios.edit".into(),
            roles: protocol::ASSOCIATION_ROLE_ALL,
        }];
        let encoded = encode_associations(&associations).unwrap();
        assert_eq!(decode_associations(&encoded).unwrap(), associations);
    }

    #[test]
    fn association_request_rejects_invalid_bundle_identifier() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&protocol::ASSOCIATION_ROLE_EDIT.to_le_bytes());
        payload.extend_from_slice(&3u16.to_le_bytes());
        payload.extend_from_slice(&10u16.to_le_bytes());
        payload.extend_from_slice(&10u16.to_le_bytes());
        payload.extend_from_slice(b"txttext/plainbad bundle");
        assert!(decode_association_request(&payload).is_none());
    }

    fn application(
        name: &str,
        bundle_id: &str,
        extension: &str,
        content_type: &str,
    ) -> InstalledApplication {
        InstalledApplication {
            name: name.into(),
            bundle_id: bundle_id.into(),
            entry_path: format!("/applications/{name}.app/entry.elf"),
            associations: vec![Association {
                extension: extension.into(),
                content_type: content_type.into(),
                bundle_id: bundle_id.into(),
                roles: protocol::ASSOCIATION_ROLE_EDIT,
            }],
        }
    }

    #[test]
    fn user_default_overrides_installed_default() {
        let applications = vec![
            application("Edit", "org.mochios.edit", "txt", "text/plain"),
            application("Other", "org.example.other", "txt", "text/plain"),
        ];
        let user = vec![Association {
            extension: "txt".into(),
            content_type: String::new(),
            bundle_id: "org.example.other".into(),
            roles: protocol::ASSOCIATION_ROLE_EDIT,
        }];
        assert_eq!(
            resolve_bundle(
                &user,
                &applications,
                "txt",
                "text/plain",
                protocol::ASSOCIATION_ROLE_EDIT,
            ),
            Some("org.example.other".into())
        );
    }

    #[test]
    fn content_type_is_preferred_over_extension() {
        let applications = vec![
            application("Extension", "org.example.extension", "data", ""),
            application("Content", "org.example.content", "", "application/json"),
        ];
        assert_eq!(
            resolve_bundle(
                &[],
                &applications,
                "data",
                "application/json",
                protocol::ASSOCIATION_ROLE_EDIT,
            ),
            Some("org.example.content".into())
        );
    }

    #[test]
    fn handler_list_is_deduplicated_and_default_first() {
        let applications = vec![
            application("Edit", "org.mochios.edit", "txt", "text/plain"),
            application("Other", "org.example.other", "txt", "text/plain"),
        ];
        let user = vec![Association {
            extension: "txt".into(),
            content_type: String::new(),
            bundle_id: "org.example.other".into(),
            roles: protocol::ASSOCIATION_ROLE_EDIT,
        }];
        let handlers = matching_handlers(
            &user,
            &applications,
            "txt",
            "text/plain",
            protocol::ASSOCIATION_ROLE_EDIT,
        );
        assert_eq!(
            handlers
                .iter()
                .map(|application| application.bundle_id.as_str())
                .collect::<Vec<_>>(),
            vec!["org.example.other", "org.mochios.edit"]
        );
    }

    #[test]
    fn document_open_requires_absolute_path_and_valid_content_type() {
        let encode = |path: &str, content_type: &str| {
            let mut payload = Vec::new();
            payload.extend_from_slice(&protocol::ASSOCIATION_ROLE_EDIT.to_le_bytes());
            payload.extend_from_slice(&(path.len() as u16).to_le_bytes());
            payload.extend_from_slice(&(content_type.len() as u16).to_le_bytes());
            payload.extend_from_slice(&0u16.to_le_bytes());
            payload.extend_from_slice(path.as_bytes());
            payload.extend_from_slice(content_type.as_bytes());
            payload
        };
        assert!(decode_document_open(&encode("/home/user/note.txt", "text/plain")).is_some());
        assert!(decode_document_open(&encode("note.txt", "text/plain")).is_none());
        assert!(decode_document_open(&encode("/home/user/note.txt", "not a type")).is_none());
    }

    #[test]
    fn about_document_declarations_are_parsed_without_section_leakage() {
        let about = r#"
            name = "Edit"
            document_roles = ["view", "edit"]
            document_extensions = [
                "txt",
                "toml",
            ]
        "#;
        assert_eq!(parse_string_field(about, "name"), Some("Edit".into()));
        assert_eq!(
            parse_string_array_field(about, "document_extensions"),
            vec!["txt", "toml"]
        );
        assert_eq!(
            parse_document_roles(&parse_string_array_field(about, "document_roles")),
            protocol::ASSOCIATION_ROLE_ALL
        );
    }
}
