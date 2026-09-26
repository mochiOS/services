use std::collections::{BTreeMap, BTreeSet};
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
const COMPOSITOR_SERVICE_NAME: &str = "compositor.service";
const FILES_ENTRY_PATH: &str = "/applications/Files.app/entry.elf";
const COMPOSITOR_BEGIN_PROCESS_MODAL: u32 = 124;
const COMPOSITOR_END_PROCESS_MODAL: u32 = 125;
const SPAWN_APP_OPCODE: u32 = 0x4150_5053;
const SPAWN_APP_HEADER_LEN: usize = 24;
const EXEC_MANIFEST_ENV_PREFIX: &str = "__MNU_EXEC_ENV=";
const SESSION_ENVIRONMENT_NAMES: [&str; 4] = ["HOME", "USER", "LOGNAME", "SHELL"];
const MAX_PENDING_FILE_PANELS: usize = 64;

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
struct PendingFilePanel {
    requester_endpoint: Option<u64>,
    grant_endpoint: u64,
    requester_process: u64,
    request_id: u64,
    picker_endpoint: Option<u64>,
    picker_request_id: u64,
    picker_process: u64,
    token: [u8; protocol::FILE_PANEL_TOKEN_LEN],
    mode: u16,
    executable: String,
    allowed_content_types: String,
}

#[derive(Debug)]
struct WorkspaceService {
    endpoint: u64,
    clipboard_generation: u64,
    clipboard_content_type: String,
    clipboard: Vec<u8>,
    transaction: Option<ClipboardTransaction>,
    next_transaction: u64,
    associations: Vec<Association>,
    association_path: PathBuf,
    pending_file_panels: Vec<PendingFilePanel>,
    next_file_panel_token: u64,
    application_endpoints: BTreeMap<u64, u64>,
}

impl WorkspaceService {
    fn load(endpoint: u64) -> Self {
        let association_path = association_path();
        let associations = fs::read(&association_path)
            .ok()
            .and_then(|bytes| decode_associations(&bytes).ok())
            .unwrap_or_default();
        Self {
            endpoint,
            clipboard_generation: 0,
            clipboard_content_type: String::new(),
            clipboard: Vec::new(),
            transaction: None,
            next_transaction: 1,
            associations,
            association_path,
            pending_file_panels: Vec::new(),
            next_file_panel_token: 1,
            application_endpoints: BTreeMap::new(),
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
            protocol::OP_FILE_PANEL
            | protocol::OP_FILE_PANEL_COMPLETE
            | protocol::OP_FILE_PANEL_FINISH
            | protocol::OP_FILE_PANEL_RETRY
            | protocol::OP_APPLICATION_REGISTER
            | protocol::OP_APPLICATION_ACTIVATE => "ipc.client",
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
            protocol::OP_FILE_PANEL => self.file_panel(sender, request),
            protocol::OP_FILE_PANEL_COMPLETE => self.file_panel_complete(sender, request),
            protocol::OP_FILE_PANEL_FINISH => self.file_panel_finish(sender, request),
            protocol::OP_FILE_PANEL_RETRY => self.file_panel_retry(sender, request),
            protocol::OP_APPLICATION_REGISTER => self.application_register(sender, request),
            protocol::OP_APPLICATION_ACTIVATE => self.application_activate(sender, request),
            _ => unreachable!(),
        }
    }

    fn application_register(&mut self, sender: u64, request: protocol::Message<'_>) {
        if request.payload.len() != 8 {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }
        let endpoint = protocol::read_u64(request.payload, 0).ok();
        let sender_process = platform::ipc::endpoint_owner_process(sender).ok();
        let endpoint_process =
            endpoint.and_then(|value| platform::ipc::endpoint_owner_process(value).ok());
        match (endpoint, sender_process, endpoint_process) {
            (Some(endpoint), Some(process), Some(owner))
                if endpoint != 0 && process != 0 && process == owner =>
            {
                self.application_endpoints.insert(process, endpoint);
                self.reply_status(sender, request.request_id, 0, 0);
            }
            _ => self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EACCES as i32),
                0,
            ),
        }
    }

    fn application_activate(&mut self, sender: u64, request: protocol::Message<'_>) {
        if request.payload.len() != 8 {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }
        let Ok(process) = protocol::read_u64(request.payload, 0) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        match self.signal_application_reopen(process) {
            Ok(_) => self.reply_status(sender, request.request_id, 0, 0),
            Err(status) => {
                self.reply_status(sender, request.request_id, -(status as i32), 0);
            }
        }
    }

    fn signal_application_reopen(&mut self, process: u64) -> Result<(), u64> {
        let Some(endpoint) = self.application_endpoints.get(&process).copied() else {
            return Err(mochi_user_syscall::ENOENT as u64);
        };
        const REOPEN: [u8; 16] = *b"MAPPREOPEN\0\0\0\0\0\0";
        platform::ipc::send(endpoint, &REOPEN)
            .map(|_| ())
            .map_err(|error| {
                self.application_endpoints.remove(&process);
                error.errno().unwrap_or(mochi_user_syscall::EIO as u64)
            })
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

    fn file_panel(&mut self, sender: u64, request: protocol::Message<'_>) {
        let Ok(options) = protocol::decode_file_panel_request(request.payload) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let Ok(context) = platform::process::thread_security_context(sender) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EPERM as i32),
                0,
            );
            return;
        };
        if context.process_id == 0
            || !options.executable.starts_with('/')
            || options.executable.as_bytes().contains(&0)
            || (!options.initial_directory.is_empty()
                && !options.initial_directory.starts_with('/'))
            || options.title.chars().any(char::is_control)
            || options.suggested_name.contains(['/', '\0'])
            || !valid_file_panel_content_types(options.allowed_content_types)
        {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }
        if self.pending_file_panels.len() >= MAX_PENDING_FILE_PANELS
            || self
                .pending_file_panels
                .iter()
                .any(|pending| pending.requester_process == context.process_id)
        {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::ENOSPC as i32),
                0,
            );
            return;
        }
        let token_counter = self.next_file_panel_token;
        self.next_file_panel_token = self.next_file_panel_token.wrapping_add(1).max(1);
        let mut token = [0u8; protocol::FILE_PANEL_TOKEN_LEN];
        token[..8].copy_from_slice(&token_counter.to_le_bytes());
        token[8..].copy_from_slice(&(sender ^ context.process_id).to_le_bytes());
        let mut launch_payload = vec![0u8; protocol::MAX_MESSAGE_LEN - protocol::HEADER_LEN];
        let launch_length = match protocol::encode_file_panel_request(options, &mut launch_payload)
        {
            Ok(length) => length,
            Err(_) => {
                self.reply_status(
                    sender,
                    request.request_id,
                    -(mochi_user_syscall::EINVAL as i32),
                    0,
                );
                return;
            }
        };
        let argument = format!(
            "--system-file-panel={}:{}:{}",
            self.endpoint,
            hex_encode(&token),
            hex_encode(&launch_payload[..launch_length])
        );
        let picker_process = match launch_executable(FILES_ENTRY_PATH, &[argument]) {
            Ok(process) => process,
            Err(status) => {
                self.reply_status(sender, request.request_id, -(status as i32), 0);
                return;
            }
        };
        if let Err(status) = set_process_modal(
            COMPOSITOR_BEGIN_PROCESS_MODAL,
            context.process_id,
            picker_process,
        ) {
            let _ = platform::process::kill(picker_process, 9);
            self.reply_status(sender, request.request_id, -(status as i32), 0);
            return;
        }
        self.pending_file_panels.push(PendingFilePanel {
            requester_endpoint: Some(sender),
            grant_endpoint: sender,
            requester_process: context.process_id,
            request_id: request.request_id,
            picker_endpoint: None,
            picker_request_id: 0,
            picker_process,
            token,
            mode: options.mode,
            executable: options.executable.to_owned(),
            allowed_content_types: options.allowed_content_types.to_owned(),
        });
        // The request intentionally remains unanswered until the trusted picker
        // reports a selection or cancellation.
    }

    fn file_panel_complete(&mut self, sender: u64, request: protocol::Message<'_>) {
        let Ok(result) = protocol::decode_file_panel_result(request.payload) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let sender_process = platform::ipc::endpoint_owner_process(sender).ok();
        let Some(index) = self.pending_file_panels.iter().position(|pending| {
            pending.token == result.token && sender_process == Some(pending.picker_process)
        }) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EACCES as i32),
                0,
            );
            return;
        };
        if result.status == 1 {
            let pending = self.pending_file_panels.remove(index);
            if let Some(endpoint) = pending.requester_endpoint {
                self.reply_file_panel_result(endpoint, pending.request_id, 1, pending.token, "");
            }
            self.reply_status(sender, request.request_id, 0, 0);
            let _ = set_process_modal(
                COMPOSITOR_END_PROCESS_MODAL,
                pending.requester_process,
                pending.picker_process,
            );
            let _ = self.signal_application_reopen(pending.requester_process);
            return;
        }
        if result.status != 0 {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }

        if self.pending_file_panels[index].requester_endpoint.is_none()
            || self.pending_file_panels[index].picker_endpoint.is_some()
        {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EAGAIN as i32),
                0,
            );
            return;
        }
        let outcome = {
            let pending = &self.pending_file_panels[index];
            validate_panel_selection(pending, result.path).and_then(|path| {
                grant_selected_path(pending, &path)?;
                Ok(path)
            })
        };
        let path = match outcome {
            Ok(path) => path,
            Err(status) => {
                // Keep both the requesting application and its picker alive so
                // the user can correct the selection and try again.
                self.reply_status(sender, request.request_id, -(status as i32), 0);
                return;
            }
        };
        let pending = &mut self.pending_file_panels[index];
        let requester_endpoint = pending
            .requester_endpoint
            .take()
            .expect("file panel requester checked above");
        let requester_request_id = pending.request_id;
        let token = pending.token;
        pending.picker_endpoint = Some(sender);
        pending.picker_request_id = request.request_id;
        self.reply_file_panel_result(requester_endpoint, requester_request_id, 0, token, &path);
        // The picker call remains blocked until the requesting application
        // confirms that it actually completed the open/save operation.
    }

    fn file_panel_finish(&mut self, sender: u64, request: protocol::Message<'_>) {
        let Ok(finish) = protocol::decode_file_panel_finish(request.payload) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        };
        let sender_process = platform::ipc::endpoint_owner_process(sender).ok();
        let Some(index) = self.pending_file_panels.iter().position(|pending| {
            pending.token == finish.token
                && sender_process == Some(pending.requester_process)
                && pending.requester_endpoint.is_none()
                && pending.picker_endpoint.is_some()
        }) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EACCES as i32),
                0,
            );
            return;
        };

        if finish.status == 1 {
            let pending = &mut self.pending_file_panels[index];
            let picker_endpoint = pending
                .picker_endpoint
                .take()
                .expect("file panel picker checked above");
            let picker_request_id = pending.picker_request_id;
            pending.picker_request_id = 0;
            self.reply_status(
                picker_endpoint,
                picker_request_id,
                -(mochi_user_syscall::EIO as i32),
                0,
            );
            self.reply_status(sender, request.request_id, 0, 0);
            return;
        }

        let pending = self.pending_file_panels.remove(index);
        let picker_endpoint = pending
            .picker_endpoint
            .expect("file panel picker checked above");
        self.reply_status(picker_endpoint, pending.picker_request_id, 0, 0);
        self.reply_status(sender, request.request_id, 0, 0);
        let _ = set_process_modal(
            COMPOSITOR_END_PROCESS_MODAL,
            pending.requester_process,
            pending.picker_process,
        );
        let _ = self.signal_application_reopen(pending.requester_process);
    }

    fn file_panel_retry(&mut self, sender: u64, request: protocol::Message<'_>) {
        if request.payload.len() != protocol::FILE_PANEL_TOKEN_LEN {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EINVAL as i32),
                0,
            );
            return;
        }
        let sender_process = platform::ipc::endpoint_owner_process(sender).ok();
        let Some(pending) = self.pending_file_panels.iter_mut().find(|pending| {
            pending.token.as_slice() == request.payload
                && sender_process == Some(pending.requester_process)
        }) else {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EACCES as i32),
                0,
            );
            return;
        };
        if pending.requester_endpoint.is_some() || pending.picker_endpoint.is_some() {
            self.reply_status(
                sender,
                request.request_id,
                -(mochi_user_syscall::EAGAIN as i32),
                0,
            );
            return;
        }
        pending.requester_endpoint = Some(sender);
        pending.request_id = request.request_id;
        // This retry request remains unanswered until the picker submits a new
        // selection or is cancelled.
    }

    fn reply_file_panel_result(
        &self,
        sender: u64,
        request_id: u64,
        status: i32,
        token: [u8; protocol::FILE_PANEL_TOKEN_LEN],
        path: &str,
    ) {
        let mut payload = vec![0u8; protocol::FILE_PANEL_RESULT_PREFIX_LEN + path.len()];
        let Ok(length) = protocol::encode_file_panel_result(
            protocol::FilePanelResult {
                status,
                token,
                path,
            },
            &mut payload,
        ) else {
            self.reply_status(sender, request_id, -(mochi_user_syscall::EINVAL as i32), 0);
            return;
        };
        self.reply(
            sender,
            protocol::OP_FILE_PANEL_RESULT,
            request_id,
            &payload[..length],
        );
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

fn valid_file_panel_content_types(value: &str) -> bool {
    value.is_empty()
        || value.split('\x1f').all(|content_type| {
            content_type.len() <= protocol::MAX_CONTENT_TYPE_LEN && valid_content_type(content_type)
        })
}

fn validate_panel_selection(pending: &PendingFilePanel, selected: &str) -> Result<String, u64> {
    if selected.is_empty() || !selected.starts_with('/') || selected.as_bytes().contains(&0) {
        return Err(mochi_user_syscall::EINVAL as u64);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok())
        .ok_or(mochi_user_syscall::EACCES as u64)?;
    let path = Path::new(selected);
    let validated = if pending.mode == protocol::FILE_PANEL_MODE_OPEN {
        let canonical = fs::canonicalize(path).map_err(errno)?;
        if !canonical.is_file() {
            return Err(mochi_user_syscall::EISDIR as u64);
        }
        canonical
    } else {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty() && *name != "." && *name != "..")
            .ok_or(mochi_user_syscall::EINVAL as u64)?;
        let parent = path.parent().ok_or(mochi_user_syscall::EINVAL as u64)?;
        let parent = fs::canonicalize(parent).map_err(errno)?;
        if !parent.is_dir() {
            return Err(mochi_user_syscall::ENOTDIR as u64);
        }
        let destination = parent.join(name);
        if destination.is_dir() {
            return Err(mochi_user_syscall::EISDIR as u64);
        }
        destination
    };
    if !validated.starts_with(&home) {
        return Err(mochi_user_syscall::EACCES as u64);
    }
    if !selection_matches_content_types(&validated, &pending.allowed_content_types) {
        return Err(mochi_user_syscall::EINVAL as u64);
    }
    validated
        .to_str()
        .map(str::to_owned)
        .ok_or(mochi_user_syscall::EINVAL as u64)
}

fn selection_matches_content_types(path: &Path, allowed: &str) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let actual = match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "txt" | "text" | "log" => "text/plain;charset=utf-8",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" | "cjs" => "text/javascript",
        "md" | "markdown" => "text/markdown",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    };
    allowed.split('\x1f').any(|candidate| {
        candidate == actual
            || candidate == "application/octet-stream"
            || (candidate == "text/plain" && actual.starts_with("text/plain;"))
    })
}

fn grant_selected_path(pending: &PendingFilePanel, path: &str) -> Result<(), u64> {
    let service = platform::process::find_by_name(CAPABILITY_SERVICE_NAME)
        .map_err(|error| error.errno().unwrap_or(mochi_user_syscall::ENOENT as u64))?;
    if service == 0 {
        return Err(mochi_user_syscall::ENOENT as u64);
    }
    let capability = if pending.mode == protocol::FILE_PANEL_MODE_SAVE {
        "fs.write.user"
    } else {
        "fs.read.user"
    };
    let request = platform::capability::CapabilityRequest::new_prompt(
        pending.requester_process,
        &pending.executable,
        [0; 32],
        capability,
        Some(path),
        Some(if pending.mode == protocol::FILE_PANEL_MODE_SAVE {
            "Save the selected file"
        } else {
            "Open the selected file"
        }),
        true,
        platform::capability::CapabilityClass::UserGrantable,
    )
    .map_err(|_| mochi_user_syscall::EINVAL as u64)?;
    let mut decision = platform::capability::CapabilityDecisionRequest::new(
        platform::capability::CapabilityDecision::AllowForProcess,
        request,
    );
    decision.reserved = pending.grant_endpoint;
    let mut encoded =
        vec![0u8; core::mem::size_of::<platform::capability::CapabilityDecisionRequest>()];
    let length = platform::capability::encode_decision_request(&decision, &mut encoded)
        .map_err(|_| mochi_user_syscall::EINVAL as u64)?;
    let mut reply = [0u8; 8];
    let message = platform::ipc::call(service, &encoded[..length], &mut reply)
        .map_err(|error| error.errno().unwrap_or(mochi_user_syscall::EIO as u64))?;
    if (message & 0xffff_ffff) as usize != reply.len() {
        return Err(mochi_user_syscall::EINVAL as u64);
    }
    let status = u64::from_le_bytes(reply);
    if status == 0 { Ok(()) } else { Err(status) }
}

fn set_process_modal(opcode: u32, owner_process: u64, modal_process: u64) -> Result<(), u64> {
    if !matches!(
        opcode,
        COMPOSITOR_BEGIN_PROCESS_MODAL | COMPOSITOR_END_PROCESS_MODAL
    ) || owner_process == 0
        || modal_process == 0
        || owner_process == modal_process
    {
        return Err(mochi_user_syscall::EINVAL as u64);
    }
    let compositor = platform::process::find_by_name(COMPOSITOR_SERVICE_NAME)
        .map_err(|error| error.errno().unwrap_or(mochi_user_syscall::ENOENT as u64))?;
    if compositor == 0 {
        return Err(mochi_user_syscall::ENOENT as u64);
    }
    let mut request = [0u8; 20];
    request[..4].copy_from_slice(&opcode.to_le_bytes());
    request[4..12].copy_from_slice(&owner_process.to_le_bytes());
    request[12..20].copy_from_slice(&modal_process.to_le_bytes());
    let mut reply = [0u8; 16];
    let message = platform::ipc::call(compositor, &request, &mut reply)
        .map_err(|error| error.errno().unwrap_or(mochi_user_syscall::EIO as u64))?;
    let length = (message & 0xffff_ffff) as usize;
    let status = reply
        .get(..length)
        .and_then(|bytes| bytes.get(..4))
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .ok_or(mochi_user_syscall::EIO as u64)?;
    if status == 0 {
        Ok(())
    } else {
        Err(u64::from(status))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
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
    launch_executable(&application.entry_path, &[document.to_owned()])
}

fn launch_executable(executable: &str, arguments: &[String]) -> Result<u64, u64> {
    let service = platform::process::find_by_name(CAPABILITY_SERVICE_NAME)
        .map_err(|error| error.errno().unwrap_or(mochi_user_syscall::ENOENT as u64))?;
    if service == 0 {
        return Err(mochi_user_syscall::ENOENT as u64);
    }
    let mut items = Vec::with_capacity(1 + arguments.len() + SESSION_ENVIRONMENT_NAMES.len());
    items.push(executable.to_owned());
    items.extend(arguments.iter().cloned());
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
    let mut service = WorkspaceService::load(endpoint);
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
    fn file_panel_content_filters_match_appkit_inference() {
        assert!(selection_matches_content_types(
            Path::new("/home/user/note.txt"),
            "text/plain"
        ));
        assert!(selection_matches_content_types(
            Path::new("/home/user/data.json"),
            "text/plain\x1fapplication/json"
        ));
        assert!(!selection_matches_content_types(
            Path::new("/home/user/image.png"),
            "text/plain"
        ));
        assert!(selection_matches_content_types(
            Path::new("/home/user/unknown.bin"),
            "application/octet-stream"
        ));
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
