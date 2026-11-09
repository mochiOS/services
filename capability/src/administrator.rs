//! One retained administrative operation, completed only by the common consent
//! controller and user.service's password verifier. No ambient elevation token.
use crate::{consent_peer::Peer, image_catalog::Catalog, resolver::ApplicationIdentity};
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use mochi_user_platform as p;
use mochios_posix_client::{Client, EndpointTransport, ObjectHandleAttachment};
use p::capability::{administrator as wire, consent};
use p::syscall::{NativeError, SysError};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn denied() -> SysError {
    SysError::from(NativeError::AccessDenied.into_raw())
}
fn invalid() -> SysError {
    SysError::from(NativeError::InvalidArgument.into_raw())
}
struct Reference(u32);
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = p::handle::close(self.0);
    }
}

pub(crate) struct Request {
    identity: ApplicationIdentity,
    capabilities: Vec<String>,
    digest: [u8; 32],
    username: String,
    description: String,
    action: Operation,
}
enum Operation {
    Package {
        prepared: crate::package_approval::Prepared,
        approvals: crate::package_approval::Shared,
    },
    Account {
        payload: Zeroizing<Vec<u8>>,
    },
    Run {
        packet: Zeroizing<Vec<u8>>,
        scope: Reference,
        objects: Vec<Reference>,
        stdio: crate::app_stdio::Stdio,
        catalog: Catalog,
    },
}
impl Request {
    pub(crate) fn account(peer: &Peer, bytes: &[u8]) -> Result<(Self, Vec<u8>), SysError> {
        if p::capability::check_thread(peer.instance.endpoint, "account.other.modify") != Ok(1) {
            return Err(denied());
        }
        let bytes = wire::decode_operation(bytes).map_err(|_| invalid())?;
        let description = account_description(bytes)?;
        let identity = caller_identity(peer)?;
        let source = description.as_bytes().to_vec();
        Ok((
            Self {
                identity,
                capabilities: vec!["account.other.modify".into()],
                digest: Sha256::digest(&source).into(),
                username: username(peer),
                description,
                action: Operation::Account {
                    payload: Zeroizing::new(bytes.to_vec()),
                },
            },
            source,
        ))
    }
    pub(crate) fn package(
        peer: &Peer,
        bytes: &[u8],
        objects: &mut p::ipc::IpcObjectHandles,
        approvals: crate::package_approval::Shared,
    ) -> Result<(Self, Vec<u8>), SysError> {
        let prepared = crate::package_approval::Prepared::capture(peer, bytes, objects)?;
        let source = prepared.bytes.clone();
        let request = Self {
            identity: caller_identity(peer)?,
            capabilities: vec![prepared.capability().into()],
            digest: Sha256::digest(&source).into(),
            username: username(peer),
            description: prepared.description(),
            action: Operation::Package {
                prepared,
                approvals,
            },
        };
        Ok((request, source))
    }
    fn required(&self) -> &'static str {
        match &self.action {
            Operation::Package { prepared, .. } => prepared.capability(),
            Operation::Run { .. } => "process.spawn",
            Operation::Account { .. } => "account.other.modify",
        }
    }
    pub(crate) fn run(
        index: &crate::package_index::PackageIndex,
        peer: &Peer,
        packet: &[u8],
        objects: &mut p::ipc::IpcObjectHandles,
    ) -> Result<(Self, Vec<u8>), SysError> {
        if index.duplicate
            || p::capability::check_thread(peer.instance.endpoint, "process.spawn") != Ok(1)
            || packet.len() < wire::HEADER
            || packet[..4] != wire::RUN_OPCODE.to_le_bytes()
            || packet[4..8] != 1u32.to_le_bytes()
            || !objects.is_user_delivery()
            || objects.count != 4
            || objects.handles[0].reserved != 0
            || objects.handles[0].handle == 0
            || objects.handles[0].rights != mochios_posix_protocol::read_scope::ATTACH_RIGHTS
        {
            return Err(invalid());
        }
        let packet = &packet[8..];
        let request = p::capability::application_launch::decode(packet).map_err(|_| invalid())?;
        let stdio = crate::app_stdio::Stdio::new(&objects.handles[1..4], request.stdio_metadata)?;
        let scope = ObjectHandleAttachment {
            handle: objects.handles[0].handle,
            rights: objects.handles[0].rights,
        };
        let endpoint = Reference(crate::persistent_grant::launch_endpoint()?);
        let client = Client::new(EndpointTransport::new(endpoint.0));
        let info = client
            .read_scope_source_info(scope)
            .map_err(crate::app_image::remote)
            .map_err(crate::app_image::status)?;
        if info.process_id != peer.instance.process {
            return Err(denied());
        }
        let root = client
            .read_scope_open_executable(scope, true, request.path)
            .map_err(crate::app_image::remote)
            .map_err(crate::app_image::status)?;
        let root = Reference(root.handle);
        let source = crate::app_image::capture(root.0)?;
        // An index path is a hint; authenticate its bound manifest and compare
        // the captured bytes before any question is rendered.
        let digest: [u8; 32] = Sha256::digest(&source).into();
        let mut matched = None;
        for (path, record) in &index.by_binary {
            if crate::image_catalog::declared_root_binding(&record.manifest, path).is_ok_and(
                |binding| binding.digest == digest && binding.size == source.len() as u64,
            ) {
                if matched.is_some() {
                    return Err(denied());
                }
                matched = Some((path, record));
            }
        }
        let (identity, mut capabilities, catalog) = if let Some((path, record)) = matched {
            let verified = crate::resolver::verified_manifest(
                &record.manifest_path,
                crate::persistent_grant::read_file,
            )?;
            let capabilities = verified.decide_capabilities(path)?.into_allowed()?;
            let identity = verified.identity.clone();
            let catalog = Catalog::resolve(verified, path, |id| {
                let record = index
                    .by_package
                    .get(id)
                    .ok_or_else(|| SysError::from_raw(-2))?;
                crate::resolver::verified_manifest(
                    &record.manifest_path,
                    crate::persistent_grant::read_file,
                )
            })?;
            (identity, capabilities, catalog)
        } else {
            let evidence = crate::signed_image::verify_snapshot(None, &source)?;
            let selection = crate::standalone_image::select(&evidence)?;
            let (identity, capabilities, _) = selection.authority();
            let catalog = Catalog::standalone(
                request.path,
                &source,
                identity.clone(),
                evidence.manifest(),
                |id| {
                    let record = index
                        .by_package
                        .get(id)
                        .ok_or_else(|| SysError::from_raw(-2))?;
                    crate::resolver::verified_manifest(
                        &record.manifest_path,
                        crate::persistent_grant::read_file,
                    )
                },
            )?;
            (identity.clone(), capabilities.to_vec(), catalog)
        };
        // sudo assigns a POSIX administrator filesystem scope. It does not
        // turn arbitrary code into a native policy/device/security broker.
        for cap in &capabilities {
            let safe = mnu_abi::capability::metadata(cap).is_some_and(|m| m.user_grantable)
                || matches!(
                    cap.as_str(),
                    "fs.read.all"
                        | "fs.write.all"
                        | "fs.read.applications"
                        | "ipc.client"
                        | "ipc.server"
                        | "process.spawn"
                        | "system.random.read"
                        | "system.time.read"
                        | "account.other.read"
                        | "account.other.modify"
                        | "package.install"
                        | "package.remove"
                        | "package.update"
                );
            if !safe {
                return Err(denied());
            }
        }
        for name in ["fs.read.all", "fs.write.all", "ipc.client", "process.spawn"] {
            if !capabilities.iter().any(|cap| cap == name) {
                capabilities.push(name.into());
            }
        }
        catalog.validate(
            mochios_posix_client::image_preparation::Source::Root,
            &source,
        )?;
        // Debug quoting escapes control bytes, so a path/argument cannot forge
        // the protected description or inject terminal escape sequences.
        let mut description = format!("Run as administrator: {:?}", request.path);
        for argument in request.arguments.iter().skip(1) {
            description.push_str(&format!(" {argument:?}"));
        }
        if description.len() > consent::question::MAX_DESCRIPTION {
            return Err(invalid());
        }
        let retained = objects.handles[..4]
            .iter_mut()
            .map(|object| {
                let reference = Reference(object.handle);
                object.handle = 0;
                reference
            })
            .collect::<Vec<_>>();
        let mut retained = retained.into_iter();
        let scope = retained.next().unwrap();
        Ok((
            Self {
                identity,
                capabilities,
                digest: Sha256::digest(&source).into(),
                username: username(peer),
                description,
                action: Operation::Run {
                    packet: Zeroizing::new(packet.to_vec()),
                    scope,
                    objects: retained.collect(),
                    stdio,
                    catalog,
                },
            },
            source,
        ))
    }
    pub(crate) fn authority(&self) -> (&ApplicationIdentity, &[String], &[u8; 32]) {
        (&self.identity, &self.capabilities, &self.digest)
    }
    pub(crate) fn is_run(&self) -> bool {
        matches!(self.action, Operation::Run { .. })
    }
    pub(crate) fn requirements(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"mochiOS administrator operation v1\0");
        hash.update(self.digest);
        match &self.action {
            Operation::Run { packet, .. } => hash.update(&packet[..]),
            Operation::Account { payload } => hash.update(&payload[..]),
            Operation::Package { prepared, .. } => hash.update(&prepared.bytes),
        }
        for capability in &self.capabilities {
            hash.update((capability.len() as u32).to_le_bytes());
            hash.update(capability.as_bytes());
        }
        hash.finalize().into()
    }
    pub(crate) fn question(&self) -> consent::question::Administrator<'_> {
        consent::question::Administrator {
            username: &self.username,
            description: &self.description,
        }
    }
    pub(crate) fn complete(
        self,
        source: &[u8],
        peer: &Peer,
        credentials: wire::Credentials<'_>,
        deadline: u64,
        binding: crate::consent::Binding,
        account: (u32, u64),
    ) -> Result<u64, SysError> {
        // Credentials are accepted only after consuming a fresh physical input
        // approval in execution_frontend. No plaintext-input RPC can get here.
        if crate::execution_grant::requester_account(peer)? != account {
            return Err(denied());
        }
        let mut request = Zeroizing::new(vec![0; mochios_user_protocol::MAX_MESSAGE_LEN]);
        let length = mochios_user_protocol::VerifyAdministrator {
            request_id: credentials.correlation.ticket.id,
            name: credentials.name,
            password: credentials.password,
        }
        .encode(&mut request)
        .map_err(|_| invalid())?;
        account_call(&request[..length]).map_err(|_| denied())?;
        let current = crate::consent_peer::capture(peer.instance.endpoint)?;
        if current.instance != peer.instance
            || !p::handle::same_object(current.process.0, peer.process.0)?
            || crate::execution_grant::requester_account(&current)? != account
            || p::time::monotonic_nanoseconds()? >= deadline
            || p::capability::check_thread(peer.instance.endpoint, self.required()) != Ok(1)
        {
            return Err(denied());
        }
        match self.action {
            Operation::Package {
                prepared,
                approvals,
            } => {
                prepared.approve(&approvals, peer, binding, deadline, account)?;
                Ok(0)
            }
            Operation::Account { payload } => {
                perform_account(&payload)?;
                Ok(0)
            }
            Operation::Run {
                packet,
                scope,
                objects,
                stdio,
                catalog,
            } => {
                let _owned_stdio = objects;
                let request =
                    p::capability::application_launch::decode(&packet).map_err(|_| invalid())?;
                let mut environment = vec![
                    format!("HOME={}", root_home()?),
                    "USER=root".to_string(),
                    "LOGNAME=root".to_string(),
                    "PATH=/bin:/system/bin".to_string(),
                ];
                for entry in request.environment.iter() {
                    let Some((name, _)) = entry.split_once('=') else {
                        return Err(invalid());
                    };
                    if matches!(name, "TERM" | "COLORTERM" | "LANG" | "TZ")
                        || name.starts_with("LC_")
                    {
                        environment.push(entry.to_string());
                    }
                }
                let arguments = crate::native_app::Arguments {
                    path: request.path,
                    arguments: request.arguments.iter().map(str::as_bytes).collect(),
                    environment: environment.iter().map(String::as_bytes).collect(),
                };
                let endpoint = Reference(crate::persistent_grant::launch_endpoint()?);
                crate::native_app::launch_captured(
                    None,
                    &arguments,
                    endpoint.0,
                    peer.instance.endpoint,
                    peer.instance.process,
                    ObjectHandleAttachment {
                        handle: scope.0,
                        rights: mochios_posix_protocol::read_scope::ATTACH_RIGHTS,
                    },
                    source,
                    &catalog,
                    &self.capabilities,
                    Some(&stdio),
                    true,
                )
            }
        }
    }
}
fn root_home() -> Result<String, SysError> {
    let mut bytes = [0; mochios_user_protocol::public_account::MAX_RECORD];
    let length = crate::persistent_grant::with_client(|client| {
        client.lookup_account(
            mochios_user_protocol::public_account::Query::Uid(0),
            &mut bytes,
        )
    })?;
    let root = mochios_user_protocol::public_account::decode_record(&bytes[..length])
        .map_err(|_| invalid())?;
    if root.uid != 0 || root.gid != 0 || root.name != "root" || !root.home.starts_with('/') {
        return Err(denied());
    }
    Ok(root.home.to_string())
}
fn username(peer: &Peer) -> String {
    let mut bytes = [0; mochios_user_protocol::public_account::MAX_RECORD];
    let result = crate::persistent_grant::with_client(|client| {
        let info = client.process_session_info(ObjectHandleAttachment {
            handle: peer.process.0,
            rights: mnu_abi::HANDLE_RIGHT_WAIT,
        })?;
        client.lookup_account(
            mochios_user_protocol::public_account::Query::Uid(info.real_uid),
            &mut bytes,
        )
    });
    result
        .ok()
        .and_then(|length| {
            mochios_user_protocol::public_account::decode_record(&bytes[..length]).ok()
        })
        .map(|account| account.name.to_string())
        .unwrap_or_default()
}
fn caller_identity(peer: &Peer) -> Result<ApplicationIdentity, SysError> {
    let context = &peer.context;
    Ok(ApplicationIdentity {
        package_id: core::str::from_utf8(
            context
                .package_id
                .get(..context.package_id_len as usize)
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?
        .into(),
        developer_id: core::str::from_utf8(
            context
                .developer_id
                .get(..context.developer_id_len as usize)
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?
        .into(),
        subject_key_id: context.subject_key_id,
        provenance: mochios_signature_protocol::InstallProvenance::Development,
    })
}
fn account_call(bytes: &[u8]) -> Result<(), SysError> {
    let service = p::execution_peer::capture(p::process::find_by_name("user.service")?)?;
    if service.context.provenance != 1
        || service.context.subject_key_id != [0; 32]
        || service
            .context
            .package_id
            .get(..service.context.package_id_len as usize)
            != Some(b"org.mochios.user")
    {
        return Err(denied());
    }
    let mut response = [0; mochios_user_protocol::STATUS_LEN];
    let mut objects = p::ipc::IpcObjectHandles::default();
    let result = p::ipc::call_object_handles(
        service.endpoint.try_into().map_err(|_| invalid())?,
        bytes,
        &mut response,
        &mut objects,
    );
    let unexpected = objects.count != 0 || objects.delivery_flags != 0;
    for object in objects
        .handles
        .iter()
        .take((objects.count as usize).min(objects.handles.len()))
    {
        if object.handle != 0 {
            let _ = p::handle::close(object.handle);
        }
    }
    let reply = result?;
    if unexpected || reply >> 32 != service.endpoint || reply as u32 as usize != response.len() {
        return Err(denied());
    }
    let current = p::execution_peer::capture(service.endpoint)?;
    if current.image != service.image
        || !p::handle::same_object(current.process.0, service.process.0)?
    {
        return Err(denied());
    }
    let status = mochios_user_protocol::Status::decode(&response).map_err(|_| invalid())?;
    let expected = u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| invalid())?);
    if status.request_id != expected {
        return Err(denied());
    }
    if status.status != 0 {
        return Err(SysError::from_raw(i64::from(status.status)));
    }
    Ok(())
}
fn account_description(bytes: &[u8]) -> Result<String, SysError> {
    use mochios_user_protocol as user;
    if bytes.starts_with(&wire::CREATE_ACCOUNT) {
        let (add, password) = wire::decode_create_account(bytes).map_err(|_| invalid())?;
        let user = managed_user(add, password)?;
        return Ok(format!(
            "Create user {:?} (UID {}, home {:?})",
            user.name, user.uid, user.home
        ));
    }
    if bytes.starts_with(&wire::AUTO_LOGIN) {
        let (enabled, name) = wire::decode_auto_login(bytes).map_err(|_| invalid())?;
        if !name.is_empty() {
            mochios_user_database::UserRecord::regular(name, 1000, 1000)
                .validate()
                .map_err(|_| invalid())?;
        }
        if enabled && name.is_empty() {
            return Err(invalid());
        }
        return Ok(format!(
            "{} automatic login for {:?}",
            if enabled { "Enable" } else { "Disable" },
            name
        ));
    }
    match user::decode_opcode(bytes).map_err(|_| invalid())? {
        user::Opcode::RemoveUser => Ok(format!(
            "Delete user {:?}",
            user::RemoveUser::decode(bytes).map_err(|_| invalid())?.name
        )),
        user::Opcode::SetPassword => Ok(format!(
            "Change password for {:?}",
            user::SetPassword::decode(bytes)
                .map_err(|_| invalid())?
                .name
        )),
        _ => Err(invalid()),
    }
}
fn managed_user(
    add: &[u8],
    password: &[u8],
) -> Result<mochios_user_database::UserRecord, SysError> {
    let add = mochios_user_protocol::AddUser::decode(add).map_err(|_| invalid())?;
    let password = mochios_user_protocol::SetPassword::decode(password).map_err(|_| invalid())?;
    let user =
        mochios_user_database::UserRecord::parse(add.encoded_record).map_err(|_| invalid())?;
    if user.uid < mochios_user_database::FIRST_REGULAR_UID
        || user.gid != user.uid
        || !user.locked
        || user.password_hash != "!"
        || user.home != format!("/home/{}", user.name)
        || user.shell != "/bin/msh"
        || password.name != user.name
    {
        return Err(invalid());
    }
    Ok(user)
}
fn io(error: std::io::Error) -> SysError {
    SysError::from_raw(mochios_posix_client::newlib_errno::to_status(
        error.raw_os_error().unwrap_or(5),
    ) as i64)
}
fn perform_account(bytes: &[u8]) -> Result<(), SysError> {
    account_description(bytes)?;
    if bytes.starts_with(&wire::CREATE_ACCOUNT) {
        let (add, password) = wire::decode_create_account(bytes).map_err(|_| invalid())?;
        let user = managed_user(add, password)?;
        account_call(add)?;
        // Keep a failed creation locked and assigned to this UID. Removing
        // the account here could hand an already-created home to a reused UID.
        // An administrator can retry the password operation or delete it.
        create_home(&user)?;
        return account_call(password);
    }
    if bytes.starts_with(&wire::AUTO_LOGIN) {
        use std::{
            fs,
            io::Write,
            os::unix::fs::{MetadataExt, PermissionsExt},
        };
        let (enabled, name) = wire::decode_auto_login(bytes).map_err(|_| invalid())?;
        if enabled {
            let mut record = [0; mochios_user_protocol::public_account::MAX_RECORD];
            crate::persistent_grant::with_client(|client| {
                client.lookup_account(
                    mochios_user_protocol::public_account::Query::Name(name),
                    &mut record,
                )
            })?;
        }
        let directory = "/var/config/account";
        let metadata = fs::symlink_metadata(directory).map_err(io)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(denied());
        }
        let temporary = format!(
            "{directory}/.administrator-{}.tmp",
            p::time::monotonic_nanoseconds()?
        );
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(io)?;
            file.set_permissions(fs::Permissions::from_mode(0o644))
                .map_err(io)?;
            write!(file, "auto_login={enabled}\nauto_login_user={name}\n").map_err(io)?;
            file.sync_all().map_err(io)?;
            fs::rename(&temporary, format!("{directory}/settings.conf")).map_err(io)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }
    account_call(bytes)
}
fn create_home(user: &mochios_user_database::UserRecord) -> Result<(), SysError> {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, chown},
    };
    let parent = fs::symlink_metadata("/home").map_err(io)?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err(denied());
    }
    fs::create_dir(&user.home).map_err(io)?;
    fs::set_permissions(&user.home, fs::Permissions::from_mode(0o700)).map_err(io)?;
    for name in [
        "Desktop",
        "Documents",
        "Downloads",
        "Movies",
        "Music",
        "Pictures",
    ] {
        let path = format!("{}/{name}", user.home);
        fs::create_dir(&path).map_err(io)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(io)?;
        chown(&path, Some(user.uid), Some(user.gid)).map_err(io)?;
    }
    chown(&user.home, Some(user.uid), Some(user.gid)).map_err(io)
}

impl crate::execution_approval::Administration for Request {
    fn authority(&self) -> (&ApplicationIdentity, &[String], &[u8; 32]) {
        self.authority()
    }
    fn requirements(&self) -> [u8; 32] {
        self.requirements()
    }
    fn is_run(&self) -> bool {
        self.is_run()
    }
    fn question(&self) -> consent::question::Administrator<'_> {
        self.question()
    }
    fn complete(
        self: alloc::boxed::Box<Self>,
        source: &[u8],
        peer: &Peer,
        credentials: wire::Credentials<'_>,
        deadline: u64,
        binding: crate::consent::Binding,
        account: (u32, u64),
    ) -> Result<u64, SysError> {
        (*self).complete(source, peer, credentials, deadline, binding, account)
    }
}
