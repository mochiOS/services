//! Provision a default private writable directory for the authenticated app.
//! Every namespace step uses a retained directory and nofollow; text supplied
//! by the app never chooses its owner, publisher, account or storage location.
use mochi_user_platform as p;
use mochios_posix_client::{ClientError, ObjectHandleAttachment, OpenAtBase};
use mochios_posix_protocol as posix;
type Error = p::syscall::SysError;
struct Owned(u32);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = p::handle::close(self.0);
    }
}
fn denied() -> Error {
    Error::from_raw(-13)
}
pub(crate) fn request(
    sender: u64,
    bytes: &[u8],
    attached: &p::ipc::IpcObjectHandles,
) -> Result<ObjectHandleAttachment<u32>, Error> {
    if bytes != p::capability::application_data::REQUEST
        || attached.count != 0
        || !attached.is_user_delivery()
    {
        return Err(denied());
    }
    let peer = p::execution_peer::capture(sender)?;
    let context = crate::persistent_grant::requester_context(sender)?;
    let native = &peer.context;
    if native.process_id != context.process_id || !matches!(native.provenance, 1..=3) {
        return Err(denied());
    }
    let parts = crate::application_data_identity::namespace(
        native,
        context.effective_uid,
        context.account_generation,
    )
    .ok_or_else(denied)?;
    let package = parts[2].as_str();
    let result = crate::persistent_grant::with_client(|client| {
        let session = client.process_session_info(ObjectHandleAttachment {
            handle: peer.process.0,
            rights: p::handle::HANDLE_RIGHT_WAIT,
        })?;
        if session.real_uid != session.effective_uid
            || session.effective_uid != context.effective_uid
        {
            return Err(ClientError::Remote(-13));
        }
        let mut directory = client.open_at(
            OpenAtBase::ProcessRoot,
            posix::OPEN_READ | posix::OPEN_DIRECTORY | posix::OPEN_NOFOLLOW,
            0,
            "/",
        )?;
        let mut owned = Owned(directory.handle);
        for (i, part) in parts.iter().enumerate() {
            let last = i == parts.len() - 1;
            match client.mkdir_at(
                OpenAtBase::Directory(directory),
                if last { 0o700 } else { 0o755 },
                part,
            ) {
                Ok(()) | Err(ClientError::Remote(-17)) => {}
                Err(error) => return Err(error),
            }
            let flags = posix::OPEN_READ
                | posix::OPEN_DIRECTORY
                | posix::OPEN_NOFOLLOW
                | posix::OPEN_BENEATH
                | if last {
                    posix::OPEN_WRITE | posix::OPEN_DIRECTORY_AUTHORITY
                } else {
                    0
                };
            let child = client.open_at(OpenAtBase::Directory(directory), flags, 0, part)?;
            let child_owner = Owned(child.handle);
            let metadata = client.fstat(child)?;
            if metadata.mode & 0o170000 != 0o040000
                || metadata.uid != if last { session.effective_uid } else { 0 }
            {
                // A newly created final directory is still owned by this root
                // broker; it may be published only after ownership is fixed.
                if !last || metadata.uid != 0 {
                    return Err(ClientError::Remote(-13));
                }
            }
            if last {
                client.fchmod(child, 0o700)?;
                client.fchown(child, session.effective_uid, session.effective_gid)?;
            } else if metadata.mode & 0o022 != 0 {
                return Err(ClientError::Remote(-13));
            }
            client.fsync(child)?;
            client.fsync(directory)?;
            directory = child;
            owned = child_owner;
        }
        if native.provenance == 1
            && native.subject_key_id == [0; 32]
            && native.developer_id.get(..native.developer_id_len as usize)
                == Some(b"org.mochios.system")
        {
            import_legacy(
                client,
                directory,
                package,
                session.effective_uid,
                session.effective_gid,
            )?;
        }
        let current = p::execution_peer::capture(sender).map_err(ClientError::Transport)?;
        let current_session = client.process_session_info(ObjectHandleAttachment {
            handle: current.process.0,
            rights: p::handle::HANDLE_RIGHT_WAIT,
        })?;
        if current.context != peer.context
            || current.image != peer.image
            || !p::handle::same_object(current.process.0, peer.process.0)
                .map_err(ClientError::Transport)?
            || current_session.real_uid != session.real_uid
            || current_session.effective_uid != session.effective_uid
            || current_session.effective_gid != session.effective_gid
            || client.account_generation(session.effective_uid)? != context.account_generation
        {
            return Err(ClientError::Remote(-13));
        }
        let rights = p::handle::HANDLE_RIGHT_READ
            | p::handle::HANDLE_RIGHT_WRITE
            | p::handle::HANDLE_RIGHT_DUPLICATE
            | p::handle::HANDLE_RIGHT_TRANSFER;
        let handle =
            p::handle::duplicate(directory.handle, rights).map_err(ClientError::Transport)?;
        drop(owned);
        Ok(ObjectHandleAttachment { handle, rights })
    })?;
    Ok(result)
}

/// Import only known built-in app data. Originals remain untouched.
fn import_legacy(
    client: &mochios_posix_client::Client<mochios_posix_client::EndpointTransport>,
    directory: ObjectHandleAttachment<u32>,
    package: &str,
    uid: u32,
    gid: u32,
) -> Result<(), ClientError<Error>> {
    let (root, entries): (&str, &[(&str, u64)]) = match package {
        "org.mochios.calculator" => (
            "/libraries/applications/org.mochios.calculator/users",
            &[("start-mode", 64), ("history-v1", 512 * 1024)],
        ),
        "org.mochios.edit" => (
            "/var/config/applications/org.mochios.edit/users",
            &[("preferences.conf", 16 * 1024)],
        ),
        _ => return Ok(()),
    };
    let flags =
        posix::OPEN_READ | posix::OPEN_NOFOLLOW | posix::OPEN_NONBLOCK | posix::OPEN_BENEATH;
    match client.open_at(
        OpenAtBase::Directory(directory),
        flags,
        0,
        ".legacy-import-v1",
    ) {
        Ok(file) => {
            let _owned = Owned(file.handle);
            return Ok(());
        }
        Err(ClientError::Remote(-2)) => {}
        Err(error) => return Err(error),
    }
    let mut record = [0; posix::account::MAX_RECORD];
    let n = client.lookup_account(posix::account::Query::Uid(uid), &mut record)?;
    let account =
        posix::account::decode_record(&record[..n]).map_err(|_| ClientError::Remote(-5))?;
    let legacy_path = format!("{root}/{}", account.name);
    let legacy = match client.open_at(
        OpenAtBase::ProcessRoot,
        posix::OPEN_READ | posix::OPEN_DIRECTORY | posix::OPEN_NOFOLLOW,
        0,
        legacy_path,
    ) {
        Ok(legacy) => Some((legacy, Owned(legacy.handle))),
        Err(ClientError::Remote(-2)) => None,
        Err(error) => return Err(error),
    };
    if let Some((legacy, _)) = legacy.as_ref() {
        if client.fstat(*legacy)?.uid != uid {
            return Err(ClientError::Remote(-13));
        }
        for &(name, maximum) in entries {
            match client.open_at(OpenAtBase::Directory(directory), flags, 0, name) {
                Ok(file) => {
                    let _owned = Owned(file.handle);
                    continue;
                }
                Err(ClientError::Remote(-2)) => {}
                Err(error) => return Err(error),
            }
            let input = match client
                .open_at(OpenAtBase::Directory(*legacy), flags, 0, name)
                .or_else(|error| match error {
                    ClientError::Remote(-2) => client.open_at(
                        OpenAtBase::Directory(*legacy),
                        flags,
                        0,
                        if package == "org.mochios.edit" {
                            ".preferences.conf.backup".to_owned()
                        } else if name == "history-v1" {
                            "history-v1.previous".to_owned()
                        } else {
                            "start-mode.previous".to_owned()
                        },
                    ),
                    error => Err(error),
                }) {
                Ok(file) => file,
                Err(ClientError::Remote(-2)) => continue,
                Err(error) => return Err(error),
            };
            let _input = Owned(input.handle);
            let status = client.fstat(input)?;
            if status.uid != uid
                || status.mode & 0o170000 != 0o100000
                || status.size < 0
                || status.size as u64 > maximum
            {
                return Err(ClientError::Remote(-13));
            }
            let temporary = format!(".legacy-import-{name}");
            // This reserved name is confined to the newly private directory.
            match client.unlink_at(
                mochios_posix_client::StatAtBase::Directory(directory),
                0,
                &temporary,
            ) {
                Ok(()) | Err(ClientError::Remote(-2)) => {}
                Err(error) => return Err(error),
            }
            let output = client.open_at(
                OpenAtBase::Directory(directory),
                posix::OPEN_WRITE
                    | posix::OPEN_CREATE
                    | posix::OPEN_EXCLUSIVE
                    | posix::OPEN_NOFOLLOW
                    | posix::OPEN_BENEATH,
                0o600,
                &temporary,
            )?;
            let _output = Owned(output.handle);
            let result = (|| {
                let mut total = 0u64;
                let mut bytes = [0; 8192];
                loop {
                    let n = p::handle::read(input.handle, &mut bytes)
                        .map_err(ClientError::Transport)?;
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                    if total > maximum {
                        return Err(ClientError::Remote(-27));
                    }
                    let mut offset = 0;
                    while offset < n {
                        let count = p::handle::write(output.handle, &bytes[offset..n])
                            .map_err(ClientError::Transport)?;
                        if count == 0 {
                            return Err(ClientError::Remote(-5));
                        }
                        offset += count;
                    }
                }
                client.fchown(output, uid, gid)?;
                client.fsync(output)?;
                client.rename_at(
                    mochios_posix_client::StatAtBase::Directory(directory),
                    &temporary,
                    mochios_posix_client::StatAtBase::Directory(directory),
                    name,
                )?;
                client.fsync(directory)
            })();
            if result.is_err() {
                let _ = client.unlink_at(
                    mochios_posix_client::StatAtBase::Directory(directory),
                    0,
                    &temporary,
                );
            }
            result?;
        }
    }
    let marker = client.open_at(
        OpenAtBase::Directory(directory),
        posix::OPEN_WRITE
            | posix::OPEN_CREATE
            | posix::OPEN_EXCLUSIVE
            | posix::OPEN_NOFOLLOW
            | posix::OPEN_BENEATH,
        0o600,
        ".legacy-import-v1",
    )?;
    let _marker = Owned(marker.handle);
    client.fchown(marker, uid, gid)?;
    client.fsync(marker)?;
    client.fsync(directory)
}
