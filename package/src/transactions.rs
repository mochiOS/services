//! Prepared package objects own captured input and the installed base version.
//! Only the common broker can authorize one; COMMIT consumes that authorization
//! before touching installation paths. No UID-zero or capability-only bypass.
use super::*;
use mochios_posix_client::{ObjectHandleAttachment, StatAtBase};
use mochios_posix_protocol as posix;
use package_protocol::transaction as wire;
use platform::execution_peer::MeasuredPeer;
type Error = mochi_user_syscall::SysError;
struct Reference(u32);
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.0);
    }
}
const ROOT: &str = "/var/lib/package-transactions";
fn denied() -> Error {
    Error::from_raw(-13)
}
fn reference(handle: u32) -> ObjectHandleAttachment<u32> {
    ObjectHandleAttachment {
        handle,
        rights: platform::handle::HANDLE_RIGHT_TRANSFER,
    }
}

struct Snapshot {
    directory: String,
    path: String,
    size: u64,
    digest: [u8; 32],
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = posix_io::remove(&self.path);
        let _ = posix_io::with_client(|c| {
            c.unlink_at(
                StatAtBase::ProcessRoot,
                posix::UNLINK_REMOVE_DIRECTORY,
                &self.directory,
            )
        });
    }
}
fn session(process: u32) -> Result<posix::SessionInfo, Error> {
    posix_io::with_client(|c| {
        c.process_session_info(ObjectHandleAttachment {
            handle: process,
            rights: platform::handle::HANDLE_RIGHT_WAIT,
        })
    })
}
fn current(
    owner: &MeasuredPeer,
    sender: u64,
    credentials: posix::SessionInfo,
) -> Result<(), Error> {
    let peer = platform::execution_peer::capture(sender)?;
    if peer.image != owner.image
        || !platform::handle::same_object(peer.process.0, owner.process.0)?
        || session(peer.process.0)? != credentials
    {
        return Err(denied());
    }
    Ok(())
}
fn broker(sender: u64) -> Result<MeasuredPeer, Error> {
    let peer = platform::execution_peer::capture(sender)?;
    let c = &peer.context;
    if platform::capability::check_thread(sender, "capabilities.manage") != Ok(1)
        || c.provenance != 1
        || c.subject_key_id != [0; 32]
        || c.package_id.get(..c.package_id_len as usize) != Some(b"org.mochios.capability")
        || c.developer_id.get(..c.developer_id_len as usize) != Some(b"org.mochios.system")
    {
        return Err(denied());
    }
    Ok(peer)
}
fn directory() -> Result<(), Error> {
    match posix_io::create_dir(ROOT, 0o700) {
        Ok(()) => {}
        Err(error) if error.raw() == -17 => {}
        Err(error) => return Err(error),
    }
    let stat =
        posix_io::with_client(|c| c.stat_at(StatAtBase::ProcessRoot, posix::STAT_NOFOLLOW, ROOT))?;
    if stat.mode & 0o170000 != 0o040000 || stat.uid != 0 || stat.mode & 0o077 != 0 {
        return Err(denied());
    }
    Ok(())
}
fn capture(input: u32, id: u64) -> Result<Snapshot, Error> {
    let stat = posix_io::with_client(|c| c.fstat(reference(input)))?;
    let length = u64::try_from(stat.size).map_err(|_| invalid_request())?;
    if stat.mode & 0o170000 != 0o100000 || length == 0 || length > wire::MAX_PACKAGE_BYTES {
        return Err(invalid_request());
    }
    directory()?;
    let directory = alloc::format!("{ROOT}/{}-{id}", platform::time::monotonic_nanoseconds()?);
    posix_io::create_dir(&directory, 0o700)?;
    let mut snapshot = Snapshot {
        path: alloc::format!("{directory}/source.mpkg"),
        directory,
        size: length,
        digest: [0; 32],
    };
    let output = Reference(posix_io::open_path(
        &snapshot.path,
        O_WRONLY | O_CREAT | O_EXCL,
        0o600,
    )?);
    let mut buffer = [0; 16384];
    let mut offset = 0;
    let mut digest = Sha256::new();
    while offset < length {
        let wanted = buffer.len().min((length - offset) as usize);
        let count = platform::handle::read_at(input, &mut buffer[..wanted], offset)?;
        if count == 0 || count > wanted {
            return Err(Error::from_raw(-5));
        }
        digest.update(&buffer[..count]);
        let mut written = 0;
        while written < count {
            let n = platform::handle::write(output.0, &buffer[written..count])?;
            if n == 0 || n > count - written {
                return Err(Error::from_raw(-5));
            }
            written += n;
        }
        offset += count as u64;
    }
    if platform::handle::read_at(input, &mut [0], length)? != 0 {
        return Err(Error::from_raw(-5));
    }
    posix_io::sync(output.0)?;
    snapshot.digest = digest.finalize().into();
    Ok(snapshot)
}
fn hash_file(path: &str) -> Result<[u8; 32], Error> {
    let input = Reference(posix_io::open_path(path, 0, 0)?);
    let mut hash = Sha256::new();
    let mut buffer = [0; 16384];
    let mut offset = 0;
    loop {
        let n = platform::handle::read_at(input.0, &mut buffer, offset)?;
        if n == 0 {
            break;
        }
        offset += n as u64;
        if n > buffer.len() || offset > wire::MAX_PACKAGE_BYTES {
            return Err(invalid_request());
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash.finalize().into())
}
fn base(id: &str) -> Result<Option<([u8; 32], platform::package::PackageManifest, String)>, Error> {
    let root = alloc::format!("/var/lib/packages/{id}");
    let bytes = match posix_io::read_to_end_path(&alloc::format!("{root}/manifest.toml")) {
        Ok(bytes) => bytes,
        Err(error) if error.raw() == -2 => {
            require_path_absent(&alloc::format!("{root}/verification.bin"))?;
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let verification = posix_io::read_to_end_path(&alloc::format!("{root}/verification.bin"))?;
    let record = InstallRecordView::decode(&verification).map_err(|_| denied())?;
    let manifest = core::str::from_utf8(&bytes)
        .ok()
        .and_then(platform::package::parse_manifest)
        .ok_or_else(denied)?;
    if record.provenance == InstallProvenance::BuiltIn
        || manifest.package_id != id
        || record.verification.verified_package_id != id
        || record.verification.manifest_digest != Sha256::digest(&bytes).as_slice()
    {
        return Err(denied());
    }
    let mut hash = Sha256::new();
    hash.update(b"mochiOS installed package base v1\0");
    hash.update(Sha256::digest(&bytes));
    hash.update(Sha256::digest(&verification));
    Ok(Some((
        hash.finalize().into(),
        manifest,
        record.verification.developer_id.to_string(),
    )))
}
struct Entry {
    id: u64,
    owner: MeasuredPeer,
    credentials: posix::SessionInfo,
    deadline: u64,
    mutation: wire::Mutation,
    manifest: platform::package::PackageManifest,
    developer: String,
    snapshot: Option<Snapshot>,
    previous: [u8; 32],
}
impl Entry {
    fn write(&self, request: u64, bytes: &mut [u8]) -> Result<usize, Error> {
        wire::encode_plan(
            request,
            wire::Plan {
                mutation: self.mutation,
                source_digest: self
                    .snapshot
                    .as_ref()
                    .map(|s| s.digest)
                    .unwrap_or(self.previous),
                previous_digest: self.previous,
                package_id: &self.manifest.package_id,
                name: &self.manifest.package_name,
                version: &self.manifest.package_version,
                developer: &self.developer,
            },
            bytes,
        )
        .map_err(|_| invalid_request())
    }
    fn size(&self) -> u64 {
        self.snapshot.as_ref().map(|s| s.size).unwrap_or(0)
    }
}
#[derive(Default)]
pub(super) struct Registry {
    next: u64,
    entries: Vec<Entry>,
    recovered: bool,
}
impl Registry {
    pub fn maintain(&mut self, now: u64) {
        self.entries.retain(|entry| {
            now < entry.deadline
                && platform::process::handle_status(entry.owner.process.0)
                    .is_ok_and(|p| p.state != platform::process::PROCESS_STATE_EXITED)
        });
    }
    pub fn wait(&self, endpoint: u32) -> Result<(), Error> {
        let mut items = [platform::syscall::HandleWaitItem::default(); wire::MAX_PENDING + 1];
        items[0] = platform::syscall::HandleWaitItem {
            handle: endpoint,
            interests: mnu_abi::HANDLE_SIGNAL_READABLE,
            ..Default::default()
        };
        for (item, entry) in items[1..].iter_mut().zip(&self.entries) {
            *item = platform::syscall::HandleWaitItem {
                handle: entry.owner.process.0,
                interests: mnu_abi::HANDLE_SIGNAL_TERMINATED,
                ..Default::default()
            };
        }
        let deadline = self
            .entries
            .iter()
            .map(|entry| entry.deadline)
            .min()
            .unwrap_or(mnu_abi::HANDLE_WAIT_INFINITE);
        platform::process::wait_many(&mut items[..self.entries.len() + 1], deadline).map(|_| ())
    }
    fn recover_snapshots(&mut self) -> Result<(), Error> {
        if self.recovered {
            return Ok(());
        }
        directory()?;
        for name in posix_io::read_dir_names(ROOT)? {
            if name.split('-').count() != 2
                || !name.bytes().all(|c| c.is_ascii_digit() || c == b'-')
            {
                continue;
            }
            let path = alloc::format!("{ROOT}/{name}");
            let stat = posix_io::with_client(|c| {
                c.stat_at(StatAtBase::ProcessRoot, posix::STAT_NOFOLLOW, &path)
            })?;
            if stat.mode & 0o170000 != 0o040000 || stat.uid != 0 || stat.mode & 0o077 != 0 {
                continue;
            }
            let source = alloc::format!("{path}/source.mpkg");
            match posix_io::with_client(|c| {
                c.stat_at(StatAtBase::ProcessRoot, posix::STAT_NOFOLLOW, &source)
            }) {
                Ok(stat)
                    if stat.mode & 0o170000 == 0o100000
                        && stat.uid == 0
                        && stat.mode & 0o077 == 0 =>
                {
                    posix_io::remove(&source)?;
                }
                Err(error) if error.raw() == -2 => {}
                _ => continue,
            }
            // Never recurse through names or remove unknown contents.
            let _ = posix_io::with_client(|c| {
                c.unlink_at(
                    StatAtBase::ProcessRoot,
                    posix::UNLINK_REMOVE_DIRECTORY,
                    &path,
                )
            });
        }
        self.recovered = true;
        Ok(())
    }
    fn prepare(
        &mut self,
        sender: u64,
        mutation: wire::Mutation,
        id: &str,
        attached: &platform::ipc::IpcObjectHandles,
    ) -> Result<(u64, [u8; wire::MAX_PLAN_BYTES], usize), Error> {
        if platform::capability::check_thread(sender, mutation.capability()) != Ok(1) {
            return Err(denied());
        }
        let owner = platform::execution_peer::capture(sender)?;
        let credentials = session(owner.process.0)?;
        if self.entries.len() >= wire::MAX_PENDING
            || self
                .entries
                .iter()
                .filter(|entry| entry.owner.image.process_id == owner.image.process_id)
                .count()
                >= 2
        {
            return Err(Error::from_raw(-11));
        }
        self.next = self.next.checked_add(1).ok_or_else(invalid_request)?;
        let transaction = self.next;
        self.recover_snapshots()?;
        let snapshot = if mutation == wire::Mutation::Remove {
            if attached.count != 0 {
                return Err(invalid_request());
            }
            None
        } else {
            if attached.count != 1
                || attached.handles[0].reserved != 0
                || attached.handles[0].rights
                    != platform::handle::HANDLE_RIGHT_READ | platform::handle::HANDLE_RIGHT_TRANSFER
            {
                return Err(invalid_request());
            }
            let size =
                posix_io::with_client(|c| c.fstat(reference(attached.handles[0].handle)))?.size;
            let size = u64::try_from(size).map_err(|_| invalid_request())?;
            if self
                .entries
                .iter()
                .map(Entry::size)
                .sum::<u64>()
                .checked_add(size)
                .is_none_or(|n| n > wire::MAX_TOTAL_PACKAGE_BYTES)
            {
                return Err(Error::from_raw(-12));
            }
            Some(capture(attached.handles[0].handle, transaction)?)
        };
        let (manifest, developer, previous) = if let Some(snapshot) = &snapshot {
            let index = posix_io::index_mpkg(&snapshot.path)?;
            let verified = verify_when_database_ready(&snapshot.path)?;
            let manifest = core::str::from_utf8(&index.manifest)
                .ok()
                .and_then(platform::package::parse_manifest)
                .ok_or_else(invalid_request)?;
            if verified.verified_package_id != manifest.package_id
                || verified.manifest_digest != Sha256::digest(&index.manifest).as_slice()
            {
                return Err(denied());
            }
            require_path_absent(&alloc::format!(
                "/system/packages/{}/manifest.toml",
                manifest.package_id
            ))?;
            let installed = base(&manifest.package_id)?;
            match (mutation, installed.is_some()) {
                (wire::Mutation::Install, true) => return Err(Error::from_raw(-17)),
                (wire::Mutation::Update, false) => return Err(Error::from_raw(-2)),
                _ => {}
            }
            (
                manifest,
                verified.developer_id,
                installed.map(|b| b.0).unwrap_or([0; 32]),
            )
        } else {
            let (digest, manifest, developer) = base(id)?.ok_or_else(|| Error::from_raw(-2))?;
            if manifest.linux.is_some() {
                return Err(Error::from_raw(-95));
            }
            (manifest, developer, digest)
        };
        current(&owner, sender, credentials)?;
        let entry = Entry {
            id: transaction,
            owner,
            credentials,
            mutation,
            manifest,
            developer,
            snapshot,
            previous,
            deadline: platform::time::monotonic_nanoseconds()?
                .checked_add(wire::TIMEOUT_NS)
                .ok_or_else(invalid_request)?,
        };
        let mut bytes = [0; wire::MAX_PLAN_BYTES];
        let length = entry.write(0, &mut bytes)?;
        self.entries.push(entry);
        Ok((transaction, bytes, length))
    }
    pub fn handle(
        &mut self,
        endpoint: u32,
        sender: u64,
        bytes: &[u8],
        attached: &platform::ipc::IpcObjectHandles,
    ) -> bool {
        if attached.delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT && attached.count == 0 {
            if let Ok((header, _)) = mnu_abi::provider::RequestHeader::decode(bytes) {
                if header.opcode == mnu_abi::provider::OP_RELEASE {
                    self.entries.retain(|e| e.id != header.object_id);
                }
            }
            return true;
        }
        let Ok((request_id, command)) = wire::decode_command(bytes) else {
            return false;
        };
        let result = (|| {
            if !attached.is_user_delivery() {
                return Err(denied());
            }
            match command {
                wire::Command::Connect => {
                    if attached.count != 0 {
                        return Err(invalid_request());
                    }
                    let _broker = broker(sender)?;
                    let mut response = [0; package_protocol::HEADER_LEN];
                    let length = package_protocol::encode_status(request_id, 0, &mut response)
                        .map_err(|_| invalid_request())?;
                    let mut handles = platform::ipc::IpcObjectHandles::default();
                    handles.count = 1;
                    handles.handles[0] = platform::ipc::IpcObjectHandle {
                        handle: endpoint,
                        reserved: 0,
                        rights: platform::handle::HANDLE_RIGHT_SEND
                            | platform::handle::HANDLE_RIGHT_TRANSFER,
                    };
                    platform::ipc::reply_object_handles(sender, &response[..length], &handles)?;
                    Ok(true)
                }
                wire::Command::Prepare(mutation, id) => {
                    let (id, mut bytes, length) = self.prepare(sender, mutation, id, attached)?;
                    bytes[8..16].copy_from_slice(&request_id.to_le_bytes());
                    let handle = match platform::handle::create_provider_object(
                        endpoint,
                        id,
                        wire::PLAN_RIGHTS,
                    ) {
                        Ok(handle) => Reference(handle),
                        Err(error) => {
                            self.entries.retain(|e| e.id != id);
                            return Err(error);
                        }
                    };
                    let mut handles = platform::ipc::IpcObjectHandles::default();
                    handles.count = 1;
                    handles.handles[0] = platform::ipc::IpcObjectHandle {
                        handle: handle.0,
                        reserved: 0,
                        rights: wire::PLAN_RIGHTS,
                    };
                    if let Err(error) =
                        platform::ipc::reply_object_handles(sender, &bytes[..length], &handles)
                    {
                        self.entries.retain(|e| e.id != id);
                        return Err(error);
                    }
                    Ok(true)
                }
                wire::Command::Describe | wire::Command::Commit => {
                    let describe = matches!(command, wire::Command::Describe);
                    if attached.count != if describe { 2 } else { 1 }
                        || attached.handles[0].reserved != 0
                        || attached.handles[0].rights != platform::handle::HANDLE_RIGHT_TRANSFER
                    {
                        return Err(invalid_request());
                    }
                    let id =
                        platform::handle::identify_provider_object(attached.handles[0].handle)?;
                    let index = self
                        .entries
                        .iter()
                        .position(|entry| entry.id == id)
                        .ok_or_else(|| Error::from_raw(-9))?;
                    if describe {
                        let _broker = broker(sender)?;
                        let entry = &self.entries[index];
                        if attached.handles[1].reserved != 0
                            || attached.handles[1].rights != platform::handle::HANDLE_RIGHT_WAIT
                            || !platform::handle::same_object(
                                attached.handles[1].handle,
                                entry.owner.process.0,
                            )?
                        {
                            return Err(denied());
                        }
                        current(&entry.owner, entry.owner.endpoint, entry.credentials)?;
                        let mut bytes = [0; wire::MAX_PLAN_BYTES];
                        let length = entry.write(request_id, &mut bytes)?;
                        platform::ipc::reply(sender, &bytes[..length])?;
                        Ok(true)
                    } else {
                        // One attempt consumes the plan before any external I/O.
                        let entry = self.entries.swap_remove(index);
                        current(&entry.owner, sender, entry.credentials)?;
                        if platform::time::monotonic_nanoseconds()? >= entry.deadline
                            || platform::capability::check_thread(
                                sender,
                                entry.mutation.capability(),
                            ) != Ok(1)
                        {
                            return Err(denied());
                        }
                        consume_approval(
                            attached.handles[0].handle,
                            sender,
                            entry.owner.process.0,
                        )?;
                        let previous = base(&entry.manifest.package_id)?
                            .map(|v| v.0)
                            .unwrap_or([0; 32]);
                        if previous != entry.previous {
                            return Err(Error::from_raw(-11));
                        }
                        match entry.snapshot.as_ref() {
                            Some(snapshot) => {
                                if hash_file(&snapshot.path)? != snapshot.digest {
                                    return Err(denied());
                                }
                                install_package(
                                    &snapshot.path,
                                    if entry.mutation == wire::Mutation::Install {
                                        PackageMutation::Install
                                    } else {
                                        PackageMutation::Update
                                    },
                                )?;
                            }
                            None => remove_package(&entry.manifest.package_id)?,
                        }
                        Ok(false)
                    }
                }
            }
        })();
        match result {
            Ok(true) => {}
            result => reply_status(sender, request_id, false, result.map(|_| ())),
        }
        true
    }
}
fn consume_approval(plan: u32, sender: u64, expected: u32) -> Result<(), Error> {
    let process = Reference(platform::process::open_handle_for_endpoint(
        sender,
        platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_TRANSFER,
    )?);
    if !platform::handle::same_object(process.0, expected)? {
        return Err(denied());
    }
    let service = platform::execution_peer::capture(platform::process::find_by_name(
        CAPABILITY_SERVICE_NAME,
    )?)?;
    let _verified = broker(service.endpoint)?;
    let mut attached = platform::ipc::IpcObjectHandles::default();
    attached.count = 2;
    attached.handles[0] = platform::ipc::IpcObjectHandle {
        handle: plan,
        reserved: 0,
        rights: platform::handle::HANDLE_RIGHT_TRANSFER,
    };
    attached.handles[1] = platform::ipc::IpcObjectHandle {
        handle: process.0,
        reserved: 0,
        rights: platform::handle::HANDLE_RIGHT_WAIT,
    };
    let borrowed = [plan, process.0];
    let mut reply = [0; 8];
    let result = platform::ipc::call_object_handles(
        service.endpoint.try_into().map_err(|_| invalid_request())?,
        &platform::capability::administrator::PACKAGE_CONSUME_OPCODE.to_le_bytes(),
        &mut reply,
        &mut attached,
    );
    let unexpected = attached.count != 0 || attached.delivery_flags != 0;
    for object in attached
        .handles
        .iter()
        .take((attached.count as usize).min(attached.handles.len()))
    {
        if object.handle != 0 && !borrowed.contains(&object.handle) {
            let _ = platform::handle::close(object.handle);
        }
    }
    let message = result?;
    let current = broker(service.endpoint)?;
    if unexpected
        || message >> 32 != service.endpoint
        || message as u32 != 8
        || current.image != service.image
    {
        return Err(denied());
    }
    match u64::from_le_bytes(reply) {
        0 => Ok(()),
        n @ 1..=4095 => Err(Error::from_raw(-(n as i64))),
        _ => Err(denied()),
    }
}
