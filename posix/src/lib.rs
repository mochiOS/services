use std::collections::{BTreeMap, BTreeSet};
use std::string::String;

use mochios_posix_protocol as protocol;

pub mod pty;

pub const STATUS_EINVAL: i32 = -22;

/// Validates a delegated signal-thread object against kernel-authenticated
/// sender identity. An IPC endpoint number is not a native thread identifier.
pub fn signal_thread_registration_matches(
    sender: &mnu_abi::ExecutionIdentity,
    thread: &mnu_abi::ThreadStatus,
    rights: u64,
) -> bool {
    sender.process_id != 0
        && sender.thread_id != 0
        && rights == mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL
        && thread.thread_id == sender.thread_id
        && thread.process_id == sender.process_id
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    pub process_id: u64,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    pub process_id: u64,
    pub real_uid: u32,
    pub effective_uid: u32,
    pub saved_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub saved_gid: u32,
    pub umask: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub header: protocol::Header,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedOpen {
    pub base: protocol::OpenBase,
    pub options: u32,
    pub mode: u32,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedMkdir {
    pub base: protocol::OpenBase,
    pub mode: u32,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedUnlink {
    pub base: protocol::OpenBase,
    pub flags: u32,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRename {
    pub old_base: protocol::OpenBase,
    pub new_base: protocol::OpenBase,
    pub old_path: String,
    pub new_path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedLink {
    pub old_base: protocol::OpenBase,
    pub new_base: protocol::OpenBase,
    pub flags: u32,
    pub old_path: String,
    pub new_path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTruncate {
    pub base: protocol::OpenBase,
    pub path: String,
    pub length: u64,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSymlink {
    pub base: protocol::OpenBase,
    pub target: String,
    pub link_path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReadlink {
    pub base: protocol::OpenBase,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedChmod {
    pub base: protocol::OpenBase,
    pub path: String,
    pub mode: u32,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedChown {
    pub base: protocol::OpenBase,
    pub path: String,
    pub flags: u32,
    pub uid: u32,
    pub gid: u32,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedStat {
    pub base: protocol::OpenBase,
    pub flags: u32,
    pub path: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAccess {
    pub base: protocol::OpenBase,
    pub flags: u32,
    pub modes: u32,
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachedObject<H> {
    pub handle: H,
    pub rights: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenedObject<H> {
    pub handle: H,
    pub rights: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathObjects<H> {
    pub root: AttachedObject<H>,
    pub base: Option<AttachedObject<H>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenamePathObjects<H> {
    pub root: AttachedObject<H>,
    pub old_base: Option<AttachedObject<H>>,
    pub new_base: Option<AttachedObject<H>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionDirectories<H> {
    pub root: AttachedObject<H>,
    pub cwd: AttachedObject<H>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedProcess<H> {
    pub handle: H,
    pub process_id: u64,
}

pub trait FilesystemBackend<H: Copy> {
    /// Opens two independently-owned handles for the filesystem root. They
    /// become the initial process root and current working directory.
    fn open_session_root(
        &mut self,
        effective_uid: u32,
        effective_gid: u32,
        supplementary_groups: &[u32],
    ) -> Result<SessionDirectories<H>, i32>;

    /// Executes path resolution, optional creation, exclusivity checks and
    /// opening as one backend operation.
    fn open_at(
        &mut self,
        request: &PreparedOpen,
        paths: PathObjects<H>,
    ) -> Result<OpenedObject<H>, i32>;

    /// Resolves a directory and checks search permission without granting a
    /// client-visible readable file description.
    fn open_directory_at(
        &mut self,
        request: &PreparedStat,
        paths: PathObjects<H>,
    ) -> Result<OpenedObject<H>, i32>;

    /// Resolves and reads metadata in one backend operation.
    fn stat_at(
        &mut self,
        request: &PreparedStat,
        paths: PathObjects<H>,
    ) -> Result<protocol::FileStatus, i32>;

    /// Reads metadata from the open file description identified by `file`.
    fn fstat(&mut self, file: AttachedObject<H>) -> Result<protocol::FileStatus, i32>;

    fn ftruncate(&mut self, file: AttachedObject<H>, length: u64) -> Result<(), i32>;

    fn fchmod(
        &mut self,
        file: AttachedObject<H>,
        mode: u32,
        effective_uid: u32,
        effective_gid: u32,
        supplementary_groups: &[u32],
    ) -> Result<(), i32>;

    fn fchown(
        &mut self,
        file: AttachedObject<H>,
        uid: u32,
        gid: u32,
        effective_uid: u32,
        effective_gid: u32,
        supplementary_groups: &[u32],
    ) -> Result<(), i32>;

    fn fsync(&mut self, file: AttachedObject<H>) -> Result<(), i32>;

    fn get_status_flags(&mut self, file: AttachedObject<H>) -> Result<u32, i32>;

    fn set_status_flags(&mut self, file: AttachedObject<H>, flags: u32) -> Result<(), i32>;

    fn mkdir_at(&mut self, request: &PreparedMkdir, paths: PathObjects<H>) -> Result<(), i32>;

    fn unlink_at(&mut self, request: &PreparedUnlink, paths: PathObjects<H>) -> Result<(), i32>;

    fn rename_at(
        &mut self,
        request: &PreparedRename,
        paths: RenamePathObjects<H>,
    ) -> Result<(), i32>;

    fn link_at(&mut self, request: &PreparedLink, paths: RenamePathObjects<H>) -> Result<(), i32>;

    fn truncate_at(&mut self, request: &PreparedTruncate, paths: PathObjects<H>)
    -> Result<(), i32>;

    fn symlink_at(&mut self, request: &PreparedSymlink, paths: PathObjects<H>) -> Result<(), i32>;

    fn readlink_at(
        &mut self,
        request: &PreparedReadlink,
        paths: PathObjects<H>,
    ) -> Result<Vec<u8>, i32>;

    fn chmod_at(&mut self, request: &PreparedChmod, paths: PathObjects<H>) -> Result<(), i32>;

    fn chown_at(&mut self, request: &PreparedChown, paths: PathObjects<H>) -> Result<(), i32>;

    /// Resolves a path and checks access using the supplied authenticated
    /// POSIX credentials as one backend operation.
    fn access_at(&mut self, request: &PreparedAccess, paths: PathObjects<H>) -> Result<(), i32>;

    /// Retains an attached object beyond the lifetime of the current IPC
    /// request, monotonically preserving or reducing its rights.
    fn retain_object(&mut self, object: AttachedObject<H>) -> Result<AttachedObject<H>, i32>;

    /// Releases one service-owned object reference.
    fn release_object(&mut self, object: AttachedObject<H>);

    /// Returns the live path of `directory` relative to `root`.
    fn directory_path(
        &mut self,
        root: AttachedObject<H>,
        directory: AttachedObject<H>,
    ) -> Result<Vec<u8>, i32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessLifecycle {
    Running,
    Exited { exit_code: u64 },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ProcessWaitState {
    stopped: bool,
    stop_signal: u32,
    stop_reported: bool,
    continued_pending: bool,
    exit_observed: bool,
    exit_notified: bool,
    discard_exit_status: bool,
    deliveries: BTreeMap<u64, SignalDeliveryOwner>,
    termination_signal: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignalDeliveryOwner {
    signal: u32,
    // Captured from authenticated dequeue metadata, never from request bytes.
    thread_id: u64,
}

impl ProcessWaitState {
    fn stopped(&mut self, signal: u32) -> bool {
        if self.stopped {
            return false;
        }
        self.stopped = true;
        self.stop_signal = signal;
        self.stop_reported = false;
        self.continued_pending = false;
        true
    }

    fn continued(&mut self) -> bool {
        self.cancel_stop_deliveries();
        if !self.stopped {
            return false;
        }
        self.stopped = false;
        self.stop_reported = false;
        self.continued_pending = true;
        true
    }

    fn begin_delivery(&mut self, delivery: protocol::SignalDelivery, thread_id: u64) {
        self.deliveries.insert(
            delivery.token,
            SignalDeliveryOwner {
                signal: delivery.signal,
                thread_id,
            },
        );
    }

    fn contains_delivery_token(&self, token: u64) -> bool {
        self.deliveries.contains_key(&token)
    }

    fn cancel_stop_deliveries(&mut self) {
        self.deliveries
            .retain(|_, owner| signal_bit(owner.signal) & JOB_CONTROL_STOP_SIGNALS == 0);
    }

    fn consume_delivery(&mut self, delivery: protocol::SignalDelivery) -> bool {
        if self.deliveries.get(&delivery.token).map(|owner| owner.signal) != Some(delivery.signal) {
            return false;
        }
        self.deliveries.remove(&delivery.token);
        true
    }

    fn take_status(&mut self, options: u32) -> Option<u32> {
        if options & protocol::WAIT_UNTRACED != 0 && self.stopped && !self.stop_reported {
            self.stop_reported = true;
            return Some((self.stop_signal << 8) | 0x7f);
        }
        if options & protocol::WAIT_CONTINUED != 0 && self.continued_pending {
            self.continued_pending = false;
            return Some(protocol::WAIT_STATUS_CONTINUED);
        }
        None
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessSignalState {
    pending: u64,
    ignored: u64,
    caught: u64,
}

impl ProcessSignalState {
    pub const fn pending(self) -> u64 {
        self.pending
    }

    fn disposition(self, signal: u32) -> u32 {
        let bit = signal_bit(signal);
        if self.ignored & bit != 0 {
            protocol::SIGNAL_DISPOSITION_IGNORE
        } else if self.caught & bit != 0 {
            protocol::SIGNAL_DISPOSITION_CAUGHT
        } else {
            protocol::SIGNAL_DISPOSITION_DEFAULT
        }
    }

    fn fork_child(self) -> Self {
        Self { pending: 0, ..self }
    }

    fn set_disposition(&mut self, signal: u32, kind: u32) {
        let bit = signal_bit(signal);
        self.ignored &= !bit;
        self.caught &= !bit;
        if kind == protocol::SIGNAL_DISPOSITION_IGNORE {
            self.ignored |= bit;
            // POSIX discards already pending signals when changing to SIG_IGN.
            self.pending &= !bit;
        } else if kind == protocol::SIGNAL_DISPOSITION_CAUGHT {
            self.caught |= bit;
        }
    }

    fn enqueue(&mut self, signal: u32) {
        let signal = signal_bit(signal);
        if signal == signal_bit(protocol::SIGNAL_CONT) {
            self.pending &= !JOB_CONTROL_STOP_SIGNALS;
        } else if signal & JOB_CONTROL_STOP_SIGNALS != 0 {
            self.pending &= !signal_bit(protocol::SIGNAL_CONT);
        }
        if self.ignored & signal == 0 {
            self.pending |= signal;
        }
    }

    fn next_deliverable(&self, blocked: u64) -> u32 {
        let unblockable = signal_bit(protocol::SIGNAL_KILL) | signal_bit(protocol::SIGNAL_STOP);
        let deliverable = self.pending & !(blocked & !unblockable);
        if deliverable == 0 {
            return 0;
        }
        deliverable.trailing_zeros() + 1
    }

    fn dequeue(&mut self, blocked: u64) -> u32 {
        let signal = self.next_deliverable(blocked);
        if signal != 0 {
            self.pending &= !signal_bit(signal);
        }
        signal
    }
}

const fn signal_bit(signal: u32) -> u64 {
    1u64 << (signal - 1)
}

const JOB_CONTROL_STOP_SIGNALS: u64 = signal_bit(protocol::SIGNAL_STOP)
    | signal_bit(protocol::SIGNAL_TSTP)
    | signal_bit(protocol::SIGNAL_TTIN)
    | signal_bit(protocol::SIGNAL_TTOU);
const MAX_OUTSTANDING_SIGNAL_DELIVERIES: usize = protocol::SIGNAL_MAX as usize;

fn default_signal_terminates(signal: u32) -> bool {
    (1..=protocol::SIGNAL_MAX).contains(&signal)
        && !matches!(
            signal,
            protocol::SIGNAL_URG
                | protocol::SIGNAL_CONT
                | protocol::SIGNAL_CHLD
                | protocol::SIGNAL_WINCH
                | protocol::SIGNAL_STOP
                | protocol::SIGNAL_TSTP
                | protocol::SIGNAL_TTIN
                | protocol::SIGNAL_TTOU
        )
}

pub trait ProcessBackend<H: Copy> {
    fn status(&mut self, process: H) -> Result<ProcessLifecycle, i32>;
    fn suspend(&mut self, process: H) -> Result<(), i32>;
    fn terminate(&mut self, process: H, exit_code: u64) -> Result<(), i32>;
    fn release(&mut self, process: H);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectResponse<H> {
    pub response: Response,
    pub handles: Vec<OpenedObject<H>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllingTerminal {
    pub session_id: u64,
    pub foreground_process_group: u64,
}

#[derive(Debug)]
pub struct PosixService<H: Copy = u32> {
    bootstrap_process_id: Option<u64>,
    sessions: BTreeMap<u64, Session>,
    directories: BTreeMap<u64, SessionDirectories<H>>,
    processes: BTreeMap<u64, H>,
    parents: BTreeMap<u64, u64>,
    children: BTreeMap<u64, BTreeSet<u64>>,
    launch_creators: BTreeMap<u64, u64>,
    tree_teardowns: BTreeMap<u64, Vec<u64>>,
    orphaned_processes: BTreeSet<u64>,
    process_groups: BTreeMap<u64, u64>,
    session_ids: BTreeMap<u64, u64>,
    controlling_terminals: BTreeMap<u64, u64>,
    terminals: BTreeMap<u64, ControllingTerminal>,
    supplementary_groups: BTreeMap<u64, Vec<u32>>,
    resource_limits: BTreeMap<(u64, u32), protocol::ResourceLimit>,
    signals: BTreeMap<u64, ProcessSignalState>,
    // Native identities arrive only from authenticated endpoint metadata.
    signal_masks: BTreeMap<(u64, u64), u64>,
    signal_delivery_epochs: BTreeMap<(u64, u64), u64>,
    thread_pending_signals: BTreeMap<(u64, u64), u64>,
    thread_signal_notifications: BTreeSet<(u64, u64)>,
    signal_child_options: BTreeMap<u64, u32>,
    process_wait_states: BTreeMap<u64, ProcessWaitState>,
    next_signal_delivery_token: u64,
    signal_notifications: BTreeSet<u64>,
    process_resume_notifications: BTreeSet<u64>,
}

impl PosixService<u32> {
    pub const fn new() -> Self {
        Self {
            bootstrap_process_id: None,
            sessions: BTreeMap::new(),
            directories: BTreeMap::new(),
            processes: BTreeMap::new(),
            parents: BTreeMap::new(),
            children: BTreeMap::new(),
            launch_creators: BTreeMap::new(),
            tree_teardowns: BTreeMap::new(),
            orphaned_processes: BTreeSet::new(),
            process_groups: BTreeMap::new(),
            session_ids: BTreeMap::new(),
            controlling_terminals: BTreeMap::new(),
            terminals: BTreeMap::new(),
            supplementary_groups: BTreeMap::new(),
            resource_limits: BTreeMap::new(),
            signals: BTreeMap::new(),
            signal_masks: BTreeMap::new(),
            signal_delivery_epochs: BTreeMap::new(),
            thread_pending_signals: BTreeMap::new(),
            thread_signal_notifications: BTreeSet::new(),
            signal_child_options: BTreeMap::new(),
            process_wait_states: BTreeMap::new(),
            next_signal_delivery_token: 1,
            signal_notifications: BTreeSet::new(),
            process_resume_notifications: BTreeSet::new(),
        }
    }
}

impl Default for PosixService<u32> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Copy> PosixService<H> {
    /// Seeds the initial userspace authority from an explicitly inherited,
    /// authenticated ProcessHandle, before accepting requests. This operation
    /// is not an IPC opcode and cannot replace an existing service environment.
    pub fn initialize_bootstrap_process(
        &mut self,
        process: AuthenticatedProcess<H>,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<(), i32> {
        if !self.processes.is_empty() || !self.sessions.is_empty() {
            return Err(protocol::STATUS_EPERM);
        }
        self.initialize_process_environment(process, uid, gid, groups)?;
        self.bootstrap_process_id = Some(process.process_id);
        Ok(())
    }

    /// Initialize pre-existing boot processes only on behalf of the authority
    /// selected by the inherited bootstrap Handle. POSIX root alone is not
    /// enough, and existing environments may never be replaced.
    pub fn initialize_process(
        &mut self,
        peer: PeerIdentity,
        process: AuthenticatedProcess<H>,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<(), i32> {
        if self.bootstrap_process_id != Some(peer.process_id)
            || !self
                .sessions
                .get(&peer.process_id)
                .is_some_and(|session| session.effective_uid == 0)
        {
            return Err(protocol::STATUS_EPERM);
        }
        self.initialize_process_environment(process, uid, gid, groups)
    }

    fn initialize_process_environment(
        &mut self,
        process: AuthenticatedProcess<H>,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<(), i32> {
        if self.processes.contains_key(&process.process_id)
            || self.sessions.contains_key(&process.process_id)
        {
            return Err(STATUS_EINVAL);
        }
        if process.process_id == 0
            || uid == u32::MAX
            || gid == u32::MAX
            || groups.len() > protocol::MAX_SUPPLEMENTARY_GROUPS
        {
            return Err(STATUS_EINVAL);
        }
        let peer = PeerIdentity {
            process_id: process.process_id,
            effective_uid: uid,
            effective_gid: gid,
        };
        self.bind_process(peer, process)?;
        self.sessions.insert(
            process.process_id,
            Session {
                process_id: process.process_id,
                real_uid: uid,
                effective_uid: uid,
                saved_uid: uid,
                real_gid: gid,
                effective_gid: gid,
                saved_gid: gid,
                umask: 0o022,
            },
        );
        self.supplementary_groups
            .insert(process.process_id, groups.to_vec());
        Ok(())
    }

    pub fn session(&self, process_id: u64) -> Option<&Session> {
        self.sessions.get(&process_id)
    }

    /// Resolve an IPC-authenticated native process ID to an initialized POSIX
    /// environment. Native UID/GID fields are not credentials for this layer.
    pub fn registered_peer(&self, process_id: u64) -> Option<PeerIdentity> {
        self.processes.get(&process_id)?;
        let session = self.sessions.get(&process_id)?;
        Some(PeerIdentity {
            process_id,
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
        })
    }

    pub fn session_directories(&self, process_id: u64) -> Option<&SessionDirectories<H>> {
        self.directories.get(&process_id)
    }

    pub fn process_handle(&self, process_id: u64) -> Option<H> {
        self.processes.get(&process_id).copied()
    }

    pub fn parent_id(&self, process_id: u64) -> Option<u64> {
        self.parents.get(&process_id).copied()
    }

    pub fn controlling_terminal(&self, terminal_id: u64) -> Option<ControllingTerminal> {
        self.terminals.get(&terminal_id).copied()
    }

    pub fn supplementary_groups(&self, process_id: u64) -> Option<&[u32]> {
        self.supplementary_groups
            .get(&process_id)
            .map(Vec::as_slice)
    }

    pub fn signal_state(&self, process_id: u64) -> Option<ProcessSignalState> {
        self.signals.get(&process_id).copied()
    }

    pub fn signal_notification_processes(&self) -> impl Iterator<Item = u64> + '_ {
        self.signal_notifications.iter().copied()
    }

    pub fn acknowledge_signal_notification(&mut self, process_id: u64) {
        self.signal_notifications.remove(&process_id);
    }

    pub fn thread_signal_notification_threads(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.thread_signal_notifications.iter().copied()
    }

    pub fn acknowledge_thread_signal_notification(&mut self, process_id: u64, thread_id: u64) {
        self.thread_signal_notifications.remove(&(process_id, thread_id));
    }

    pub fn process_resume_notification_processes(&self) -> impl Iterator<Item = u64> + '_ {
        self.process_resume_notifications.iter().copied()
    }

    pub fn acknowledge_process_resume_notification(&mut self, process_id: u64) {
        self.process_resume_notifications.remove(&process_id);
    }

    fn enqueue_signal(&mut self, process_id: u64, signal: u32) -> Result<(), i32> {
        self.prepare_signal_generation(process_id, signal)?;
        self.signals
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .enqueue(signal);
        if self.signals[&process_id].pending() & signal_bit(signal) != 0 {
            self.signal_notifications.insert(process_id);
        } else if self.signals[&process_id].pending() == 0 {
            self.signal_notifications.remove(&process_id);
        }
        Ok(())
    }

    fn prepare_signal_generation(&mut self, process_id: u64, signal: u32) -> Result<(), i32> {
        let cancelled = if signal == protocol::SIGNAL_CONT {
            JOB_CONTROL_STOP_SIGNALS
        } else if signal_bit(signal) & JOB_CONTROL_STOP_SIGNALS != 0 {
            signal_bit(protocol::SIGNAL_CONT)
        } else {
            0
        };
        let state = self
            .signals
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        state.pending &= !cancelled;
        for ((process, _), pending) in &mut self.thread_pending_signals {
            if *process == process_id {
                *pending &= !cancelled;
            }
        }
        let continued = if signal == protocol::SIGNAL_CONT {
            self.process_wait_states
                .get_mut(&process_id)
                .ok_or(protocol::STATUS_ESRCH)?
                .continued()
        } else if signal == protocol::SIGNAL_KILL {
            self.process_wait_states
                .get_mut(&process_id)
                .ok_or(protocol::STATUS_ESRCH)?
                .cancel_stop_deliveries();
            false
        } else {
            false
        };
        if matches!(signal, protocol::SIGNAL_KILL | protocol::SIGNAL_CONT) {
            self.process_resume_notifications.insert(process_id);
        }
        if continued {
            self.notify_parent_of_child_change(process_id, true)?;
        }
        Ok(())
    }

    fn notify_parent_of_child_change(
        &mut self,
        child_id: u64,
        stopped_or_continued: bool,
    ) -> Result<(), i32> {
        let Some(parent_id) = self.parents.get(&child_id).copied() else {
            return Ok(());
        };
        if !self.signals.contains_key(&parent_id) {
            return Ok(());
        }
        if stopped_or_continued
            && self
                .signal_child_options
                .get(&parent_id)
                .copied()
                .unwrap_or_default()
                & protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP
                != 0
        {
            return Ok(());
        }
        self.enqueue_signal(parent_id, protocol::SIGNAL_CHLD)
    }

    fn note_child_exited(&mut self, child_id: u64) -> Result<bool, i32> {
        let wait_state = self
            .process_wait_states
            .get_mut(&child_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if wait_state.exit_notified {
            return Ok(false);
        }
        wait_state.exit_notified = true;
        if let Err(status) = self.notify_parent_of_child_change(child_id, false) {
            if let Some(wait_state) = self.process_wait_states.get_mut(&child_id) {
                wait_state.exit_notified = false;
            }
            return Err(status);
        }
        Ok(true)
    }

    /// Observes native process lifecycle without assigning POSIX meaning in
    /// the kernel. Each child exit queues one coalescing SIGCHLD for its POSIX
    /// parent. Exited parents relinquish unpinned children to the orphan reaper.
    pub fn refresh_child_exit_notifications<P: ProcessBackend<H>>(
        &mut self,
        processes: &mut P,
    ) -> Result<usize, i32> {
        let candidates: Vec<(u64, H)> = self
            .processes
            .keys()
            .filter_map(|child_id| {
                let wait_state = self.process_wait_states.get(child_id)?;
                let has_children = self.has_reparentable_children(*child_id);
                if (wait_state.exit_notified || !self.parents.contains_key(child_id))
                    && !has_children
                    && !self.controlling_terminals.contains_key(child_id)
                    && !self.needs_parent_exit_observation(*child_id)
                {
                    return None;
                }
                self.processes
                    .get(child_id)
                    .copied()
                    .map(|handle| (*child_id, handle))
            })
            .collect();
        let mut notified = 0;
        for (child_id, handle) in candidates {
            if matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                self.observe_process_exit(child_id)?;
                if self.parents.contains_key(&child_id) && self.note_child_exited(child_id)? {
                    notified += 1;
                }
            }
        }
        Ok(notified)
    }

    fn needs_parent_exit_observation(&self, process_id: u64) -> bool {
        self.bootstrap_process_id != Some(process_id)
            && self
                .process_wait_states
                .get(&process_id)
                .is_some_and(|state| !state.exit_observed)
            && self
                .children
                .get(&process_id)
                .is_some_and(|children| !children.is_empty())
    }

    /// A group remains connected to job control while a live member has a
    /// live parent in another group of the same session. Frozen teardown links
    /// may retain exited parents, so linkage alone is not proof of connection.
    fn non_orphaned_groups(&self) -> BTreeSet<(u64, u64)> {
        self.process_groups
            .iter()
            .filter_map(|(&member, &group)| {
                let session = *self.session_ids.get(&member)?;
                let parent = *self.parents.get(&member)?;
                let member_state = self.process_wait_states.get(&member)?;
                let parent_state = self.process_wait_states.get(&parent)?;
                (!member_state.exit_observed
                    && !parent_state.exit_observed
                    && self.session_ids.get(&parent).copied() == Some(session)
                    && self.process_groups.get(&parent).copied() != Some(group))
                .then_some((session, group))
            })
            .collect()
    }

    fn observe_process_exit(&mut self, process_id: u64) -> Result<(), i32> {
        if self.parents.get(&process_id).is_some_and(|parent| self.discards_child_status(*parent)) {
            self.process_wait_states
                .get_mut(&process_id)
                .ok_or(protocol::STATUS_ESRCH)?
                .discard_exit_status = true;
        }
        if self
            .process_wait_states
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .exit_observed
        {
            return Ok(());
        }
        let connected_before = self.non_orphaned_groups();
        self.hangup_exited_controlling_process(process_id)?;
        self.process_wait_states
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .exit_observed = true;
        self.reparent_children_of_exited(process_id);
        let connected_after = self.non_orphaned_groups();
        for &(session, group) in connected_before.difference(&connected_after) {
            let members: Vec<u64> = self
                .process_groups
                .iter()
                .filter_map(|(&member, &candidate)| {
                    (candidate == group
                        && self.session_ids.get(&member).copied() == Some(session)
                        && self
                            .process_wait_states
                            .get(&member)
                            .is_some_and(|state| !state.exit_observed))
                    .then_some(member)
                })
                .collect();
            if !members.iter().any(|member| {
                self.process_wait_states
                    .get(member)
                    .is_some_and(|state| state.stopped)
            }) {
                continue;
            }
            // Generate hangup before continue for the entire group, including
            // running members. Existing signal delivery/resume paths enforce
            // native authority; no PID capture or kernel POSIX policy is used.
            for &member in &members {
                self.enqueue_signal(member, protocol::SIGNAL_HUP)?;
            }
            for member in members {
                self.enqueue_signal(member, protocol::SIGNAL_CONT)?;
            }
        }
        Ok(())
    }

    /// The inherited bootstrap process is the userspace orphan reaper. Moving
    /// parent links never changes credentials, descriptors or object authority.
    /// A launcher's frozen teardown retains its relationships until reclaim.
    fn reparent_children_of_exited(&mut self, parent: u64) {
        let Some(reaper) = self.bootstrap_process_id else {
            return;
        };
        if parent == reaper
            || !self.sessions.contains_key(&reaper)
            || self.tree_teardown_owns(parent)
        {
            return;
        }
        let children: Vec<u64> = self
            .children
            .get(&parent)
            .into_iter()
            .flatten()
            .copied()
            .filter(|child| !self.tree_teardown_owns(*child))
            .collect();
        for child in children {
            self.parents.insert(child, reaper);
            self.children.entry(reaper).or_default().insert(child);
            if let Some(siblings) = self.children.get_mut(&parent) {
                siblings.remove(&child);
            }
            self.orphaned_processes.insert(child);
            // An already-observed zombie now belongs to a different parent.
            if let Some(state) = self.process_wait_states.get_mut(&child) {
                state.exit_notified = false;
            }
        }
        if self.children.get(&parent).is_some_and(BTreeSet::is_empty) {
            self.children.remove(&parent);
        }
    }

    fn has_reparentable_children(&self, process_id: u64) -> bool {
        self.bootstrap_process_id
            .is_some_and(|reaper| reaper != process_id)
            && !self.tree_teardown_owns(process_id)
            && self.children.get(&process_id).is_some_and(|children| {
                children
                    .iter()
                    .any(|child| !self.tree_teardown_owns(*child))
            })
    }

    fn reap_is_pinned(&self, process_id: u64) -> bool {
        self.tree_teardown_owns(process_id)
            || self
                .children
                .get(&process_id)
                .into_iter()
                .flatten()
                .any(|child| self.tree_teardown_owns(*child))
    }

    /// Release only orphan objects whose native exit is confirmed. The service
    /// implements init's reaping policy; mnu knows no parent or orphan semantics.
    pub fn reap_orphans<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<usize, i32> {
        let candidates: Vec<u64> = self.orphaned_processes.iter().copied().collect();
        let mut reaped = 0;
        for process_id in candidates {
            if self.reap_is_pinned(process_id) {
                continue;
            }
            let handle = *self
                .processes
                .get(&process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            if !matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                continue;
            }
            self.observe_process_exit(process_id)?;
            let parent = *self
                .parents
                .get(&process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            self.reap_child(parent, process_id, filesystem, processes)?;
            reaped += 1;
        }
        Ok(reaped)
    }

    fn discards_child_status(&self, parent: u64) -> bool {
        self.signals.get(&parent).is_some_and(|state| {
            state.disposition(protocol::SIGNAL_CHLD) == protocol::SIGNAL_DISPOSITION_IGNORE
        }) || self.signal_child_options.get(&parent).copied().unwrap_or(0)
            & protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT
            != 0
    }

    fn discard_observed_child_status(&mut self, parent: u64) {
        for (&child, &owner) in &self.parents {
            if owner == parent {
                if let Some(wait) = self.process_wait_states.get_mut(&child) {
                    if wait.exit_observed {
                        wait.discard_exit_status = true;
                    }
                }
            }
        }
    }

    /// Explicit SIG_IGN or SA_NOCLDWAIT for SIGCHLD discards exit status; default SIGCHLD
    /// does not. Retain teardown-pinned records, but never resurrect their
    /// discarded status if the parent subsequently changes its disposition.
    pub fn reap_discarded_children<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<usize, i32> {
        self.reap_discarded_children_for(None, filesystem, processes)
    }

    fn reap_discarded_children_for<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        parent_filter: Option<u64>,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<usize, i32> {
        let candidates: Vec<_> = self
            .parents
            .iter()
            .filter_map(|(&child, &parent)| {
                if parent_filter.is_some_and(|filter| filter != parent) {
                    return None;
                }
                let discarded = self
                    .process_wait_states
                    .get(&child)
                    .is_some_and(|state| state.discard_exit_status);
                let ignored = self.discards_child_status(parent);
                (discarded || ignored).then_some((child, parent))
            })
            .collect();
        let mut reaped = 0;
        for (child, parent) in candidates {
            let handle = *self.processes.get(&child).ok_or(protocol::STATUS_ESRCH)?;
            if !matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                continue;
            }
            self.observe_process_exit(child)?;
            self.process_wait_states
                .get_mut(&child)
                .ok_or(protocol::STATUS_ESRCH)?
                .discard_exit_status = true;
            if self.reap_is_pinned(child) {
                continue;
            }
            self.reap_child(parent, child, filesystem, processes)?;
            reaped += 1;
        }
        Ok(reaped)
    }

    /// Native process handles whose lifecycle can trigger a first child-exit
    /// notification or reparenting, including roots without a POSIX parent.
    /// The service main loop combines these with its IPC endpoint in one
    /// generic HandleWaitMany operation.
    pub fn child_lifecycle_handles(&self) -> Vec<H> {
        self.processes
            .keys()
            .filter_map(|child_id| match self.process_wait_states.get(child_id) {
                Some(state)
                    if (!state.exit_notified && self.parents.contains_key(child_id))
                        || self.has_reparentable_children(*child_id)
                        || self.needs_parent_exit_observation(*child_id)
                        || self.controlling_terminals.contains_key(child_id) =>
                {
                    self.processes.get(child_id).copied()
                }
                _ => None,
            })
            .collect()
    }

    /// Enqueues a terminal-generated signal for every member of the terminal's
    /// foreground process group. The PTY provider authenticates `terminal_id`;
    /// this path deliberately bypasses user credential checks because the
    /// terminal, rather than a POSIX process, is the signal source.
    pub fn signal_terminal_foreground_group(
        &mut self,
        terminal_id: u64,
        signal: u32,
    ) -> Result<usize, i32> {
        if signal == 0 || signal > protocol::SIGNAL_MAX {
            return Err(STATUS_EINVAL);
        }
        let terminal = self
            .terminals
            .get(&terminal_id)
            .copied()
            .ok_or(protocol::STATUS_ENOTTY)?;
        let targets: Vec<u64> = self
            .process_groups
            .iter()
            .filter_map(|(process_id, process_group)| {
                (*process_group == terminal.foreground_process_group
                    && self.session_ids.get(process_id).copied() == Some(terminal.session_id))
                .then_some(*process_id)
            })
            .collect();
        if targets.is_empty() {
            return Err(protocol::STATUS_ESRCH);
        }
        for process_id in targets.iter().copied() {
            self.enqueue_signal(process_id, signal)?;
        }
        Ok(targets.len())
    }

    /// The last PTY master close hangs up its controlling process, not the
    /// foreground job. Only the authenticated provider supplies terminal IDs.
    /// If SIGHUP terminates the controller, its normal exit policy subsequently
    /// hangs up the foreground group and disassociates the terminal.
    pub fn hangup_terminal(&mut self, terminal_id: u64) -> Result<(), i32> {
        let controller = self
            .terminals
            .get(&terminal_id)
            .ok_or(protocol::STATUS_ENOTTY)?
            .session_id;
        self.enqueue_signal(controller, protocol::SIGNAL_HUP)
    }

    pub fn is_child(&self, parent_id: u64, process_id: u64) -> bool {
        self.children
            .get(&parent_id)
            .is_some_and(|children| children.contains(&process_id))
    }

    /// Binds service state to a kernel-authenticated process object. The
    /// caller retains ownership when this returns `Ok(false)`.
    pub fn bind_process(
        &mut self,
        peer: PeerIdentity,
        process: AuthenticatedProcess<H>,
    ) -> Result<bool, i32> {
        if process.process_id != peer.process_id {
            return Err(STATUS_EINVAL);
        }
        if self.processes.contains_key(&peer.process_id) {
            return Ok(false);
        }
        self.processes.insert(peer.process_id, process.handle);
        self.process_groups.insert(peer.process_id, peer.process_id);
        self.session_ids.insert(peer.process_id, peer.process_id);
        self.supplementary_groups
            .insert(peer.process_id, Vec::new());
        self.signals
            .insert(peer.process_id, ProcessSignalState::default());
        self.signal_child_options.insert(peer.process_id, 0);
        self.process_wait_states
            .insert(peer.process_id, ProcessWaitState::default());
        Ok(true)
    }

    /// Installs POSIX state for a native process cloned by `peer`. Directory
    /// capabilities are retained so parent and child own independent service
    /// references to the same live filesystem objects.
    pub fn adopt_child<F: FilesystemBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        process: AuthenticatedProcess<H>,
        filesystem: &mut F,
    ) -> Result<(), i32> {
        if self.tree_teardown_owns(peer.process_id) {
            return Err(protocol::STATUS_EAGAIN);
        }
        if process.process_id == peer.process_id
            || !self.processes.contains_key(&peer.process_id)
            || self.processes.contains_key(&process.process_id)
        {
            return Err(STATUS_EINVAL);
        }
        let parent_session = self
            .sessions
            .get(&peer.process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let child_directories =
            if let Some(parent) = self.directories.get(&peer.process_id).copied() {
                let root = filesystem.retain_object(parent.root)?;
                let cwd = match filesystem.retain_object(parent.cwd) {
                    Ok(cwd) => cwd,
                    Err(error) => {
                        filesystem.release_object(root);
                        return Err(error);
                    }
                };
                Some(SessionDirectories { root, cwd })
            } else {
                None
            };
        let child_id = process.process_id;
        let inherited_limits: Vec<(u32, protocol::ResourceLimit)> = self
            .resource_limits
            .iter()
            .filter_map(|(&(process_id, resource), &limit)| {
                (process_id == peer.process_id).then_some((resource, limit))
            })
            .collect();
        let inherited_groups = self
            .supplementary_groups
            .get(&peer.process_id)
            .cloned()
            .unwrap_or_default();
        let inherited_signal_child_options = self
            .signal_child_options
            .get(&peer.process_id)
            .copied()
            .unwrap_or_default();
        self.processes.insert(child_id, process.handle);
        self.sessions.insert(
            child_id,
            Session {
                process_id: child_id,
                ..parent_session
            },
        );
        if let Some(directories) = child_directories {
            self.directories.insert(child_id, directories);
        }
        self.parents.insert(child_id, peer.process_id);
        // Keep failure-cleanup ownership separate from the POSIX parent link:
        // reparenting must not transfer the creator's rollback authority.
        self.launch_creators.insert(child_id, peer.process_id);
        self.process_groups.insert(
            child_id,
            self.process_groups
                .get(&peer.process_id)
                .copied()
                .unwrap_or(peer.process_id),
        );
        self.session_ids.insert(
            child_id,
            self.session_ids
                .get(&peer.process_id)
                .copied()
                .unwrap_or(peer.process_id),
        );
        self.supplementary_groups.insert(child_id, inherited_groups);
        self.children
            .entry(peer.process_id)
            .or_default()
            .insert(child_id);
        let child_signals = self.signals[&peer.process_id].fork_child();
        self.signals.insert(child_id, child_signals);
        self.signal_child_options
            .insert(child_id, inherited_signal_child_options);
        self.process_wait_states
            .insert(child_id, ProcessWaitState::default());
        for (resource, limit) in inherited_limits {
            self.resource_limits.insert((child_id, resource), limit);
        }
        Ok(())
    }

    /// Initialize a fresh image using userspace POSIX authority, without
    /// changing native capabilities or trusting sender-supplied identity.
    pub fn adopt_spawned_child<F: FilesystemBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        process: AuthenticatedProcess<H>,
        uid: u32,
        gid: u32,
        groups: &[u32],
        filesystem: &mut F,
    ) -> Result<(), i32> {
        if uid == u32::MAX || gid == u32::MAX || groups.len() > protocol::MAX_SUPPLEMENTARY_GROUPS {
            return Err(STATUS_EINVAL);
        }
        let parent = self
            .sessions
            .get(&peer.process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if parent.effective_uid != 0 {
            let memberships = self.supplementary_groups.get(&peer.process_id);
            if uid != parent.effective_uid
                || gid != parent.effective_gid
                || groups.iter().any(|group| {
                    !memberships.is_some_and(|memberships| memberships.contains(group))
                })
            {
                return Err(protocol::STATUS_EPERM);
            }
        }
        self.adopt_child(peer, process, filesystem)?;
        let child = self.sessions.get_mut(&process.process_id).unwrap();
        child.real_uid = uid;
        child.effective_uid = uid;
        child.saved_uid = uid;
        child.real_gid = gid;
        child.effective_gid = gid;
        child.saved_gid = gid;
        self.supplementary_groups
            .insert(process.process_id, groups.to_vec());
        // Fresh-image launchers need the same failure cleanup authority as a
        // broker. This records only this authenticated creator, not UID zero.
        self.launch_creators.insert(process.process_id, peer.process_id);
        Ok(())
    }

    /// Initialize a broker-created image from an authenticated requester, not
    /// from the broker's environment. Native process creation/Handle rights
    /// remain separately enforced by mnu. Only userspace POSIX root can assign
    /// another process's parent relationship or credential environment.
    pub fn adopt_launched_child<F: FilesystemBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        requester: AuthenticatedProcess<H>,
        child: AuthenticatedProcess<H>,
        filesystem: &mut F,
    ) -> Result<(), i32> {
        let broker = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if broker.effective_uid != 0 {
            return Err(protocol::STATUS_EPERM);
        }
        let parent = self
            .sessions
            .get(&requester.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let parent_peer = PeerIdentity {
            process_id: parent.process_id,
            effective_uid: parent.effective_uid,
            effective_gid: parent.effective_gid,
        };
        self.adopt_child(parent_peer, child, filesystem)?;
        self.launch_creators
            .insert(child.process_id, peer.process_id);
        Ok(())
    }

    /// Snapshot retained process objects in descendant-first order for a
    /// launcher's teardown. The root must be an explicitly authenticated
    /// ProcessHandle for an image registered by this launcher. POSIX root or
    /// possession of an unrelated process object is not teardown authority.
    /// Handles remain owned by the service; this neither transfers nor closes
    /// them. Parent relationships come only from userspace registration.
    pub fn launched_tree_handles(
        &self,
        peer: PeerIdentity,
        root: AuthenticatedProcess<H>,
    ) -> Result<Vec<H>, i32> {
        self.launched_tree_process_ids(peer, root)?
            .into_iter()
            .map(|process_id| {
                self.processes
                    .get(&process_id)
                    .copied()
                    .ok_or(protocol::STATUS_ESRCH)
            })
            .collect()
    }

    fn launched_tree_process_ids(
        &self,
        peer: PeerIdentity,
        root: AuthenticatedProcess<H>,
    ) -> Result<Vec<u64>, i32> {
        if self.registered_peer(peer.process_id).is_none() {
            return Err(protocol::STATUS_ESRCH);
        }
        if self.launch_creators.get(&root.process_id) != Some(&peer.process_id) {
            return Err(protocol::STATUS_EPERM);
        }
        let mut process_ids = vec![root.process_id];
        let mut index = 0;
        while index < process_ids.len() {
            if let Some(children) = self.children.get(&process_ids[index]) {
                process_ids.extend(children.iter().copied());
            }
            index += 1;
        }
        process_ids.reverse();
        Ok(process_ids)
    }

    fn tree_teardown_owns(&self, process_id: u64) -> bool {
        self.tree_teardowns
            .values()
            .any(|members| members.contains(&process_id))
    }

    /// Freeze the authenticated tree before terminating anything. Keep every
    /// relationship and owned reference until a separate reclaim request: a
    /// lost completion reply can repeat this operation without losing authority.
    /// Ordinary wait/launch rollback must not steal these references meanwhile.
    pub fn begin_launched_tree_termination<P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        root: AuthenticatedProcess<H>,
        processes: &mut P,
    ) -> Result<(), i32> {
        let members = self.launched_tree_process_ids(peer, root)?;
        if !self.tree_teardowns.contains_key(&root.process_id) {
            if members
                .iter()
                .any(|&process_id| self.tree_teardown_owns(process_id))
            {
                return Err(protocol::STATUS_EAGAIN);
            }
            for process_id in &members {
                if !self.parents.contains_key(process_id)
                    || !self.processes.contains_key(process_id)
                {
                    return Err(protocol::STATUS_ESRCH);
                }
            }
            self.tree_teardowns.insert(root.process_id, members);
        }
        let handles: Vec<H> = self.tree_teardowns[&root.process_id]
            .iter()
            .map(|process_id| {
                self.processes
                    .get(process_id)
                    .copied()
                    .ok_or(protocol::STATUS_ESRCH)
            })
            .collect::<Result<_, _>>()?;
        for handle in handles {
            if !matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                processes.terminate(handle, 1)?;
                if !matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                    return Err(protocol::STATUS_EAGAIN);
                }
            }
        }
        Ok(())
    }

    /// Release a frozen tree only after every native exit is confirmed. Once
    /// this succeeds the root no longer has a POSIX environment (ESRCH), so a
    /// caller that already received termination confirmation can retry reclaim
    /// after a lost reply without keeping an unbounded completion tombstone.
    pub fn reclaim_launched_tree<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        root: AuthenticatedProcess<H>,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<(), i32> {
        if self.registered_peer(peer.process_id).is_none() {
            return Err(protocol::STATUS_ESRCH);
        }
        if !self.processes.contains_key(&root.process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        self.launched_tree_process_ids(peer, root)?;
        let plan: Vec<(u64, u64, H)> = self
            .tree_teardowns
            .get(&root.process_id)
            .ok_or(protocol::STATUS_EAGAIN)?
            .iter()
            .map(|&process_id| {
                let parent = self
                    .parents
                    .get(&process_id)
                    .copied()
                    .ok_or(protocol::STATUS_ESRCH)?;
                let handle = self
                    .processes
                    .get(&process_id)
                    .copied()
                    .ok_or(protocol::STATUS_ESRCH)?;
                Ok((process_id, parent, handle))
            })
            .collect::<Result<_, i32>>()?;
        for &(_, _, handle) in &plan {
            if !matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                return Err(protocol::STATUS_EAGAIN);
            }
        }
        for (process_id, parent, _) in plan {
            self.reap_child(parent, process_id, filesystem, processes)?;
        }
        self.tree_teardowns.remove(&root.process_id);
        Ok(())
    }

    /// Roll back a creator's failed fork or launch without an unreported zombie.
    /// Possessing another process's WAIT Handle or being POSIX root alone does
    /// not suffice: the sender must have registered this child. ESRCH means
    /// registration is already absent; callers may treat it as completed only
    /// after confirming native exit through their retained ProcessHandle.
    pub fn abort_launched_child<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        child: AuthenticatedProcess<H>,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<(), i32> {
        if !self.processes.contains_key(&child.process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        if self.launch_creators.get(&child.process_id) != Some(&peer.process_id) {
            return Err(protocol::STATUS_EPERM);
        }
        if self.reap_is_pinned(child.process_id) {
            return Err(protocol::STATUS_EAGAIN);
        }
        let handle = self
            .processes
            .get(&child.process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let parent = self
            .parents
            .get(&child.process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if !matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
            processes.terminate(handle, 127)?;
            if !matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                return Err(protocol::STATUS_EAGAIN);
            }
        }
        self.reap_child(parent, child.process_id, filesystem, processes)?;
        Ok(())
    }

    pub fn wait_child<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        request: protocol::WaitRequest,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<protocol::WaitResult, i32> {
        self.matching_child_ids(peer, request)?;
        self.reap_discarded_children_for(Some(peer.process_id), filesystem, processes)?;
        let candidates = self.matching_child_ids(peer, request)?;
        for child in candidates {
            if self.reap_is_pinned(child) {
                continue;
            }
            let handle = self
                .processes
                .get(&child)
                .copied()
                .ok_or(protocol::STATUS_ESRCH)?;
            if let ProcessLifecycle::Exited { exit_code } = processes.status(handle)? {
                self.note_child_exited(child)?;
                let status = self
                    .process_wait_states
                    .get(&child)
                    .and_then(|state| state.termination_signal)
                    .map(|signal| signal & 0x7f)
                    .unwrap_or_else(|| ((exit_code & 0xff) as u32) << 8);
                self.reap_child(peer.process_id, child, filesystem, processes)?;
                return Ok(protocol::WaitResult {
                    process_id: child,
                    status,
                });
            }
            if let Some(status) = self
                .process_wait_states
                .get_mut(&child)
                .and_then(|state| state.take_status(request.options))
            {
                return Ok(protocol::WaitResult {
                    process_id: child,
                    status,
                });
            }
        }
        if request.options & protocol::WAIT_NOHANG != 0 {
            Ok(protocol::WaitResult::default())
        } else {
            Err(protocol::STATUS_EAGAIN)
        }
    }

    /// Returns the native process handles whose lifecycle can satisfy a
    /// blocking wait request. The caller may wait on these together with its
    /// IPC endpoint without importing POSIX child semantics into the kernel.
    pub fn wait_handles(
        &self,
        peer: PeerIdentity,
        request: protocol::WaitRequest,
    ) -> Result<Vec<H>, i32> {
        self.matching_child_ids(peer, request)?
            .into_iter()
            .filter(|child| !self.reap_is_pinned(*child))
            .map(|child| {
                self.processes
                    .get(&child)
                    .copied()
                    .ok_or(protocol::STATUS_ESRCH)
            })
            .collect()
    }

    fn matching_child_ids(
        &self,
        peer: PeerIdentity,
        request: protocol::WaitRequest,
    ) -> Result<Vec<u64>, i32> {
        if request.options & !protocol::WAIT_OPTIONS_ALL != 0 {
            return Err(STATUS_EINVAL);
        }
        let caller_group = self
            .process_groups
            .get(&peer.process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let children = self
            .children
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ECHILD)?;
        let requested_group = if request.selector < -1 {
            request.selector.checked_neg().map(|value| value as u64)
        } else {
            None
        };
        if request.selector < -1 && requested_group.is_none() {
            return Err(STATUS_EINVAL);
        }
        let candidates: Vec<u64> = children
            .iter()
            .copied()
            .filter(|child| match request.selector {
                selector if selector > 0 => *child == selector as u64,
                -1 => true,
                0 => self.process_groups.get(child).copied() == Some(caller_group),
                _ => self.process_groups.get(child).copied() == requested_group,
            })
            .collect();
        if candidates.is_empty() {
            return Err(protocol::STATUS_ECHILD);
        }
        Ok(candidates)
    }

    fn reap_child<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        parent_id: u64,
        child_id: u64,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<(), i32> {
        self.observe_process_exit(child_id)?;
        self.orphaned_processes.remove(&child_id);
        if let Some(children) = self.children.get_mut(&parent_id) {
            children.remove(&child_id);
            if children.is_empty() {
                self.children.remove(&parent_id);
            }
        }
        self.parents.remove(&child_id);
        self.launch_creators.remove(&child_id);
        self.process_groups.remove(&child_id);
        let session_id = self.session_ids.remove(&child_id);
        if session_id == Some(child_id) {
            self.release_session_terminal(child_id);
        }
        self.supplementary_groups.remove(&child_id);
        self.resource_limits
            .retain(|(process_id, _), _| *process_id != child_id);
        self.signals.remove(&child_id);
        self.signal_masks.retain(|(process, _), _| *process != child_id);
        self.signal_delivery_epochs.retain(|(process, _), _| *process != child_id);
        self.thread_pending_signals.retain(|(process, _), _| *process != child_id);
        self.thread_signal_notifications.retain(|(process, _)| *process != child_id);
        self.signal_child_options.remove(&child_id);
        self.process_wait_states.remove(&child_id);
        self.signal_notifications.remove(&child_id);
        self.process_resume_notifications.remove(&child_id);
        self.sessions.remove(&child_id);
        if let Some(directories) = self.directories.remove(&child_id) {
            filesystem.release_object(directories.root);
            filesystem.release_object(directories.cwd);
        }
        if let Some(handle) = self.processes.remove(&child_id) {
            processes.release(handle);
        }
        Ok(())
    }

    fn process_info_payload(&self, caller_id: u64, payload: &[u8]) -> Result<Vec<u8>, i32> {
        let requested = protocol::decode_process_id_request(payload).map_err(|_| STATUS_EINVAL)?;
        let process_id = match requested {
            0 => caller_id,
            value if value > 0 => value as u64,
            _ => return Err(STATUS_EINVAL),
        };
        let caller_session = self
            .session_ids
            .get(&caller_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if self.session_ids.get(&process_id).copied() != Some(caller_session) {
            return Err(protocol::STATUS_ESRCH);
        }
        encode_process_info_payload(self.process_info_for(process_id)?)
    }

    fn process_info_for(&self, process_id: u64) -> Result<protocol::ProcessInfo, i32> {
        Ok(protocol::ProcessInfo {
            process_id,
            parent_id: self.parents.get(&process_id).copied().unwrap_or(0),
            process_group_id: self
                .process_groups
                .get(&process_id)
                .copied()
                .ok_or(protocol::STATUS_ESRCH)?,
            session_id: self
                .session_ids
                .get(&process_id)
                .copied()
                .ok_or(protocol::STATUS_ESRCH)?,
        })
    }

    fn set_process_group(&mut self, caller_id: u64, payload: &[u8]) -> Result<(), i32> {
        let (process_id, process_group_id) =
            protocol::decode_process_group_request(payload).map_err(|_| STATUS_EINVAL)?;
        if process_id < 0 || process_group_id < 0 {
            return Err(STATUS_EINVAL);
        }
        let target = if process_id == 0 {
            caller_id
        } else {
            process_id as u64
        };
        if target != caller_id && self.parents.get(&target).copied() != Some(caller_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        let caller_session = self
            .session_ids
            .get(&caller_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if self.session_ids.get(&target).copied() != Some(caller_session) {
            return Err(protocol::STATUS_EPERM);
        }
        if self.session_ids.get(&target).copied() == Some(target) {
            return Err(protocol::STATUS_EPERM);
        }
        let group = if process_group_id == 0 {
            target
        } else {
            process_group_id as u64
        };
        if group != target
            && !self.process_groups.iter().any(|(process, candidate)| {
                *candidate == group
                    && self.session_ids.get(process).copied() == Some(caller_session)
            })
        {
            return Err(protocol::STATUS_EPERM);
        }
        self.process_groups.insert(target, group);
        Ok(())
    }

    fn create_session(&mut self, process_id: u64) -> Result<protocol::ProcessInfo, i32> {
        if self
            .process_groups
            .values()
            .any(|group| *group == process_id)
        {
            return Err(protocol::STATUS_EPERM);
        }
        if !self.processes.contains_key(&process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        self.process_groups.insert(process_id, process_id);
        self.session_ids.insert(process_id, process_id);
        self.process_info_for(process_id)
    }

    fn acquire_controlling_terminal(
        &mut self,
        process_id: u64,
        terminal_id: u64,
    ) -> Result<(), i32> {
        let session_id = self
            .session_ids
            .get(&process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if !self.sessions.contains_key(&process_id) || session_id != process_id {
            return Err(protocol::STATUS_EPERM);
        }
        if let Some(existing) = self.controlling_terminals.get(&session_id).copied() {
            return if existing == terminal_id {
                Ok(())
            } else {
                Err(protocol::STATUS_EPERM)
            };
        }
        if self.terminals.contains_key(&terminal_id) {
            return Err(protocol::STATUS_EPERM);
        }
        let foreground_process_group = self
            .process_groups
            .get(&process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        self.controlling_terminals.insert(session_id, terminal_id);
        self.terminals.insert(
            terminal_id,
            ControllingTerminal {
                session_id,
                foreground_process_group,
            },
        );
        Ok(())
    }

    fn release_controlling_terminal(
        &mut self,
        process_id: u64,
        terminal_id: u64,
    ) -> Result<(), i32> {
        let session_id = self
            .session_ids
            .get(&process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if session_id != process_id
            || self.controlling_terminals.get(&session_id).copied() != Some(terminal_id)
        {
            return Err(protocol::STATUS_ENOTTY);
        }
        self.release_session_terminal(session_id);
        Ok(())
    }

    fn release_session_terminal(&mut self, session_id: u64) {
        if let Some(terminal_id) = self.controlling_terminals.remove(&session_id) {
            self.terminals.remove(&terminal_id);
        }
    }

    /// POSIX exit policy, applied only after native exit is confirmed. Drop the
    /// terminal association at exit, not at wait/reap; its removal also makes
    /// repeated lifecycle observations unable to generate another hangup.
    fn hangup_exited_controlling_process(&mut self, process_id: u64) -> Result<(), i32> {
        let Some(terminal_id) = self.controlling_terminals.get(&process_id).copied() else {
            return Ok(());
        };
        let terminal = self
            .terminals
            .get(&terminal_id)
            .ok_or(protocol::STATUS_ENOTTY)?;
        let has_foreground_members = self.process_groups.iter().any(|(member, group)| {
            *group == terminal.foreground_process_group
                && self.session_ids.get(member).copied() == Some(terminal.session_id)
        });
        if has_foreground_members {
            self.signal_terminal_foreground_group(terminal_id, protocol::SIGNAL_HUP)?;
        }
        self.release_session_terminal(process_id);
        Ok(())
    }

    fn terminal_foreground_process_group(
        &self,
        process_id: u64,
        terminal_id: u64,
    ) -> Result<u64, i32> {
        let session_id = self
            .session_ids
            .get(&process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let terminal = self
            .terminals
            .get(&terminal_id)
            .copied()
            .ok_or(protocol::STATUS_ENOTTY)?;
        if terminal.session_id != session_id
            || self.controlling_terminals.get(&session_id).copied() != Some(terminal_id)
        {
            return Err(protocol::STATUS_ENOTTY);
        }
        Ok(terminal.foreground_process_group)
    }

    fn set_terminal_foreground_process_group(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        terminal_id: u64,
        payload: &[u8],
    ) -> Result<(), i32> {
        let process_id = sender.process_id;
        let process_group =
            protocol::decode_process_id_request(payload).map_err(|_| STATUS_EINVAL)?;
        if process_group <= 0 {
            return Err(STATUS_EINVAL);
        }
        let process_group = process_group as u64;
        let session_id = self
            .session_ids
            .get(&process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let terminal = self
            .terminals
            .get(&terminal_id)
            .ok_or(protocol::STATUS_ENOTTY)?;
        if terminal.session_id != session_id
            || self.controlling_terminals.get(&session_id).copied() != Some(terminal_id)
        {
            return Err(protocol::STATUS_ENOTTY);
        }
        let group_is_in_session = self.process_groups.iter().any(|(member, group)| {
            *group == process_group && self.session_ids.get(member).copied() == Some(session_id)
        });
        if !group_is_in_session {
            return Err(protocol::STATUS_EPERM);
        }
        self.authorize_terminal_change(sender, terminal_id)?;
        self.terminals
            .get_mut(&terminal_id)
            .ok_or(protocol::STATUS_ENOTTY)?
            .foreground_process_group = process_group;
        Ok(())
    }

    /// Terminal-changing operations ignore TOSTOP. Only the authenticated
    /// calling thread's mask can exempt a background caller from SIGTTOU.
    fn authorize_terminal_change(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        terminal_id: u64,
    ) -> Result<(), i32> {
        self.authorize_terminal_access(sender, terminal_id, protocol::SIGNAL_TTOU, false)
    }

    /// Applies job control only to the caller's controlling terminal. Native
    /// handle rights continue to govern other delegated terminal resources.
    /// `sender` must come from kernel-authenticated endpoint metadata.
    pub fn authorize_terminal_io(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        terminal_id: u64,
        reading: bool,
        stop_background_write: bool,
    ) -> Result<(), i32> {
        if sender.process_id == 0 || sender.thread_id == 0 {
            return Err(protocol::STATUS_EPERM);
        }
        let Some(session) = self.session_ids.get(&sender.process_id).copied() else {
            return Ok(());
        };
        if self.controlling_terminals.get(&session).copied() != Some(terminal_id) {
            return Ok(());
        }
        if !reading && !stop_background_write {
            return Ok(());
        }
        self.authorize_terminal_access(
            sender,
            terminal_id,
            if reading {
                protocol::SIGNAL_TTIN
            } else {
                protocol::SIGNAL_TTOU
            },
            reading,
        )
    }

    fn authorize_terminal_access(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        terminal_id: u64,
        signal: u32,
        reading: bool,
    ) -> Result<(), i32> {
        let terminal = self
            .terminals
            .get(&terminal_id)
            .ok_or(protocol::STATUS_ENOTTY)?;
        let group = *self
            .process_groups
            .get(&sender.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if group == terminal.foreground_process_group {
            return Ok(());
        }
        let ignored = self
            .signals
            .get(&sender.process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .disposition(signal)
            == protocol::SIGNAL_DISPOSITION_IGNORE;
        if ignored {
            return if reading {
                Err(protocol::STATUS_EIO)
            } else {
                Ok(())
            };
        }
        let blocked = *self
            .signal_masks
            .get(&(sender.process_id, sender.thread_id))
            .ok_or(protocol::STATUS_ESRCH)?;
        if blocked & signal_bit(signal) != 0 {
            return if reading {
                Err(protocol::STATUS_EIO)
            } else {
                Ok(())
            };
        }
        let session = terminal.session_id;
        if !self.non_orphaned_groups().contains(&(session, group)) {
            return Err(protocol::STATUS_EIO);
        }
        let members: Vec<u64> = self
            .process_groups
            .iter()
            .filter_map(|(&member, &candidate)| {
                (candidate == group
                    && self.session_ids.get(&member).copied() == Some(session)
                    && self
                        .process_wait_states
                        .get(&member)
                        .is_some_and(|state| !state.exit_observed))
                .then_some(member)
            })
            .collect();
        for member in members {
            self.enqueue_signal(member, signal)?;
        }
        Err(protocol::STATUS_EINTR)
    }

    /// Applies POSIX controlling-terminal policy to a terminal object already
    /// authenticated by its provider. `terminal_id` is provider-owned state;
    /// clients cannot select or forge it in request bytes.
    /// `sender` must be resolved from the kernel-authenticated IPC endpoint.
    pub fn handle_terminal(
        &mut self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
        header: protocol::Header,
        payload: &[u8],
        terminal_id: u64,
    ) -> Response {
        if sender.process_id != peer.process_id || sender.process_id == 0 || sender.thread_id == 0 {
            return status_response(header.request_id, protocol::STATUS_EPERM);
        }
        let result = match header.opcode {
            protocol::OP_TERMINAL_ACQUIRE if header.flags == 0 && payload.is_empty() => self
                .acquire_controlling_terminal(peer.process_id, terminal_id)
                .map(|_| Vec::new()),
            protocol::OP_TERMINAL_RELEASE if header.flags == 0 && payload.is_empty() => self
                .release_controlling_terminal(peer.process_id, terminal_id)
                .map(|_| Vec::new()),
            protocol::OP_TERMINAL_GET_FOREGROUND if header.flags == 0 && payload.is_empty() => self
                .terminal_foreground_process_group(peer.process_id, terminal_id)
                .and_then(|group| {
                    let group = i64::try_from(group).map_err(|_| STATUS_EINVAL)?;
                    let mut output = vec![0; protocol::PROCESS_ID_REQUEST_LEN];
                    protocol::encode_process_id_request(group, &mut output)
                        .map_err(|_| STATUS_EINVAL)?;
                    Ok(output)
                }),
            protocol::OP_TERMINAL_SET_FOREGROUND if header.flags == 0 => self
                .set_terminal_foreground_process_group(sender, terminal_id, payload)
                .map(|_| Vec::new()),
            protocol::OP_TERMINAL_ACQUIRE
            | protocol::OP_TERMINAL_RELEASE
            | protocol::OP_TERMINAL_GET_FOREGROUND
            | protocol::OP_TERMINAL_SET_FOREGROUND => Err(STATUS_EINVAL),
            _ => Err(protocol::STATUS_ENOSYS),
        };
        match result {
            Ok(payload) => Response {
                header: protocol::Header {
                    opcode: protocol::OP_STATUS,
                    request_id: header.request_id,
                    flags: 0,
                    payload_len: payload.len() as u32,
                    status: protocol::STATUS_OK,
                },
                payload,
            },
            Err(status) => status_response(header.request_id, status),
        }
    }

    fn resource_limit_payload(&mut self, caller_id: u64, payload: &[u8]) -> Result<Vec<u8>, i32> {
        let request =
            protocol::decode_resource_limit_request(payload).map_err(|_| STATUS_EINVAL)?;
        if request.process_id < 0 || request.resource >= protocol::RLIMIT_COUNT {
            return Err(STATUS_EINVAL);
        }
        let target_id = if request.process_id == 0 {
            caller_id
        } else {
            request.process_id as u64
        };
        let caller = self
            .sessions
            .get(&caller_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let target = self
            .sessions
            .get(&target_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let same_credentials = caller.real_uid == target.real_uid
            && caller.real_uid == target.effective_uid
            && caller.real_uid == target.saved_uid
            && caller.real_gid == target.real_gid
            && caller.real_gid == target.effective_gid
            && caller.real_gid == target.saved_gid;
        if target_id != caller_id && caller.effective_uid != 0 && !same_credentials {
            return Err(protocol::STATUS_EPERM);
        }

        let key = (target_id, request.resource);
        let previous = self.resource_limits.get(&key).copied().unwrap_or_default();
        if request.flags & protocol::RESOURCE_LIMIT_SET != 0 {
            if request.limit.soft > request.limit.hard {
                return Err(STATUS_EINVAL);
            }
            if request.limit.hard > previous.hard && caller.effective_uid != 0 {
                return Err(protocol::STATUS_EPERM);
            }
            self.resource_limits.insert(key, request.limit);
        }

        let mut output = vec![0; protocol::RESOURCE_LIMIT_LEN];
        protocol::encode_resource_limit(previous, &mut output).map_err(|_| STATUS_EINVAL)?;
        Ok(output)
    }

    fn send_signal(&mut self, caller_id: u64, payload: &[u8]) -> Result<(), i32> {
        let request = protocol::decode_signal_send_request(payload).map_err(|_| STATUS_EINVAL)?;
        let caller = self
            .sessions
            .get(&caller_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let caller_group = self
            .process_groups
            .get(&caller_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let requested_group = if request.selector < -1 {
            request.selector.checked_neg().map(|value| value as u64)
        } else {
            None
        };
        if request.selector < -1 && requested_group.is_none() {
            return Err(STATUS_EINVAL);
        }

        let targets: Vec<u64> = self
            .sessions
            .keys()
            .copied()
            .filter(|target| match request.selector {
                selector if selector > 0 => *target == selector as u64,
                0 => self.process_groups.get(target).copied() == Some(caller_group),
                -1 => true,
                _ => self.process_groups.get(target).copied() == requested_group,
            })
            .collect();
        if targets.is_empty() {
            return Err(protocol::STATUS_ESRCH);
        }

        let mut permitted = false;
        for target_id in targets {
            let Some(target) = self.sessions.get(&target_id).copied() else {
                continue;
            };
            // Job-control shells may continue jobs which changed their UID,
            // but only within the same POSIX session. Native object authority
            // remains unchanged; this is userspace signal permission policy.
            let same_session_continue = request.signal == protocol::SIGNAL_CONT
                && self
                    .session_ids
                    .get(&caller_id)
                    .is_some_and(|session| self.session_ids.get(&target_id) == Some(session));
            if !same_session_continue && !signal_permission(caller_id, caller, target_id, target) {
                continue;
            }
            permitted = true;
            if request.signal != 0 {
                self.enqueue_signal(target_id, request.signal)?;
            }
        }
        if permitted {
            Ok(())
        } else {
            Err(protocol::STATUS_EPERM)
        }
    }

    fn pending_signals_payload(&self, process_id: u64) -> Result<Vec<u8>, i32> {
        let pending = self
            .signals
            .get(&process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?
            .pending();
        let mut output = vec![0; protocol::SIGNAL_MASK_LEN];
        protocol::encode_signal_mask(pending, &mut output).map_err(|_| STATUS_EINVAL)?;
        Ok(output)
    }

    fn set_signal_child_options(
        &mut self,
        process_id: u64,
        payload: &[u8],
    ) -> Result<(), i32> {
        if !self.sessions.contains_key(&process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        let options = protocol::decode_signal_child_options(payload).map_err(|_| STATUS_EINVAL)?;
        self.signal_child_options.insert(process_id, options);
        if options & protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT != 0 {
            self.discard_observed_child_status(process_id);
        }
        Ok(())
    }

    fn signal_disposition_payload(
        &mut self,
        process_id: u64,
        flags: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, i32> {
        let request = protocol::decode_signal_disposition(payload).map_err(|_| STATUS_EINVAL)?;
        let setting = flags == protocol::SIGNAL_DISPOSITION_SET;
        if (!setting && (request.kind != 0 || request.child_options != 0))
            || (setting
                && matches!(
                    request.signal,
                    protocol::SIGNAL_KILL | protocol::SIGNAL_STOP
                ))
        {
            return Err(STATUS_EINVAL);
        }
        let state = self
            .signals
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let previous = protocol::SignalDisposition {
            signal: request.signal,
            kind: state.disposition(request.signal),
            child_options: if request.signal == protocol::SIGNAL_CHLD {
                self.signal_child_options
                    .get(&process_id)
                    .copied()
                    .unwrap_or_default()
            } else {
                0
            },
        };
        let mut output = vec![0; protocol::SIGNAL_DISPOSITION_LEN];
        protocol::encode_signal_disposition(previous, &mut output).map_err(|_| STATUS_EINVAL)?;
        if setting {
            state.set_disposition(request.signal, request.kind);
            if request.kind == protocol::SIGNAL_DISPOSITION_IGNORE {
                for ((process, _), pending) in &mut self.thread_pending_signals {
                    if *process == process_id {
                        *pending &= !signal_bit(request.signal);
                    }
                }
            }
            if state.pending() == 0 {
                self.signal_notifications.remove(&process_id);
            }
            if request.signal == protocol::SIGNAL_CHLD {
                self.signal_child_options
                    .insert(process_id, request.child_options);
            }
        }
        if setting && request.signal == protocol::SIGNAL_CHLD && self.discards_child_status(process_id) {
            self.discard_observed_child_status(process_id);
        }
        Ok(output)
    }

    fn signal_image_started_payload(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
    ) -> Result<Vec<u8>, i32> {
        let process_id = sender.process_id;
        let state = self
            .signals
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut output = vec![0; protocol::SIGNAL_MASK_LEN];
        protocol::encode_signal_mask(state.ignored, &mut output).map_err(|_| STATUS_EINVAL)?;
        // Startup is reached only after native image replacement succeeds.
        // Pending signals survive exec, unlike fork. Handler addresses and
        // action flags do not survive, even for an ignored signal.
        state.caught = 0;
        self.signal_child_options.insert(process_id, 0);
        // exec may replace an image while its signal handler is running.
        // That handler cannot return to complete its delivery in the old image.
        // Native image replacement retains this TID: thread-exit GC cannot
        // reclaim these tokens. Keep other threads' tokens and the caller's mask.
        if let Some(wait) = self.process_wait_states.get_mut(&process_id) {
            wait.deliveries
                .retain(|_, owner| owner.thread_id != sender.thread_id);
        }
        Ok(output)
    }

    /// `sender` must come from the kernel-authenticated request endpoint.
    /// Neither a PID nor a TID is accepted in the wire payload.
    pub fn handle_thread_signal_request(
        &mut self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
        header: protocol::Header,
        payload: &[u8],
    ) -> Response {
        let result = if !matches!(
            header.opcode,
            protocol::OP_SIGNAL_THREAD_MASK
                | protocol::OP_SIGNAL_THREAD_DEQUEUE
                | protocol::OP_SIGNAL_THREAD_PENDING
                | protocol::OP_SIGNAL_THREAD_RAISE
                | protocol::OP_SIGNAL_THREAD_EPOCH
                | protocol::OP_SIGNAL_IMAGE_STARTED
        ) {
            Err(protocol::STATUS_ENOSYS)
        } else if header.flags != 0 {
            Err(STATUS_EINVAL)
        } else if sender.process_id != peer.process_id
            || sender.process_id == 0
            || sender.thread_id == 0
        {
            Err(protocol::STATUS_EPERM)
        } else {
            match header.opcode {
                protocol::OP_SIGNAL_THREAD_MASK => self.thread_signal_mask_payload(sender, payload),
                protocol::OP_SIGNAL_THREAD_RAISE => self.thread_raise_signal_payload(sender, payload),
                protocol::OP_SIGNAL_THREAD_EPOCH if payload.is_empty() => {
                    let epoch = self
                        .signal_delivery_epochs
                        .get(&(sender.process_id, sender.thread_id))
                        .copied()
                        .ok_or(protocol::STATUS_ESRCH);
                    epoch.and_then(|epoch| {
                        let mut output = vec![0; protocol::SIGNAL_MASK_LEN];
                        protocol::encode_signal_mask(epoch, &mut output).map_err(|_| STATUS_EINVAL)?;
                        Ok(output)
                    })
                }
                protocol::OP_SIGNAL_THREAD_EPOCH => Err(STATUS_EINVAL),
                protocol::OP_SIGNAL_IMAGE_STARTED if payload.is_empty() => {
                    self.signal_image_started_payload(sender)
                }
                protocol::OP_SIGNAL_IMAGE_STARTED => Err(STATUS_EINVAL),
                _ => self.thread_signal_delivery_payload(sender, header.opcode, payload),
            }
        };
        match result {
            Ok(payload) => Response {
                header: protocol::Header {
                    opcode: protocol::OP_STATUS,
                    request_id: header.request_id,
                    payload_len: payload.len() as u32,
                    ..Default::default()
                },
                payload,
            },
            Err(error) => status_response(header.request_id, error),
        }
    }

    /// Consumes a native status observation for a retained ThreadHandle.
    /// This is a service/backend boundary, never a client-supplied IPC status.
    /// Only confirmed termination or native ESRCH permits reclamation.
    pub fn retire_signal_thread(
        &mut self,
        identity: mnu_abi::ExecutionIdentity,
        status: Result<mnu_abi::ThreadStatus, i32>,
    ) -> Result<bool, i32> {
        if identity.process_id == 0 || identity.thread_id == 0 {
            return Err(protocol::STATUS_EPERM);
        }
        let terminated = match status {
            Err(protocol::STATUS_ESRCH) => true,
            Err(error) => return Err(error),
            Ok(status) => {
                if status.process_id != identity.process_id || status.thread_id != identity.thread_id
                {
                    return Err(protocol::STATUS_EPERM);
                }
                if status.reserved != 0
                    || !(mnu_abi::THREAD_STATE_READY..=mnu_abi::THREAD_STATE_TERMINATED)
                        .contains(&status.state)
                {
                    return Err(STATUS_EINVAL);
                }
                status.state == mnu_abi::THREAD_STATE_TERMINATED
            }
        };
        if terminated {
            self.signal_masks.remove(&(identity.process_id, identity.thread_id));
            self.signal_delivery_epochs.remove(&(identity.process_id, identity.thread_id));
            self.thread_pending_signals.remove(&(identity.process_id, identity.thread_id));
            self.thread_signal_notifications.remove(&(identity.process_id, identity.thread_id));
            if let Some(wait) = self.process_wait_states.get_mut(&identity.process_id) {
                // A selected signal was already delivered to this thread.
                // Discard its abandoned completion token; do not redeliver it.
                wait.deliveries
                    .retain(|_, owner| owner.thread_id != identity.thread_id);
            }
            if self
                .signals
                .get(&identity.process_id)
                .is_some_and(|state| state.pending() != 0)
            {
                self.signal_notifications.insert(identity.process_id);
            }
        }
        Ok(terminated)
    }

    fn thread_signal_mask_payload(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        payload: &[u8],
    ) -> Result<Vec<u8>, i32> {
        if !self.sessions.contains_key(&sender.process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        let request = protocol::decode_signal_mask_request(payload).map_err(|_| STATUS_EINVAL)?;
        let unblockable = signal_bit(protocol::SIGNAL_KILL) | signal_bit(protocol::SIGNAL_STOP);
        let requested = request.mask & !unblockable;
        let key = (sender.process_id, sender.thread_id);
        let previous = self.signal_masks.get(&key).copied();
        let current = previous.unwrap_or(0);
        let updated = match request.operation {
            protocol::SIGNAL_MASK_QUERY => current,
            protocol::SIGNAL_MASK_SET => requested,
            protocol::SIGNAL_MASK_BLOCK => current | requested,
            protocol::SIGNAL_MASK_UNBLOCK => current & !requested,
            protocol::SIGNAL_MASK_INITIALIZE => previous.unwrap_or(requested),
            _ => return Err(STATUS_EINVAL),
        };
        let mut output = vec![0; protocol::SIGNAL_MASK_LEN];
        let returned = if request.operation == protocol::SIGNAL_MASK_INITIALIZE {
            updated
        } else {
            current
        };
        protocol::encode_signal_mask(returned, &mut output).map_err(|_| STATUS_EINVAL)?;
        if request.operation != protocol::SIGNAL_MASK_QUERY {
            self.signal_masks.insert(key, updated);
            self.signal_delivery_epochs.entry(key).or_insert(0);
            if current & !updated & self.signals[&sender.process_id].pending() != 0 {
                self.signal_notifications.insert(sender.process_id);
            }
            if current & !updated & self.thread_pending_signals.get(&key).copied().unwrap_or(0) != 0 {
                self.thread_signal_notifications.insert(key);
            }
        }
        Ok(output)
    }

    fn thread_raise_signal_payload(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        payload: &[u8],
    ) -> Result<Vec<u8>, i32> {
        let request = protocol::decode_signal_send_request(payload).map_err(|_| STATUS_EINVAL)?;
        if request.selector != 0 {
            return Err(STATUS_EINVAL);
        }
        let key = (sender.process_id, sender.thread_id);
        let blocked = *self.signal_masks.get(&key).ok_or(protocol::STATUS_ESRCH)?;
        if request.signal == 0 {
            return Ok(Vec::new());
        }
        self.prepare_signal_generation(sender.process_id, request.signal)?;
        if self.signals[&sender.process_id].disposition(request.signal)
            != protocol::SIGNAL_DISPOSITION_IGNORE
        {
            *self.thread_pending_signals.entry(key).or_default() |= signal_bit(request.signal);
            if blocked & signal_bit(request.signal) == 0 {
                self.thread_signal_notifications.insert(key);
            }
        }
        Ok(Vec::new())
    }

    /// Sender is authenticated endpoint metadata; target is the native status
    /// of the explicitly attached handle, never an identity from request bytes.
    pub fn send_thread_signal(
        &mut self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
        target: mnu_abi::ThreadStatus,
        rights: u64,
        payload: &[u8],
    ) -> Result<(), i32> {
        let required = mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL;
        if rights & required != required
            || sender.process_id != peer.process_id
            || sender.process_id == 0
            || sender.thread_id == 0
            || target.process_id != sender.process_id
        {
            return Err(protocol::STATUS_EPERM);
        }
        if target.thread_id == 0
            || target.reserved != 0
            || !(mnu_abi::THREAD_STATE_READY..=mnu_abi::THREAD_STATE_TERMINATED).contains(&target.state)
        {
            return Err(STATUS_EINVAL);
        }
        if target.state == mnu_abi::THREAD_STATE_TERMINATED {
            return Err(protocol::STATUS_ESRCH);
        }
        self.thread_raise_signal_payload(
            mnu_abi::ExecutionIdentity {
                process_id: target.process_id,
                thread_id: target.thread_id,
            },
            payload,
        )
        .map(|_| ())
    }

    fn thread_signal_delivery_payload(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        opcode: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, i32> {
        if !payload.is_empty() {
            return Err(STATUS_EINVAL);
        }
        // An explicit initialization is required: a missing thread record
        // must not silently grant delivery with an unblocked mask.
        let blocked = self
            .signal_masks
            .get(&(sender.process_id, sender.thread_id))
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if opcode == protocol::OP_SIGNAL_THREAD_DEQUEUE {
            self.dequeue_signal_with_mask(sender, blocked)
        } else {
            let pending = self
                .signals
                .get(&sender.process_id)
                .ok_or(protocol::STATUS_ESRCH)?
                .pending()
                | self
                    .thread_pending_signals
                    .get(&(sender.process_id, sender.thread_id))
                    .copied()
                    .unwrap_or(0);
            let pending = pending & blocked;
            let mut output = vec![0; protocol::SIGNAL_MASK_LEN];
            protocol::encode_signal_mask(pending, &mut output).map_err(|_| STATUS_EINVAL)?;
            Ok(output)
        }
    }

    fn dequeue_signal_with_mask(
        &mut self,
        sender: mnu_abi::ExecutionIdentity,
        blocked: u64,
    ) -> Result<Vec<u8>, i32> {
        let process_id = sender.process_id;
        let own_pending = self
            .thread_pending_signals
            .get(&(process_id, sender.thread_id))
            .copied()
            .unwrap_or(0)
            & !blocked;
        let own_signal = if own_pending == 0 {
            0
        } else {
            own_pending.trailing_zeros() + 1
        };
        let signal = if own_signal != 0 {
            own_signal
        } else {
            self.signals
                .get(&process_id)
                .ok_or(protocol::STATUS_ESRCH)?
                .next_deliverable(blocked)
        };
        let token = if signal != 0 {
            let state = self
                .process_wait_states
                .get_mut(&process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            if state.deliveries.len() >= MAX_OUTSTANDING_SIGNAL_DELIVERIES {
                return Err(protocol::STATUS_EAGAIN);
            }
            let mut token = self.next_signal_delivery_token.max(1);
            while state.contains_delivery_token(token) {
                token = token.wrapping_add(1).max(1);
            }
            self.next_signal_delivery_token = token.wrapping_add(1).max(1);
            let dequeued = if own_signal != 0 {
                *self
                    .thread_pending_signals
                    .get_mut(&(process_id, sender.thread_id))
                    .unwrap() &= !signal_bit(signal);
                signal
            } else {
                self.signals
                    .get_mut(&process_id)
                    .ok_or(protocol::STATUS_ESRCH)?
                    .dequeue(blocked)
            };
            debug_assert_eq!(dequeued, signal);
            let delivery = protocol::SignalDelivery { signal, token };
            state.begin_delivery(delivery, sender.thread_id);
            let epoch = self
                .signal_delivery_epochs
                .entry((process_id, sender.thread_id))
                .or_insert(0);
            *epoch = epoch.wrapping_add(1);
            token
        } else {
            0
        };
        let mut output = vec![0; protocol::SIGNAL_DELIVERY_LEN];
        protocol::encode_signal_delivery(protocol::SignalDelivery { signal, token }, &mut output)
            .map_err(|_| STATUS_EINVAL)?;
        Ok(output)
    }

    /// Validate before examining/reaping a child. `sender` is native endpoint
    /// metadata. A pending delivery or changed sequence releases a blocked IPC
    /// caller; userspace decides EINTR versus SA_RESTART after dispatch.
    pub fn validate_wait_delivery_epoch(
        &self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
        expected: u64,
    ) -> Result<(), i32> {
        if sender.process_id != peer.process_id || sender.process_id == 0 || sender.thread_id == 0 {
            return Err(protocol::STATUS_EPERM);
        }
        let key = (sender.process_id, sender.thread_id);
        let epoch = *self
            .signal_delivery_epochs
            .get(&key)
            .ok_or(protocol::STATUS_ESRCH)?;
        let blocked = *self.signal_masks.get(&key).ok_or(protocol::STATUS_ESRCH)?;
        let pending = self
            .signals
            .get(&sender.process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .pending()
            | self.thread_pending_signals.get(&key).copied().unwrap_or(0);
        if epoch != expected || pending & !blocked != 0 {
            Err(protocol::STATUS_EINTR)
        } else {
            Ok(())
        }
    }

    pub fn report_process_stopped<P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        payload: &[u8],
        processes: &mut P,
    ) -> Result<(), i32> {
        let delivery = protocol::decode_signal_delivery(payload).map_err(|_| STATUS_EINVAL)?;
        let signal = delivery.signal;
        if !matches!(
            signal,
            protocol::SIGNAL_STOP
                | protocol::SIGNAL_TSTP
                | protocol::SIGNAL_TTIN
                | protocol::SIGNAL_TTOU
        ) {
            return Err(STATUS_EINVAL);
        }
        let process = self
            .processes
            .get(&peer.process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if !self.sessions.contains_key(&peer.process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        if delivery.token == 0
            || !self
                .process_wait_states
                .get_mut(&peer.process_id)
                .ok_or(protocol::STATUS_ESRCH)?
                .consume_delivery(delivery)
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        // Catchable job-control signals are still delivered to userspace
        // handlers, but their default stop action is discarded for an orphaned
        // group. Check at application time: membership may change after dequeue.
        // SIGSTOP remains unconditional, and the exact token is consumed even
        // when the default action does nothing.
        if signal != protocol::SIGNAL_STOP {
            let session = *self
                .session_ids
                .get(&peer.process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            let group = *self
                .process_groups
                .get(&peer.process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            if !self.non_orphaned_groups().contains(&(session, group)) {
                return Ok(());
            }
        }
        processes.suspend(process)?;
        let stopped = self
            .process_wait_states
            .get_mut(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .stopped(signal);
        if stopped {
            self.notify_parent_of_child_change(peer.process_id, true)?;
        }
        Ok(())
    }

    pub fn complete_signal_delivery(
        &mut self,
        peer: PeerIdentity,
        payload: &[u8],
    ) -> Result<(), i32> {
        let delivery = protocol::decode_signal_delivery(payload).map_err(|_| STATUS_EINVAL)?;
        if delivery.signal == 0 || delivery.token == 0 {
            return Err(STATUS_EINVAL);
        }
        if !self.sessions.contains_key(&peer.process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        if !self
            .process_wait_states
            .get_mut(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .consume_delivery(delivery)
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        Ok(())
    }

    pub fn report_process_signaled<P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        payload: &[u8],
        processes: &mut P,
    ) -> Result<(), i32> {
        let delivery = protocol::decode_signal_delivery(payload).map_err(|_| STATUS_EINVAL)?;
        if delivery.token == 0 || !default_signal_terminates(delivery.signal) {
            return Err(STATUS_EINVAL);
        }
        let process = self
            .processes
            .get(&peer.process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if !self.sessions.contains_key(&peer.process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        if !self
            .process_wait_states
            .get_mut(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .consume_delivery(delivery)
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        processes.terminate(process, u64::from(128 + delivery.signal))?;
        self.process_wait_states
            .get_mut(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .termination_signal = Some(delivery.signal);
        Ok(())
    }

    pub fn handle(
        &mut self,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
    ) -> Response {
        let result = match header.opcode {
            protocol::OP_PING if header.flags == 0 && payload.is_empty() => Ok(Vec::new()),
            protocol::OP_SESSION_REGISTER if header.flags == 0 && payload.is_empty() => {
                // Registration acknowledges an environment initialized before
                // execution; IPC peer credentials must never create one.
                if self.registered_peer(peer.process_id).is_none() {
                    return status_response(header.request_id, STATUS_EINVAL);
                }
                Ok(Vec::new())
            }
            protocol::OP_SESSION_INFO if header.flags == 0 && payload.is_empty() => {
                self.session_info(peer.process_id)
            }
            protocol::OP_UMASK_SET if header.flags == 0 => self.set_umask(peer.process_id, payload),
            protocol::OP_SET_UID if header.flags == 0 => {
                self.set_uid(peer.process_id, payload).map(|_| Vec::new())
            }
            protocol::OP_SET_GID if header.flags == 0 => {
                self.set_gid(peer.process_id, payload).map(|_| Vec::new())
            }
            protocol::OP_SET_EFFECTIVE_UID if header.flags == 0 => self
                .set_effective_uid(peer.process_id, payload)
                .map(|_| Vec::new()),
            protocol::OP_SET_EFFECTIVE_GID if header.flags == 0 => self
                .set_effective_gid(peer.process_id, payload)
                .map(|_| Vec::new()),
            protocol::OP_SET_REAL_EFFECTIVE_UID if header.flags == 0 => self
                .set_real_effective_ids(peer.process_id, payload, true)
                .map(|_| Vec::new()),
            protocol::OP_SET_REAL_EFFECTIVE_GID if header.flags == 0 => self
                .set_real_effective_ids(peer.process_id, payload, false)
                .map(|_| Vec::new()),
            protocol::OP_RESET_EFFECTIVE_IDS if header.flags == 0 && payload.is_empty() => self
                .reset_effective_ids(peer.process_id)
                .map(|_| Vec::new()),
            protocol::OP_GROUPS_GET if header.flags == 0 && payload.is_empty() => {
                self.groups_payload(peer.process_id)
            }
            protocol::OP_GROUPS_SET if header.flags == 0 => self
                .set_groups(peer.process_id, payload)
                .map(|_| Vec::new()),
            protocol::OP_PROCESS_INFO if header.flags == 0 => {
                self.process_info_payload(peer.process_id, payload)
            }
            protocol::OP_SET_PROCESS_GROUP if header.flags == 0 => self
                .set_process_group(peer.process_id, payload)
                .map(|_| Vec::new()),
            protocol::OP_CREATE_SESSION if header.flags == 0 && payload.is_empty() => self
                .create_session(peer.process_id)
                .and_then(encode_process_info_payload),
            protocol::OP_RESOURCE_LIMIT if header.flags == 0 => {
                self.resource_limit_payload(peer.process_id, payload)
            }
            protocol::OP_SIGNAL_SEND if header.flags == 0 => self
                .send_signal(peer.process_id, payload)
                .map(|_| Vec::new()),
            protocol::OP_SIGNAL_PENDING if header.flags == 0 && payload.is_empty() => {
                self.pending_signals_payload(peer.process_id)
            }
            protocol::OP_SIGNAL_DELIVERY_COMPLETE if header.flags == 0 => self
                .complete_signal_delivery(peer, payload)
                .map(|_| Vec::new()),
            protocol::OP_SIGNAL_CHILD_OPTIONS if header.flags == 0 => self
                .set_signal_child_options(peer.process_id, payload)
                .map(|_| Vec::new()),
            protocol::OP_SIGNAL_DISPOSITION if header.flags <= protocol::SIGNAL_DISPOSITION_SET => {
                self.signal_disposition_payload(peer.process_id, header.flags, payload)
            }
            protocol::OP_PING
            | protocol::OP_SESSION_REGISTER
            | protocol::OP_SIGNAL_THREAD_REGISTER
            | protocol::OP_PTY_OPEN
            | protocol::OP_TERMINAL_ACQUIRE
            | protocol::OP_TERMINAL_RELEASE
            | protocol::OP_TERMINAL_GET_FOREGROUND
            | protocol::OP_TERMINAL_SET_FOREGROUND
            | protocol::OP_SESSION_INFO
            | protocol::OP_UMASK_SET
            | protocol::OP_GROUPS_GET
            | protocol::OP_OPEN_AT
            | protocol::OP_STAT_AT
            | protocol::OP_FSTAT
            | protocol::OP_ACCESS_AT
            | protocol::OP_CHDIR_AT
            | protocol::OP_CHROOT_AT
            | protocol::OP_FCHDIR
            | protocol::OP_GETCWD => Err(STATUS_EINVAL),
            protocol::OP_SET_UID
            | protocol::OP_SET_GID
            | protocol::OP_SET_EFFECTIVE_UID
            | protocol::OP_SET_EFFECTIVE_GID
            | protocol::OP_SET_REAL_EFFECTIVE_UID
            | protocol::OP_SET_REAL_EFFECTIVE_GID
            | protocol::OP_RESET_EFFECTIVE_IDS
            | protocol::OP_GROUPS_SET
            | protocol::OP_PROCESS_FORKED
            | protocol::OP_PROCESS_SPAWNED
            | protocol::OP_PROCESS_SESSION_INFO
            | protocol::OP_PROCESS_LAUNCHED
            | protocol::OP_PROCESS_LAUNCH_ABORT
            | protocol::OP_PROCESS_TREE_TERMINATE
            | protocol::OP_PROCESS_TREE_RECLAIM
            | protocol::OP_PROCESS_INITIALIZE
            | protocol::OP_WAIT_CHILD
            | protocol::OP_PROCESS_STOPPED
            | protocol::OP_PROCESS_INFO
            | protocol::OP_SET_PROCESS_GROUP
            | protocol::OP_CREATE_SESSION
            | protocol::OP_RESOURCE_LIMIT
            | protocol::OP_SIGNAL_SEND
            | protocol::OP_SIGNAL_PENDING
            | protocol::OP_SIGNAL_DELIVERY_COMPLETE
            | protocol::OP_PROCESS_SIGNALED
            | protocol::OP_SIGNAL_CHILD_OPTIONS
            | protocol::OP_SIGNAL_DISPOSITION
            | protocol::OP_SIGNAL_IMAGE_STARTED
            | protocol::OP_SIGNAL_THREAD_MASK
            | protocol::OP_SIGNAL_THREAD_DEQUEUE
            | protocol::OP_SIGNAL_THREAD_PENDING
            | protocol::OP_FTRUNCATE
            | protocol::OP_FSYNC
            | protocol::OP_FGETFL
            | protocol::OP_FSETFL
            | protocol::OP_MKDIR_AT
            | protocol::OP_UNLINK_AT
            | protocol::OP_RENAME_AT
            | protocol::OP_LINK_AT
            | protocol::OP_TRUNCATE_AT
            | protocol::OP_SYMLINK_AT
            | protocol::OP_READLINK_AT
            | protocol::OP_CHMOD_AT
            | protocol::OP_CHOWN_AT
            | protocol::OP_FCHMOD
            | protocol::OP_FCHOWN => Err(STATUS_EINVAL),
            _ => Err(protocol::STATUS_ENOSYS),
        };
        let (status, payload) = match result {
            Ok(payload) => (protocol::STATUS_OK, payload),
            Err(status) => (status, Vec::new()),
        };
        Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                flags: 0,
                payload_len: payload.len() as u32,
                status,
            },
            payload,
        }
    }

    pub fn handle_objects<F: FilesystemBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
        handles: &[AttachedObject<H>],
        filesystem: &mut F,
    ) -> ObjectResponse<H> {
        if !matches!(
            header.opcode,
            protocol::OP_OPEN_AT
                | protocol::OP_STAT_AT
                | protocol::OP_FSTAT
                | protocol::OP_ACCESS_AT
                | protocol::OP_CHDIR_AT
                | protocol::OP_CHROOT_AT
                | protocol::OP_FCHDIR
                | protocol::OP_GETCWD
                | protocol::OP_FTRUNCATE
                | protocol::OP_FSYNC
                | protocol::OP_FGETFL
                | protocol::OP_FSETFL
                | protocol::OP_MKDIR_AT
                | protocol::OP_UNLINK_AT
                | protocol::OP_RENAME_AT
                | protocol::OP_LINK_AT
                | protocol::OP_TRUNCATE_AT
                | protocol::OP_SYMLINK_AT
                | protocol::OP_READLINK_AT
                | protocol::OP_CHMOD_AT
                | protocol::OP_CHOWN_AT
                | protocol::OP_FCHMOD
                | protocol::OP_FCHOWN
        ) {
            let response = if handles.is_empty() {
                self.handle(peer, header, payload)
            } else {
                status_response(header.request_id, STATUS_EINVAL)
            };
            return ObjectResponse {
                response,
                handles: Vec::new(),
            };
        }
        if header.flags != 0 {
            return ObjectResponse {
                response: status_response(header.request_id, STATUS_EINVAL),
                handles: Vec::new(),
            };
        }
        if matches!(
            header.opcode,
            protocol::OP_OPEN_AT
                | protocol::OP_STAT_AT
                | protocol::OP_ACCESS_AT
                | protocol::OP_CHDIR_AT
                | protocol::OP_CHROOT_AT
                | protocol::OP_FCHDIR
                | protocol::OP_GETCWD
                | protocol::OP_MKDIR_AT
                | protocol::OP_UNLINK_AT
                | protocol::OP_RENAME_AT
                | protocol::OP_LINK_AT
                | protocol::OP_TRUNCATE_AT
                | protocol::OP_SYMLINK_AT
                | protocol::OP_READLINK_AT
                | protocol::OP_CHMOD_AT
                | protocol::OP_CHOWN_AT
        ) {
            if let Err(status) = self.ensure_session_directories(peer.process_id, filesystem) {
                return object_error(header.request_id, status);
            }
        }
        match header.opcode {
            protocol::OP_OPEN_AT => {
                let prepared = match self.prepare_open_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.open_at(&prepared, paths) {
                    Ok(opened) => ObjectResponse {
                        response: status_response(header.request_id, protocol::STATUS_OK),
                        handles: vec![opened],
                    },
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_STAT_AT => {
                let prepared = match self.prepare_stat_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.stat_at(&prepared, paths) {
                    Ok(status) => object_status(header.request_id, status),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FSTAT => {
                if !payload.is_empty() || handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                match filesystem.fstat(handles[0]) {
                    Ok(status) => object_status(header.request_id, status),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_ACCESS_AT => {
                let prepared = match self.prepare_access_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.access_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_CHDIR_AT => {
                let prepared = match self.prepare_stat_at(peer, payload, handles.len()) {
                    Ok(prepared) if prepared.flags == 0 => prepared,
                    Ok(_) => return object_error(header.request_id, STATUS_EINVAL),
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.open_directory_at(&prepared, paths) {
                    Ok(opened) => {
                        self.replace_cwd(
                            peer.process_id,
                            AttachedObject {
                                handle: opened.handle,
                                rights: opened.rights,
                            },
                            filesystem,
                        );
                        object_error(header.request_id, protocol::STATUS_OK)
                    }
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_CHROOT_AT => {
                let prepared = match self.prepare_stat_at(peer, payload, handles.len()) {
                    Ok(prepared) if prepared.flags == 0 => prepared,
                    Ok(_) => return object_error(header.request_id, STATUS_EINVAL),
                    Err(status) => return object_error(header.request_id, status),
                };
                if prepared.effective_uid != 0 {
                    return object_error(header.request_id, protocol::STATUS_EPERM);
                }
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.open_directory_at(&prepared, paths) {
                    Ok(opened) => {
                        self.replace_root(
                            peer.process_id,
                            AttachedObject {
                                handle: opened.handle,
                                rights: opened.rights,
                            },
                            filesystem,
                        );
                        object_error(header.request_id, protocol::STATUS_OK)
                    }
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FCHDIR => {
                if !payload.is_empty() || handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                let directory = handles[0];
                let status = match filesystem.fstat(directory) {
                    Ok(status) => status,
                    Err(status) => return object_error(header.request_id, status),
                };
                if status.mode & 0o170000 != 0o040000 {
                    return object_error(header.request_id, -20);
                }
                let retained = match filesystem.retain_object(directory) {
                    Ok(retained) => retained,
                    Err(status) => return object_error(header.request_id, status),
                };
                self.replace_cwd(peer.process_id, retained, filesystem);
                object_error(header.request_id, protocol::STATUS_OK)
            }
            protocol::OP_GETCWD => {
                if !payload.is_empty() || !handles.is_empty() {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                let directories = match self.directories.get(&peer.process_id) {
                    Some(directories) => *directories,
                    None => return object_error(header.request_id, protocol::STATUS_ESRCH),
                };
                match filesystem.directory_path(directories.root, directories.cwd) {
                    Ok(path) => object_payload(header.request_id, path),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FTRUNCATE => {
                if handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                let length = match protocol::decode_file_length(payload) {
                    Ok(length) => length,
                    Err(_) => return object_error(header.request_id, STATUS_EINVAL),
                };
                match filesystem.ftruncate(handles[0], length) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FCHMOD => {
                if handles.len() != 1 || payload.len() != 4 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                let session = match self.sessions.get(&peer.process_id) {
                    Some(session) => *session,
                    None => return object_error(header.request_id, protocol::STATUS_ESRCH),
                };
                let mode = u32::from_le_bytes(payload.try_into().unwrap());
                if mode & !0o7777 != 0 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                let supplementary_groups = self
                    .supplementary_groups
                    .get(&peer.process_id)
                    .cloned()
                    .unwrap_or_default();
                match filesystem.fchmod(
                    handles[0],
                    mode,
                    session.effective_uid,
                    session.effective_gid,
                    &supplementary_groups,
                ) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FCHOWN => {
                if handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                let session = match self.sessions.get(&peer.process_id) {
                    Some(session) => *session,
                    None => return object_error(header.request_id, protocol::STATUS_ESRCH),
                };
                let (uid, gid) = match protocol::decode_file_owner(payload) {
                    Ok(owner) => owner,
                    Err(_) => return object_error(header.request_id, STATUS_EINVAL),
                };
                let supplementary_groups = self
                    .supplementary_groups
                    .get(&peer.process_id)
                    .cloned()
                    .unwrap_or_default();
                match filesystem.fchown(
                    handles[0],
                    uid,
                    gid,
                    session.effective_uid,
                    session.effective_gid,
                    &supplementary_groups,
                ) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FSYNC => {
                if !payload.is_empty() || handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                match filesystem.fsync(handles[0]) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FGETFL => {
                if !payload.is_empty() || handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                match filesystem.get_status_flags(handles[0]) {
                    Ok(flags) => {
                        let mut payload = vec![0; protocol::FILE_FLAGS_PAYLOAD_LEN];
                        if protocol::encode_file_flags(flags, &mut payload).is_err() {
                            return object_error(header.request_id, STATUS_EINVAL);
                        }
                        object_payload(header.request_id, payload)
                    }
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_FSETFL => {
                if handles.len() != 1 {
                    return object_error(header.request_id, STATUS_EINVAL);
                }
                if !self.sessions.contains_key(&peer.process_id) {
                    return object_error(header.request_id, protocol::STATUS_ESRCH);
                }
                let flags = match protocol::decode_file_flags(payload) {
                    Ok(flags) if flags & !protocol::MUTABLE_STATUS_FLAGS == 0 => flags,
                    _ => return object_error(header.request_id, STATUS_EINVAL),
                };
                match filesystem.set_status_flags(handles[0], flags) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_MKDIR_AT => {
                let prepared = match self.prepare_mkdir_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.mkdir_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_UNLINK_AT => {
                let prepared = match self.prepare_unlink_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.unlink_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_RENAME_AT => {
                let prepared = match self.prepare_rename_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.rename_path_objects(
                    peer.process_id,
                    prepared.old_base,
                    prepared.new_base,
                    handles,
                ) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.rename_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_LINK_AT => {
                let prepared = match self.prepare_link_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.rename_path_objects(
                    peer.process_id,
                    prepared.old_base,
                    prepared.new_base,
                    handles,
                ) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.link_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_TRUNCATE_AT => {
                let prepared = match self.prepare_truncate_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.truncate_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_SYMLINK_AT => {
                let prepared = match self.prepare_symlink_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.symlink_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_READLINK_AT => {
                let prepared = match self.prepare_readlink_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.readlink_at(&prepared, paths) {
                    Ok(target) => object_payload(header.request_id, target),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_CHMOD_AT => {
                let prepared = match self.prepare_chmod_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.chmod_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            protocol::OP_CHOWN_AT => {
                let prepared = match self.prepare_chown_at(peer, payload, handles.len()) {
                    Ok(prepared) => prepared,
                    Err(status) => return object_error(header.request_id, status),
                };
                let paths = match self.path_objects(peer.process_id, prepared.base, handles) {
                    Ok(paths) => paths,
                    Err(status) => return object_error(header.request_id, status),
                };
                match filesystem.chown_at(&prepared, paths) {
                    Ok(()) => object_error(header.request_id, protocol::STATUS_OK),
                    Err(status) => object_error(header.request_id, status),
                }
            }
            _ => unreachable!(),
        }
    }

    fn replace_cwd<F: FilesystemBackend<H>>(
        &mut self,
        process_id: u64,
        cwd: AttachedObject<H>,
        filesystem: &mut F,
    ) {
        if let Some(directories) = self.directories.get_mut(&process_id) {
            let previous = core::mem::replace(&mut directories.cwd, cwd);
            filesystem.release_object(previous);
        }
    }

    fn replace_root<F: FilesystemBackend<H>>(
        &mut self,
        process_id: u64,
        root: AttachedObject<H>,
        filesystem: &mut F,
    ) {
        if let Some(directories) = self.directories.get_mut(&process_id) {
            let previous = core::mem::replace(&mut directories.root, root);
            filesystem.release_object(previous);
        }
    }

    fn ensure_session_directories<F: FilesystemBackend<H>>(
        &mut self,
        process_id: u64,
        filesystem: &mut F,
    ) -> Result<(), i32> {
        if self.directories.contains_key(&process_id) {
            return Ok(());
        }
        let session = self
            .sessions
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let supplementary_groups = self
            .supplementary_groups
            .get(&process_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let directories = filesystem.open_session_root(
            session.effective_uid,
            session.effective_gid,
            supplementary_groups,
        )?;
        self.directories.insert(process_id, directories);
        Ok(())
    }

    fn path_objects(
        &self,
        process_id: u64,
        base: protocol::OpenBase,
        handles: &[AttachedObject<H>],
    ) -> Result<PathObjects<H>, i32> {
        let directories = self
            .directories
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let base = match base {
            protocol::OpenBase::ProcessRoot => None,
            protocol::OpenBase::ProcessCwd => Some(directories.cwd),
            protocol::OpenBase::AttachedDirectory => handles.first().copied(),
        };
        Ok(PathObjects {
            root: directories.root,
            base,
        })
    }

    fn rename_path_objects(
        &self,
        process_id: u64,
        old_base: protocol::OpenBase,
        new_base: protocol::OpenBase,
        handles: &[AttachedObject<H>],
    ) -> Result<RenamePathObjects<H>, i32> {
        let directories = self
            .directories
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut next = 0usize;
        let mut resolve = |base| -> Result<Option<AttachedObject<H>>, i32> {
            match base {
                protocol::OpenBase::ProcessRoot => Ok(None),
                protocol::OpenBase::ProcessCwd => Ok(Some(directories.cwd)),
                protocol::OpenBase::AttachedDirectory => {
                    let object = handles.get(next).copied().ok_or(STATUS_EINVAL)?;
                    next += 1;
                    Ok(Some(object))
                }
            }
        };
        let old_base = resolve(old_base)?;
        let new_base = resolve(new_base)?;
        if next != handles.len() {
            return Err(STATUS_EINVAL);
        }
        Ok(RenamePathObjects {
            root: directories.root,
            old_base,
            new_base,
        })
    }

    pub fn prepare_open_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedOpen, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_open_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        let access = request.options & (protocol::OPEN_READ | protocol::OPEN_WRITE);
        if access == 0
            || request.options & protocol::OPEN_EXCLUSIVE != 0
                && request.options & protocol::OPEN_CREATE == 0
            || request.options & (protocol::OPEN_TRUNCATE | protocol::OPEN_APPEND) != 0
                && request.options & protocol::OPEN_WRITE == 0
        {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedOpen {
            base: request.base,
            options: request.options,
            mode: (request.mode & 0o7777) & !(session.umask & 0o777),
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_mkdir_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedMkdir, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_open_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles || request.options != 0 {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedMkdir {
            base: request.base,
            mode: (request.mode & 0o7777) & !(session.umask & 0o777),
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_unlink_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedUnlink, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_stat_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles || request.flags & !protocol::UNLINK_FLAGS_ALL != 0
        {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedUnlink {
            base: request.base,
            flags: request.flags,
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_rename_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedRename, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_rename_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles =
            usize::from(request.old_base == protocol::OpenBase::AttachedDirectory)
                + usize::from(request.new_base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedRename {
            old_base: request.old_base,
            new_base: request.new_base,
            old_path: request.old_path.to_owned(),
            new_path: request.new_path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_link_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedLink, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_link_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles =
            usize::from(request.old_base == protocol::OpenBase::AttachedDirectory)
                + usize::from(request.new_base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedLink {
            old_base: request.old_base,
            new_base: request.new_base,
            flags: request.flags,
            old_path: request.old_path.to_owned(),
            new_path: request.new_path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_truncate_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedTruncate, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_truncate_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedTruncate {
            base: request.base,
            path: request.path.to_owned(),
            length: request.length,
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_symlink_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedSymlink, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_symlink_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedSymlink {
            base: request.base,
            target: request.target.to_owned(),
            link_path: request.link_path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_readlink_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedReadlink, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_stat_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles || request.flags != 0 {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedReadlink {
            base: request.base,
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_chmod_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedChmod, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_open_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles
            || request.options != 0
            || request.mode & !0o7777 != 0
        {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedChmod {
            base: request.base,
            path: request.path.to_owned(),
            mode: request.mode,
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_chown_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedChown, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_chown_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedChown {
            base: request.base,
            path: request.path.to_owned(),
            flags: request.flags,
            uid: request.uid,
            gid: request.gid,
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_stat_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedStat, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_stat_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedStat {
            base: request.base,
            flags: request.flags,
            path: request.path.to_owned(),
            effective_uid: session.effective_uid,
            effective_gid: session.effective_gid,
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub fn prepare_access_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedAccess, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::decode_access_at(payload).map_err(|_| STATUS_EINVAL)?;
        let expected_handles = usize::from(request.base == protocol::OpenBase::AttachedDirectory);
        if attached_handles != expected_handles {
            return Err(STATUS_EINVAL);
        }
        let effective = request.flags & protocol::ACCESS_EFFECTIVE_IDS != 0;
        Ok(PreparedAccess {
            base: request.base,
            flags: request.flags,
            modes: request.modes,
            path: request.path.to_owned(),
            uid: if effective {
                session.effective_uid
            } else {
                session.real_uid
            },
            gid: if effective {
                session.effective_gid
            } else {
                session.real_gid
            },
            supplementary_groups: self
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }

    fn session_info(&self, process_id: u64) -> Result<Vec<u8>, i32> {
        let session = self
            .sessions
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut payload = vec![0u8; protocol::SESSION_INFO_LEN];
        protocol::encode_session_info(
            protocol::SessionInfo {
                real_uid: session.real_uid,
                effective_uid: session.effective_uid,
                real_gid: session.real_gid,
                effective_gid: session.effective_gid,
                umask: session.umask,
            },
            &mut payload,
        )
        .map_err(|_| STATUS_EINVAL)?;
        Ok(payload)
    }

    /// The runtime must authenticate `process` using the received native
    /// ProcessHandle. Request bytes never select the subject of inspection.
    pub fn inspect_process_session(
        &self,
        peer: PeerIdentity,
        process: AuthenticatedProcess<H>,
    ) -> Result<Vec<u8>, i32> {
        let caller = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let target = self
            .sessions
            .get(&process.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if peer.process_id != process.process_id
            && caller.effective_uid != 0
            && caller.effective_uid != target.effective_uid
        {
            return Err(protocol::STATUS_EPERM);
        }
        self.session_info(process.process_id)
    }

    fn set_umask(&mut self, process_id: u64, payload: &[u8]) -> Result<Vec<u8>, i32> {
        let requested = protocol::decode_umask(payload).map_err(|_| STATUS_EINVAL)?;
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let previous = session.umask;
        session.umask = requested & 0o777;
        let mut response = vec![0u8; protocol::UMASK_PAYLOAD_LEN];
        protocol::encode_umask(previous, &mut response).map_err(|_| STATUS_EINVAL)?;
        Ok(response)
    }

    fn set_uid(&mut self, process_id: u64, payload: &[u8]) -> Result<(), i32> {
        let requested = protocol::decode_credential_id(payload).map_err(|_| STATUS_EINVAL)?;
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if session.effective_uid == 0 {
            session.real_uid = requested;
            session.effective_uid = requested;
            session.saved_uid = requested;
            return Ok(());
        }
        if requested != session.real_uid && requested != session.saved_uid {
            return Err(-1);
        }
        session.effective_uid = requested;
        Ok(())
    }

    fn set_gid(&mut self, process_id: u64, payload: &[u8]) -> Result<(), i32> {
        let requested = protocol::decode_credential_id(payload).map_err(|_| STATUS_EINVAL)?;
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if session.effective_uid == 0 {
            session.real_gid = requested;
            session.effective_gid = requested;
            session.saved_gid = requested;
            return Ok(());
        }
        if requested != session.real_gid && requested != session.saved_gid {
            return Err(-1);
        }
        session.effective_gid = requested;
        Ok(())
    }

    fn set_effective_uid(&mut self, process_id: u64, payload: &[u8]) -> Result<(), i32> {
        let requested = protocol::decode_credential_id(payload).map_err(|_| STATUS_EINVAL)?;
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if session.effective_uid != 0
            && requested != session.real_uid
            && requested != session.effective_uid
            && requested != session.saved_uid
        {
            return Err(protocol::STATUS_EPERM);
        }
        session.effective_uid = requested;
        Ok(())
    }

    fn set_effective_gid(&mut self, process_id: u64, payload: &[u8]) -> Result<(), i32> {
        let requested = protocol::decode_credential_id(payload).map_err(|_| STATUS_EINVAL)?;
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if session.effective_uid != 0
            && requested != session.real_gid
            && requested != session.effective_gid
            && requested != session.saved_gid
        {
            return Err(protocol::STATUS_EPERM);
        }
        session.effective_gid = requested;
        Ok(())
    }

    fn set_real_effective_ids(
        &mut self,
        process_id: u64,
        payload: &[u8],
        user: bool,
    ) -> Result<(), i32> {
        let (real, effective) =
            protocol::decode_credential_pair(payload).map_err(|_| STATUS_EINVAL)?;
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let (old_real, old_effective, old_saved) = if user {
            (session.real_uid, session.effective_uid, session.saved_uid)
        } else {
            (session.real_gid, session.effective_gid, session.saved_gid)
        };
        let change_real = real != protocol::CREDENTIAL_ID_UNCHANGED;
        let change_effective = effective != protocol::CREDENTIAL_ID_UNCHANGED;
        // Validate both against the OLD credentials before modifying anything.
        // POSIX privilege never changes native Handle/Capability authority.
        if session.effective_uid != 0
            && ((change_real && real != old_real && real != old_effective)
                || (change_effective
                    && effective != old_real
                    && effective != old_effective
                    && effective != old_saved))
        {
            return Err(protocol::STATUS_EPERM);
        }
        let new_real = if change_real { real } else { old_real };
        let new_effective = if change_effective {
            effective
        } else {
            old_effective
        };
        let new_saved = if change_real || (change_effective && effective != old_real) {
            new_effective
        } else {
            old_saved
        };
        if user {
            session.real_uid = new_real;
            session.effective_uid = new_effective;
            session.saved_uid = new_saved;
        } else {
            session.real_gid = new_real;
            session.effective_gid = new_effective;
            session.saved_gid = new_saved;
        }
        Ok(())
    }

    fn reset_effective_ids(&mut self, process_id: u64) -> Result<(), i32> {
        let session = self
            .sessions
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        session.effective_uid = session.real_uid;
        session.effective_gid = session.real_gid;
        Ok(())
    }

    fn groups_payload(&self, process_id: u64) -> Result<Vec<u8>, i32> {
        if !self.sessions.contains_key(&process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        let groups = self
            .supplementary_groups
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut payload = vec![0u8; protocol::GROUP_LIST_MAX_LEN];
        let length =
            protocol::encode_group_list(groups, &mut payload).map_err(|_| STATUS_EINVAL)?;
        payload.truncate(length);
        Ok(payload)
    }

    fn set_groups(&mut self, process_id: u64, payload: &[u8]) -> Result<(), i32> {
        let session = self
            .sessions
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if session.effective_uid != 0 {
            return Err(protocol::STATUS_EPERM);
        }
        let mut decoded = [0u32; protocol::MAX_SUPPLEMENTARY_GROUPS];
        let count =
            protocol::decode_group_list(payload, &mut decoded).map_err(|_| STATUS_EINVAL)?;
        self.supplementary_groups
            .insert(process_id, decoded[..count].to_vec());
        Ok(())
    }
}

fn signal_permission(caller_id: u64, caller: Session, target_id: u64, target: Session) -> bool {
    caller_id == target_id
        || caller.real_uid == target.real_uid
        || caller.real_uid == target.saved_uid
        || caller.effective_uid == target.real_uid
        || caller.effective_uid == target.saved_uid
}

fn object_error<H>(request_id: u64, status: i32) -> ObjectResponse<H> {
    ObjectResponse {
        response: status_response(request_id, status),
        handles: Vec::new(),
    }
}

fn encode_process_info_payload(info: protocol::ProcessInfo) -> Result<Vec<u8>, i32> {
    let mut payload = vec![0u8; protocol::PROCESS_INFO_LEN];
    protocol::encode_process_info(info, &mut payload).map_err(|_| STATUS_EINVAL)?;
    Ok(payload)
}

fn object_payload<H>(request_id: u64, payload: Vec<u8>) -> ObjectResponse<H> {
    ObjectResponse {
        response: Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id,
                payload_len: payload.len() as u32,
                status: protocol::STATUS_OK,
                ..protocol::Header::default()
            },
            payload,
        },
        handles: Vec::new(),
    }
}

fn object_status<H>(request_id: u64, status: protocol::FileStatus) -> ObjectResponse<H> {
    let mut payload = vec![0u8; protocol::FILE_STATUS_LEN];
    if protocol::encode_file_status(status, &mut payload).is_err() {
        return object_error(request_id, STATUS_EINVAL);
    }
    ObjectResponse {
        response: Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id,
                payload_len: payload.len() as u32,
                status: protocol::STATUS_OK,
                ..protocol::Header::default()
            },
            payload,
        },
        handles: Vec::new(),
    }
}

fn status_response(request_id: u64, status: i32) -> Response {
    Response {
        header: protocol::Header {
            opcode: protocol::OP_STATUS,
            request_id,
            status,
            ..protocol::Header::default()
        },
        payload: Vec::new(),
    }
}
