use std::collections::{BTreeMap, BTreeSet};

use mochios_posix_protocol as protocol;

pub mod pty;
pub mod pty_factory;
pub mod pty_metadata;
pub mod pty_metadata_ipc;
pub mod pty_open;
pub mod pty_request;
pub mod pty_master;
pub mod pty_grant;
pub mod pty_grant_ipc;
pub mod terminal_identity;
pub mod terminal_namespace;
pub mod terminal_publication;
pub mod named_semaphore;
pub mod shared_memory;
pub mod shared_memory_file;
pub mod socket;
pub mod socket_record;
pub mod socket_stream;
pub mod socket_record_io;
pub mod socket_rights;
mod socket_reference;
pub mod socket_gc;
pub mod socket_transfer;
pub mod socket_route;
pub mod socket_provider;
pub mod socket_binding;
pub mod socket_connect;
pub mod socket_receive_wait;
pub mod filesystem_transport;
pub mod filesystem_metadata;
pub mod mutation_admission;
mod open_flags;
pub mod open_request;
mod path_request;
pub mod path_query;
pub mod path_mutation;
pub mod path_pair;
pub mod directory_request;
pub mod file_request;
mod fault_signal;
mod signal_origin;
mod signal_dequeue;
mod alarm;
mod timer_schedule;
pub mod process_timer;
pub mod process_timer_request;
pub mod process_timer_reactor;
pub mod process_timer_delivery;
mod fork_state;
pub mod resource_policy;
pub mod cpu_limit;
pub mod process_clock;
pub mod cpu_sleep;
mod cpu_timer;
mod process_group;
mod image_state;
pub use image_state::RequestImage;
mod child_notification;
pub mod filesystem_times;
pub use fork_state::validate_fork_child;

pub const STATUS_EINVAL: i32 = -22;
pub const STATUS_EOVERFLOW: i32 = -75;

/// Translate the generic filesystem growth rejection without confusing it
/// with an ordinary filesystem EFBIG (which must not generate SIGXFSZ).
pub const fn truncate_filesystem_status(status: i32) -> i32 {
    if status == -mochios_filesystem_protocol::ERROR_GROWTH_LIMIT {
        protocol::STATUS_FILE_SIZE_LIMIT
    } else {
        mutation_filesystem_status(status)
    }
}

/// Preserve the filesystem's pre-mutation retry guarantee, not an errno-based
/// guess. The service returns immediately so other clients can finish I/O or
/// send SIGCONT; it must not wait for admission in its serialized RPC loop.
pub const fn mutation_filesystem_status(status: i32) -> i32 {
    if status == -mochios_filesystem_protocol::ERROR_MEMORY_ADMISSION_BUSY {
        protocol::STATUS_MEMORY_ADMISSION_BUSY
    } else {
        status
    }
}

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
    pub path: Vec<u8>,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedMkdir {
    pub base: protocol::OpenBase,
    pub mode: u32,
    pub path: Vec<u8>,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedUnlink {
    pub base: protocol::OpenBase,
    pub flags: u32,
    pub path: Vec<u8>,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRename {
    pub old_base: protocol::OpenBase,
    pub new_base: protocol::OpenBase,
    pub old_path: Vec<u8>,
    pub new_path: Vec<u8>,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedLink {
    pub old_base: protocol::OpenBase,
    pub new_base: protocol::OpenBase,
    pub flags: u32,
    pub old_path: Vec<u8>,
    pub new_path: Vec<u8>,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTruncate {
    pub base: protocol::OpenBase,
    pub path: Vec<u8>,
    pub length: u64,
    pub growth_ceiling: u64,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSymlink {
    pub base: protocol::OpenBase,
    pub target: Vec<u8>,
    pub link_path: Vec<u8>,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReadlink {
    pub base: protocol::OpenBase,
    pub path: Vec<u8>,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedChmod {
    pub base: protocol::OpenBase,
    pub path: Vec<u8>,
    pub mode: u32,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedChown {
    pub base: protocol::OpenBase,
    pub path: Vec<u8>,
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
    pub path: Vec<u8>,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFileTimes {
    pub target: PreparedStat,
    pub times: protocol::file_time::Update,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAccess {
    pub base: protocol::OpenBase,
    pub flags: u32,
    pub modes: u32,
    pub path: Vec<u8>,
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

/// A Wait reference is newly owned by this service, not borrowed from the
/// request. It grants waiting/transfer only, never mutation authorization.
pub enum MutationError<H> {
    Failed(i32),
    Wait(OpenedObject<H>),
}

impl<H> From<i32> for MutationError<H> {
    fn from(status: i32) -> Self {
        Self::Failed(status)
    }
}

impl<H> MutationError<H> {
    pub fn map_status(self, map: impl FnOnce(i32) -> i32) -> Self {
        match self {
            Self::Failed(status) => Self::Failed(map(status)),
            Self::Wait(ticket) => Self::Wait(ticket),
        }
    }
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

    fn open_at_admitted(
        &mut self,
        _request: &PreparedOpen,
        _paths: PathObjects<H>,
        _ticket: Option<AttachedObject<H>>,
    ) -> Result<OpenedObject<H>, MutationError<H>> {
        Err(MutationError::Failed(-95))
    }

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

    /// Resolves and reconstructs an existing pathname in one filesystem call.
    fn canonical_path_at(
        &mut self,
        _request: &PreparedStat,
        _paths: PathObjects<H>,
    ) -> Result<Vec<u8>, i32> {
        Err(protocol::STATUS_ENOSYS)
    }

    /// Reads metadata from the open file description identified by `file`.
    fn fstat(&mut self, file: AttachedObject<H>) -> Result<protocol::FileStatus, i32>;

    fn ftruncate(
        &mut self,
        file: AttachedObject<H>,
        length: u64,
        growth_ceiling: u64,
    ) -> Result<(), i32>;

    fn ftruncate_admitted(
        &mut self,
        _file: AttachedObject<H>,
        _length: u64,
        _growth_ceiling: u64,
        _ticket: Option<AttachedObject<H>>,
    ) -> Result<(), MutationError<H>> {
        Err(MutationError::Failed(-95))
    }

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

    fn futimens(
        &mut self,
        _file: AttachedObject<H>,
        _times: protocol::file_time::Update,
        _effective_uid: u32,
        _effective_gid: u32,
        _supplementary_groups: &[u32],
    ) -> Result<(), i32> {
        Err(protocol::STATUS_ENOSYS)
    }

    fn utimens_at(&mut self, _request: &PreparedFileTimes, _paths: PathObjects<H>) -> Result<(), i32> {
        Err(protocol::STATUS_ENOSYS)
    }

    fn fsync(&mut self, file: AttachedObject<H>) -> Result<(), i32>;

    fn get_status_flags(&mut self, file: AttachedObject<H>) -> Result<u32, i32>;

    fn set_status_flags(&mut self, file: AttachedObject<H>, flags: u32) -> Result<(), i32>;

    fn update_status_flags(
        &mut self,
        file: AttachedObject<H>,
        mask: u32,
        flags: u32,
    ) -> Result<(), i32>;

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

    fn truncate_at_admitted(
        &mut self,
        _request: &PreparedTruncate,
        _paths: PathObjects<H>,
        _ticket: Option<AttachedObject<H>>,
    ) -> Result<(), MutationError<H>> {
        Err(MutationError::Failed(-95))
    }

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
    /// This must use local reference management, not a peer-service RPC:
    /// callers may hold the POSIX state lock while retaining pathname anchors.
    fn retain_object(&mut self, object: AttachedObject<H>) -> Result<AttachedObject<H>, i32>;

    /// Releases one service-owned object reference locally, without peer RPC.
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
    waited_cpu: WaitedChildCpuUsage,
    // A launcher registered a fresh executable, not a pre-exec fork image.
    // Native image revisions count replacements only; initial loaded images
    // already cross the POSIX spawn/exec boundary without a replacement.
    fresh_image: bool,
    observed_image_revision: u64,
    stopped: bool,
    stop_signal: u32,
    stop_reported: bool,
    continued_pending: bool,
    // Signal enqueue requests this transition; only native resume commits it.
    resume_continued: bool,
    exit_observed: bool,
    exit_notified: bool,
    discard_exit_status: bool,
    deliveries: BTreeMap<u64, SignalDeliveryOwner>,
    termination_signal: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignalDeliveryOwner {
    signal: u32,
    origin: protocol::signal_origin::Origin,
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
        if !self.stopped {
            return false;
        }
        self.stopped = false;
        self.stop_reported = false;
        self.continued_pending = true;
        true
    }

    fn begin_delivery(
        &mut self,
        delivery: protocol::SignalDelivery,
        thread_id: u64,
        origin: protocol::signal_origin::Origin,
    ) {
        self.deliveries.insert(
            delivery.token,
            SignalDeliveryOwner {
                signal: delivery.signal,
                origin,
                thread_id,
            },
        );
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
            if options & protocol::WAIT_NOWAIT == 0 {
                self.stop_reported = true;
            }
            return Some((self.stop_signal << 8) | 0x7f);
        }
        if options & protocol::WAIT_CONTINUED != 0 && self.continued_pending {
            if options & protocol::WAIT_NOWAIT == 0 {
                self.continued_pending = false;
            }
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

/// Server-local outcome; none of these values are part of the wire protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalWaitCompletion {
    Pending,
    Replied,
    Undelivered,
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
        } else if default_signal_ignores(signal) {
            // Selecting SIG_DFL for a default-ignored signal discards pending
            // occurrences even while blocked. This does not auto-reap children.
            self.pending &= !bit;
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

fn default_signal_ignores(signal: u32) -> bool {
    matches!(
        signal,
        protocol::SIGNAL_URG | protocol::SIGNAL_CHLD | protocol::SIGNAL_WINCH
    )
}

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
    /// Observe an owned native process reference, including committed image
    /// revision. Missing support must never mean that no replacement occurred.
    fn image_status(&mut self, _process: H) -> Result<mnu_abi::ProcessStatus, i32> {
        Err(protocol::STATUS_ENOSYS)
    }
    /// Reads the retained native process object, not client-supplied metrics.
    fn execution_usage(&mut self, process: H) -> Result<mnu_abi::ProcessExecutionUsage, i32>;
    fn suspend(&mut self, process: H) -> Result<(), i32>;
    /// Resume a retained native object; success confirms completion, not queuing.
    fn resume(&mut self, _process: H) -> Result<(), i32> {
        Err(protocol::STATUS_ENOSYS)
    }
    fn terminate(&mut self, process: H, exit_code: u64) -> Result<(), i32>;
    fn release(&mut self, process: H);
}

/// Waited-for children and the descendants those children actually waited for.
/// Native tick precision is preserved until conversion at the libc boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitedChildCpuUsage {
    pub user_ticks: u128,
    pub kernel_ticks: u128,
    /// Zero only for an empty accumulator. All native processes share a clock
    /// sampling rate; inconsistent backend rates must not be mixed silently.
    pub ticks_per_second: u64,
}

impl WaitedChildCpuUsage {
    /// Combines counts without truncation, unit mixing, or wrapping.
    pub fn checked_add(self, other: Self) -> Result<Self, i32> {
        if (self.ticks_per_second == 0 && (self.user_ticks != 0 || self.kernel_ticks != 0))
            || (other.ticks_per_second == 0 && (other.user_ticks != 0 || other.kernel_ticks != 0))
        {
            return Err(protocol::STATUS_EIO);
        }
        let rate = self.ticks_per_second.max(other.ticks_per_second);
        if (self.ticks_per_second != 0 && self.ticks_per_second != rate)
            || (other.ticks_per_second != 0 && other.ticks_per_second != rate)
        {
            return Err(protocol::STATUS_EIO);
        }
        Ok(Self {
            user_ticks: self.user_ticks.checked_add(other.user_ticks)
                .ok_or(STATUS_EOVERFLOW)?,
            kernel_ticks: self.kernel_ticks.checked_add(other.kernel_ticks)
                .ok_or(STATUS_EOVERFLOW)?,
            ticks_per_second: rate,
        })
    }
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
    monotonic_clock: Option<fn() -> Result<u64, i32>>,
    real_timers: BTreeMap<u64, alarm::RealTimer>,
    cpu_timers: BTreeMap<(u64, u32), cpu_timer::CpuTimer>,
    process_timers: process_timer::Registry,
    resource_policies: Vec<(u64, Box<dyn resource_policy::Published<H>>)>,
    prepared_forks: Vec<(u64, fork_state::ForkState<H>)>,
    next_fork_token: u64,
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
    named_semaphores: named_semaphore::Namespace<H>,
    shared_memory: shared_memory::Namespace<H>,
    resource_limits: BTreeMap<(u64, u32), protocol::ResourceLimit>,
    cpu_notifications: BTreeMap<u64, u128>,
    signals: BTreeMap<u64, ProcessSignalState>,
    // Native identities arrive only from authenticated endpoint metadata.
    signal_masks: BTreeMap<(u64, u64), u64>,
    signal_delivery_epochs: BTreeMap<(u64, u64), u64>,
    thread_pending_signals: BTreeMap<(u64, u64), u64>,
    signal_origins: BTreeMap<(u64, u64, u32), protocol::signal_origin::Origin>,
    thread_signal_notifications: BTreeSet<(u64, u64)>,
    signal_child_options: BTreeMap<u64, u32>,
    process_wait_states: BTreeMap<u64, ProcessWaitState>,
    next_signal_delivery_token: u64,
    signal_notifications: BTreeSet<u64>,
    process_resume_notifications: BTreeSet<u64>,
    deferred_child_notifications: std::collections::VecDeque<child_notification::Deferred>,
}

impl PosixService<u32> {
    pub const fn new() -> Self {
        Self {
            monotonic_clock: None,
            real_timers: BTreeMap::new(),
            cpu_timers: BTreeMap::new(),
            process_timers: process_timer::Registry::new(),
            resource_policies: Vec::new(),
            prepared_forks: Vec::new(),
            next_fork_token: 1,
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
            named_semaphores: named_semaphore::Namespace::new(),
            shared_memory: shared_memory::Namespace::new(),
            resource_limits: BTreeMap::new(),
            cpu_notifications: BTreeMap::new(),
            signals: BTreeMap::new(),
            signal_masks: BTreeMap::new(),
            signal_delivery_epochs: BTreeMap::new(),
            thread_pending_signals: BTreeMap::new(),
            signal_origins: BTreeMap::new(),
            thread_signal_notifications: BTreeSet::new(),
            signal_child_options: BTreeMap::new(),
            process_wait_states: BTreeMap::new(),
            next_signal_delivery_token: 1,
            signal_notifications: BTreeSet::new(),
            process_resume_notifications: BTreeSet::new(),
            deferred_child_notifications: std::collections::VecDeque::new(),
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

    /// Complete queued signal policy through the already-retained native
    /// process reference. Failed native operations leave all effects pending.
    /// True means one pending action completed or was retired after native exit.
    pub fn apply_process_resume<P: ProcessBackend<H>>(
        &mut self,
        process_id: u64,
        processes: &mut P,
    ) -> Result<bool, i32> {
        if !self.process_resume_notifications.contains(&process_id) {
            return Ok(false);
        }
        let handle = self
            .processes
            .get(&process_id)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        if !self.process_wait_states.contains_key(&process_id) {
            return Err(protocol::STATUS_ESRCH);
        }
        if matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
            self.cancel_unconfirmed_resume(process_id);
            return Ok(true);
        }
        let continued = self.process_wait_states[&process_id].resume_continued;
        let notification = if continued {
            self.prepare_child_resume(process_id)?
        } else {
            None
        };
        if notification.is_some() {
            self.deferred_child_notifications
                .try_reserve(1)
                .map_err(|_| protocol::STATUS_ENOMEM)?;
        }
        processes.resume(handle)?;
        // No fallible observation/publication follows a successful resume.
        // STOP tokens generated after SIGCONT must remain valid; cancellation
        // belongs to signal generation, not to this later native completion.
        self.process_resume_notifications.remove(&process_id);
        if let Some(state) = self.process_wait_states.get_mut(&process_id) {
            state.resume_continued = false;
            if continued && state.continued() {
                if let Some(notification) = notification {
                    self.deferred_child_notifications.push_back(notification);
                }
            }
        }
        Ok(true)
    }

    fn cancel_unconfirmed_resume(&mut self, process_id: u64) {
        self.process_resume_notifications.remove(&process_id);
        if let Some(state) = self.process_wait_states.get_mut(&process_id) {
            state.resume_continued = false;
        }
    }

    fn enqueue_signal(&mut self, process_id: u64, signal: u32) -> Result<(), i32> {
        self.enqueue_signal_with_origin(
            process_id, signal, protocol::signal_origin::Origin::system(),
        )
    }

    fn enqueue_signal_with_origin(
        &mut self,
        process_id: u64,
        signal: u32,
        origin: protocol::signal_origin::Origin,
    ) -> Result<(), i32> {
        self.prepare_signal_generation(process_id, signal)?;
        let pending = self.signals.get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?.pending();
        self.signals
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .enqueue(signal);
        if self.signals[&process_id].pending() & signal_bit(signal) != 0 {
            if pending & signal_bit(signal) == 0 {
                self.signal_origins.insert((process_id, 0, signal), origin);
            }
            self.signal_notifications.insert(process_id);
        } else if self.signals[&process_id].pending() == 0
            && self.process_timers.pending_signal_mask(process_id) == 0 {
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
        self.process_timers.discard_signals(process_id, cancelled);
        for ((process, _), pending) in &mut self.thread_pending_signals {
            if *process == process_id {
                *pending &= !cancelled;
            }
        }
        self.signal_origins.retain(|(process, _, signal), _| {
            *process != process_id || signal_bit(*signal) & cancelled == 0
        });
        if signal == protocol::SIGNAL_CONT {
            let wait = self
                .process_wait_states
                .get_mut(&process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            wait.cancel_stop_deliveries();
            wait.resume_continued |= wait.stopped;
        } else if signal == protocol::SIGNAL_KILL {
            self.process_wait_states
                .get_mut(&process_id)
                .ok_or(protocol::STATUS_ESRCH)?
                .cancel_stop_deliveries();
        }
        if matches!(signal, protocol::SIGNAL_KILL | protocol::SIGNAL_CONT) {
            self.process_resume_notifications.insert(process_id);
        }
        Ok(())
    }

    fn notify_parent_of_child_change(
        &mut self,
        child_id: u64,
        child: protocol::signal_origin::ChildStatus,
    ) -> Result<(), i32> {
        let Some(parent_id) = self.parents.get(&child_id).copied() else {
            return Ok(());
        };
        if !self.signals.contains_key(&parent_id) {
            return Ok(());
        }
        if matches!(
            child.event,
            protocol::signal_origin::STOPPED | protocol::signal_origin::CONTINUED
        )
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
        let real_uid = self.sessions.get(&child_id)
            .ok_or(protocol::STATUS_ESRCH)?.real_uid;
        self.enqueue_signal_with_origin(
            parent_id, protocol::SIGNAL_CHLD,
            protocol::signal_origin::Origin {
                source: protocol::signal_origin::CHILD,
                real_uid,
                process_id: child_id,
                child,
                timer: None,
            },
        )
    }

    // The parent and its native Handle come only from service-owned state.
    // Refresh before applying image-local child notification/exit policy.
    fn refresh_parent_image<P: ProcessBackend<H>>(
        &mut self,
        child_id: u64,
        processes: &mut P,
    ) -> Result<(), i32> {
        if let Some(parent) = self.parents.get(&child_id).copied() {
            self.refresh_process_image_state(parent, true, processes)?;
        }
        Ok(())
    }

    fn note_child_exited<P: ProcessBackend<H>>(
        &mut self,
        child_id: u64,
        exit_code: u64,
        processes: &mut P,
    ) -> Result<bool, i32> {
        self.refresh_child_notifications_for_child(child_id, processes)?;
        self.refresh_parent_image(child_id, processes)?;
        let wait_state = self
            .process_wait_states
            .get_mut(&child_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if wait_state.exit_notified {
            return Ok(false);
        }
        let child = match wait_state.termination_signal {
            Some(signal) => protocol::signal_origin::ChildStatus {
                event: protocol::signal_origin::KILLED,
                status: signal,
            },
            None => protocol::signal_origin::ChildStatus {
                event: protocol::signal_origin::EXITED,
                status: (exit_code & 0xff) as u32,
            },
        };
        wait_state.exit_notified = true;
        if let Err(status) = self.notify_parent_of_child_change(child_id, child) {
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
        self.refresh_child_notifications(processes)?;
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
                    && !self.resource_policies.iter().any(|(owner, _)| *owner == *child_id)
                    && !self.real_timers.contains_key(child_id)
                    && !self.has_cpu_timer_state(*child_id)
                    && !self.process_timers.has_owner(*child_id)
                    && !self.process_timers.observes_process(*child_id)
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
            if let ProcessLifecycle::Exited { exit_code } = processes.status(handle)? {
                self.observe_process_exit(child_id, processes)?;
                if self.parents.contains_key(&child_id)
                    && self.note_child_exited(child_id, exit_code, processes)?
                {
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

    fn observe_process_exit<P: ProcessBackend<H>>(
        &mut self,
        process_id: u64,
        processes: &mut P,
    ) -> Result<(), i32> {
        self.cancel_unconfirmed_resume(process_id);
        self.refresh_child_notifications_for_child(process_id, processes)?;
        self.refresh_parent_image(process_id, processes)?;
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
        self.real_timers.remove(&process_id);
        self.cpu_timers.retain(|&(owner, _), _| owner != process_id);
        self.process_timers.retire_owner(process_id);
        self.retire_process_clock_targets(process_id);
        self.resource_policies.retain(|(owner, _)| *owner != process_id);
        self.hangup_exited_controlling_process(process_id)?;
        self.process_wait_states
            .get_mut(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .exit_observed = true;
        self.reparent_children_of_exited(process_id);
        self.notify_newly_orphaned_groups(connected_before)
    }

    /// Exit, setsid and setpgid can all remove the last outside-parent link
    /// from a group. Notify only on a connected-to-orphaned transition, and
    /// only when the remaining live group contains a stopped process.
    fn notify_newly_orphaned_groups(
        &mut self,
        connected_before: BTreeSet<(u64, u64)>,
    ) -> Result<(), i32> {
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
            self.observe_process_exit(process_id, processes)?;
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
            // A native exec can clear SA_NOCLDWAIT without a request from
            // the parent. Never turn an old cached flag into a lost status.
            self.refresh_parent_image(child, processes)?;
            let discarded = self
                .process_wait_states
                .get(&child)
                .is_some_and(|state| state.discard_exit_status);
            if !discarded && !self.discards_child_status(parent) {
                continue;
            }
            let handle = *self.processes.get(&child).ok_or(protocol::STATUS_ESRCH)?;
            if !matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                continue;
            }
            self.observe_process_exit(child, processes)?;
            if !self
                .process_wait_states
                .get(&child)
                .ok_or(protocol::STATUS_ESRCH)?
                .discard_exit_status
            {
                // Exit observation re-read the parent's image. An exec may
                // have cleared NOCLDWAIT after this candidate was selected;
                // only an actual discard decision authorizes reclamation.
                continue;
            }
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
                        || self.prepared_forks.iter().any(|(_, state)| state.owned_by(*child_id))
                        || self.resource_policies.iter().any(|(owner, _)| *owner == *child_id)
                        || self.has_reparentable_children(*child_id)
                        || self.needs_parent_exit_observation(*child_id)
                        || self.controlling_terminals.contains_key(child_id)
                        || (!state.exit_observed && (self.real_timers.contains_key(child_id)
                            || self.has_cpu_timer_state(*child_id)
                            || self.process_timers.has_owner(*child_id)
                            || self.process_timers.observes_process(*child_id))) =>
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
        let token = self.prepare_fork(peer, filesystem)?;
        if let Err(error) = self.commit_fork(peer, token, process) {
            let _ = self.cancel_fork(peer, token, filesystem);
            return Err(error);
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
        self.reset_image_signals(process.process_id);
        self.process_wait_states
            .get_mut(&process.process_id)
            .unwrap()
            .fresh_image = true;
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
        // This is a fresh executable, not a fork continuation: do not retain
        // the requester's old saved identities across this image boundary.
        let session = self.sessions.get_mut(&child.process_id).unwrap();
        session.saved_uid = session.effective_uid;
        session.saved_gid = session.effective_gid;
        self.reset_image_signals(child.process_id);
        self.process_wait_states
            .get_mut(&child.process_id)
            .unwrap()
            .fresh_image = true;
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
        self.wait_child_info(peer, request, filesystem, processes)
            .map(|info| info.result)
    }

    /// Captures the child's real POSIX UID in the same transaction as event
    /// selection and reaping; callers cannot query an already-reaped identity.
    pub fn wait_child_info<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        request: protocol::WaitRequest,
        filesystem: &mut F,
        processes: &mut P,
    ) -> Result<protocol::WaitInfo, i32> {
        self.wait_child_info_with_reply(peer, request, filesystem, processes, |_| true)?
            .ok_or(protocol::STATUS_EIO)
    }

    /// Select under exclusive service access, but consume only when the
    /// transport accepts the reply. `Ok(None)` means delivery failed; the
    /// event and waited CPU accounting remain available to another waiter.
    pub fn wait_child_info_with_reply<F, P, R>(
        &mut self,
        peer: PeerIdentity,
        request: protocol::WaitRequest,
        filesystem: &mut F,
        processes: &mut P,
        reply: R,
    ) -> Result<Option<protocol::WaitInfo>, i32>
    where
        F: FilesystemBackend<H>,
        P: ProcessBackend<H>,
        R: FnOnce(protocol::WaitInfo) -> bool,
    {
        self.matching_child_ids(peer, request)?;
        self.reap_discarded_children_for(Some(peer.process_id), filesystem, processes)?;
        let candidates = self.matching_child_ids(peer, request)?;
        let mut can_change = false;
        for child in candidates {
            if self.reap_is_pinned(child) {
                can_change = true;
                continue;
            }
            let handle = self
                .processes
                .get(&child)
                .copied()
                .ok_or(protocol::STATUS_ESRCH)?;
            let real_uid = self.sessions.get(&child)
                .ok_or(protocol::STATUS_ESRCH)?.real_uid;
            if let ProcessLifecycle::Exited { exit_code } = processes.status(handle)? {
                self.note_child_exited(child, exit_code, processes)?;
                if !protocol::wait_selects_exit(request.options) {
                    continue;
                }
                let status = self
                    .process_wait_states
                    .get(&child)
                    .and_then(|state| state.termination_signal)
                    .map(|signal| signal & 0x7f)
                    .unwrap_or_else(|| ((exit_code & 0xff) as u32) << 8);
                if request.options & protocol::WAIT_NOWAIT != 0 {
                    let info = protocol::WaitInfo {
                        result: protocol::WaitResult {
                            process_id: child,
                            status,
                        },
                        real_uid,
                    };
                    return Ok(reply(info).then_some(info));
                }
                let usage = processes.execution_usage(handle)?;
                if usage.ticks_per_second == 0 || usage.reserved != 0 {
                    return Err(protocol::STATUS_EIO);
                }
                let own = WaitedChildCpuUsage {
                    user_ticks: u128::from(usage.user_ticks),
                    kernel_ticks: u128::from(usage.kernel_ticks),
                    ticks_per_second: usage.ticks_per_second,
                };
                let descendant = self.process_wait_states
                    .get(&child)
                    .ok_or(protocol::STATUS_ESRCH)?
                    .waited_cpu;
                let total = self.process_wait_states
                    .get(&peer.process_id)
                    .ok_or(protocol::STATUS_ESRCH)?
                    .waited_cpu
                    .checked_add(own)?
                    .checked_add(descendant)?;
                // Compute and validate first. Backend failures and overflow
                // leave the child waitable and do not partially add its time.
                self.observe_process_exit(child, processes)?;
                let info = protocol::WaitInfo {
                    result: protocol::WaitResult {
                        process_id: child,
                        status,
                    },
                    real_uid,
                };
                if !reply(info) {
                    return Ok(None);
                }
                // No fallible observation or accounting follows publication.
                self.reap_observed_child(peer.process_id, child, filesystem, processes);
                self.process_wait_states.get_mut(&peer.process_id)
                    .unwrap().waited_cpu = total;
                return Ok(Some(info));
            }
            can_change = true;
            if let Some(status) = self
                .process_wait_states
                .get_mut(&child)
                .and_then(|state| state.take_status(request.options | protocol::WAIT_NOWAIT))
            {
                let info = protocol::WaitInfo {
                    result: protocol::WaitResult {
                        process_id: child,
                        status,
                    },
                    real_uid,
                };
                if !reply(info) {
                    return Ok(None);
                }
                self.process_wait_states.get_mut(&child).unwrap().take_status(request.options);
                return Ok(Some(info));
            }
        }
        // An exited child cannot subsequently stop or continue. Keep it
        // waitable for an exit-selecting caller, but do not block or spin on
        // its permanently-ready native exit Handle for an unrelated event.
        if !can_change {
            return Err(protocol::STATUS_ECHILD);
        }
        if request.options & protocol::WAIT_NOHANG != 0 {
            let info = protocol::WaitInfo::default();
            Ok(reply(info).then_some(info))
        } else {
            Err(protocol::STATUS_EAGAIN)
        }
    }

    /// Only the authenticated caller's already-waited child time is exposed.
    pub fn waited_child_cpu_usage(&self, peer: PeerIdentity) -> Result<WaitedChildCpuUsage, i32> {
        self.process_wait_states
            .get(&peer.process_id)
            .map(|state| state.waited_cpu)
            .ok_or(protocol::STATUS_ESRCH)
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
            .filter(|child| {
                protocol::wait_selects_exit(request.options)
                    || !self.process_wait_states.get(child).is_some_and(|state| {
                        // wait_child can discover an exit before the global
                        // teardown pass has marked exit_observed.
                        state.exit_observed || state.exit_notified
                    })
            })
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
        if !protocol::wait_options_valid(request.options)
            || (request.options & protocol::WAIT_SELECT_GROUP != 0 && request.selector < 0)
        {
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
                group if request.options & protocol::WAIT_SELECT_GROUP != 0 => {
                    let group = if group == 0 { caller_group } else { group as u64 };
                    self.process_groups.get(child).copied() == Some(group)
                }
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
        self.observe_process_exit(child_id, processes)?;
        self.reap_observed_child(parent_id, child_id, filesystem, processes);
        Ok(())
    }

    // The caller has completed all fallible exit observations. Keep cleanup
    // infallible so a published wait reply cannot leave a waitable duplicate.
    fn reap_observed_child<F: FilesystemBackend<H>, P: ProcessBackend<H>>(
        &mut self,
        parent_id: u64,
        child_id: u64,
        filesystem: &mut F,
        processes: &mut P,
    ) {
        self.cancel_owned_forks(child_id, filesystem);
        self.resource_policies.retain(|(owner, _)| *owner != child_id);
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
        self.cpu_notifications.remove(&child_id);
        self.signals.remove(&child_id);
        self.signal_masks.retain(|(process, _), _| *process != child_id);
        self.signal_delivery_epochs.retain(|(process, _), _| *process != child_id);
        self.thread_pending_signals.retain(|(process, _), _| *process != child_id);
        self.signal_origins.retain(|(process, _, _), _| *process != child_id);
        self.thread_signal_notifications.retain(|(process, _)| *process != child_id);
        self.signal_child_options.remove(&child_id);
        self.process_wait_states.remove(&child_id);
        self.signal_notifications.remove(&child_id);
        self.process_resume_notifications.remove(&child_id);
        self.discard_child_notifications_to(child_id);
        self.sessions.remove(&child_id);
        self.real_timers.remove(&child_id);
        self.cpu_timers.retain(|&(owner, _), _| owner != child_id);
        self.process_timers.retire_owner(child_id);
        self.retire_process_clock_targets(child_id);
        if let Some(directories) = self.directories.remove(&child_id) {
            filesystem.release_object(directories.root);
            filesystem.release_object(directories.cwd);
        }
        if let Some(handle) = self.processes.remove(&child_id) {
            processes.release(handle);
        }
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

    fn set_process_group(
        &mut self,
        caller_id: u64,
        payload: &[u8],
        image_status: impl FnOnce(H) -> Result<mnu_abi::ProcessStatus, i32>,
    ) -> Result<(), i32> {
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
        if target != caller_id {
            let handle = self
                .processes
                .get(&target)
                .copied()
                .ok_or(protocol::STATUS_ESRCH)?;
            let image = image_status(handle)?;
            if image.process_id != target || image.reserved != 0 {
                return Err(protocol::STATUS_EIO);
            }
            match image.state {
                mnu_abi::PROCESS_STATE_RUNNING => {}
                mnu_abi::PROCESS_STATE_EXITED => return Err(protocol::STATUS_ESRCH),
                _ => return Err(protocol::STATUS_EIO),
            }
            if image.image_revision != 0
                || self
                    .process_wait_states
                    .get(&target)
                    .ok_or(protocol::STATUS_ESRCH)?
                    .fresh_image
            {
                return Err(-13); // EACCES: this child has a new executable image.
            }
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
        let connected_before = self.non_orphaned_groups();
        self.process_groups.insert(target, group);
        self.notify_newly_orphaned_groups(connected_before)
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
        let connected_before = self.non_orphaned_groups();
        self.process_groups.insert(process_id, process_id);
        self.session_ids.insert(process_id, process_id);
        self.notify_newly_orphaned_groups(connected_before)?;
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
            protocol::OP_TERMINAL_GET_FOREGROUND | protocol::OP_TERMINAL_GET_SESSION
                if header.flags == 0 && payload.is_empty() =>
            {
                // Reuse the same controlling-terminal authorization for both
                // queries. State remains locked throughout this observation.
                self.terminal_foreground_process_group(peer.process_id, terminal_id)
                    .and_then(|foreground| {
                        let group = if header.opcode == protocol::OP_TERMINAL_GET_SESSION {
                            self.session_ids
                                .get(&peer.process_id)
                                .copied()
                                .ok_or(protocol::STATUS_ESRCH)?
                        } else {
                            foreground
                        };
                        let group = i64::try_from(group).map_err(|_| STATUS_EINVAL)?;
                        let mut output = vec![0; protocol::PROCESS_ID_REQUEST_LEN];
                        protocol::encode_process_id_request(group, &mut output)
                            .map_err(|_| STATUS_EINVAL)?;
                        Ok(output)
                    })
            }
            protocol::OP_TERMINAL_SET_FOREGROUND if header.flags == 0 => self
                .set_terminal_foreground_process_group(sender, terminal_id, payload)
                .map(|_| Vec::new()),
            protocol::OP_TERMINAL_ACQUIRE
            | protocol::OP_TERMINAL_RELEASE
            | protocol::OP_TERMINAL_GET_FOREGROUND
            | protocol::OP_TERMINAL_GET_SESSION
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
            // Keep the service map and every published reader synchronized.
            // Reserve/insert before publication, and restore the override if
            // publication fails; no client may observe a silently stale page.
            let overridden = self.resource_limits.insert(key, request.limit);
            if let Some((_, page)) = self.resource_policies.iter().find(|(owner, _)| *owner == target_id) {
                if let Err(error) = page.publish(request.resource, request.limit) {
                    if let Some(old) = overridden {
                        *self.resource_limits.get_mut(&key).unwrap() = old;
                    } else {
                        self.resource_limits.remove(&key);
                    }
                    return Err(error);
                }
            }
        }

        if request.flags & protocol::RESOURCE_LIMIT_SET != 0
            && request.resource == protocol::RLIMIT_CPU
        {
            // Publication succeeded; never alter repeat accounting on a
            // rejected limit or failed shared-policy-page update.
            self.cpu_notifications.remove(&target_id);
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
                self.enqueue_signal_with_origin(
                    target_id, request.signal,
                    protocol::signal_origin::Origin {
                        source: protocol::signal_origin::USER,
                        real_uid: caller.real_uid, process_id: caller_id,
                        ..protocol::signal_origin::Origin::system()
                    },
                )?;
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
            .pending() | self.process_timers.pending_signal_mask(process_id);
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
            if request.kind == protocol::SIGNAL_DISPOSITION_IGNORE
                || (request.kind == protocol::SIGNAL_DISPOSITION_DEFAULT
                    && default_signal_ignores(request.signal))
            {
                self.process_timers.discard_signals(process_id, signal_bit(request.signal));
                self.signal_origins.retain(|(process, _, signal), _| {
                    *process != process_id || *signal != request.signal
                });
                for (key, pending) in &mut self.thread_pending_signals {
                    if key.0 == process_id {
                        *pending &= !signal_bit(request.signal);
                        if *pending == 0 {
                            self.thread_signal_notifications.remove(key);
                        }
                    }
                }
            }
            if state.pending() == 0 && self.process_timers.pending_signal_mask(process_id) == 0 {
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
            .get(&process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut output = vec![0; protocol::SIGNAL_MASK_LEN];
        protocol::encode_signal_mask(state.ignored, &mut output).map_err(|_| STATUS_EINVAL)?;
        // Only an authenticated native image observation resets policy. A
        // repeat or fabricated startup request cannot erase installed actions
        // or abandon a still-live handler's completion token.
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
                | protocol::OP_SIGNAL_THREAD_FAULT
                | protocol::OP_SIGNAL_DELIVERY_ORIGIN
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
                protocol::OP_SIGNAL_THREAD_FAULT => self.thread_fault_signal_payload(sender, payload),
                protocol::OP_SIGNAL_DELIVERY_ORIGIN => self.signal_delivery_origin_payload(sender, payload),
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
    /// Only confirmed termination or native NotFound permits reclamation.
    pub fn retire_signal_thread(
        &mut self,
        identity: mnu_abi::ExecutionIdentity,
        status: Result<mnu_abi::ThreadStatus, i32>,
    ) -> Result<bool, i32> {
        if identity.process_id == 0 || identity.thread_id == 0 {
            return Err(protocol::STATUS_EPERM);
        }
        let terminated = match status {
            Err(error)
                if mnu_abi::status::Error::from_raw(error as i64 as u64)
                    == Some(mnu_abi::status::Error::NotFound) =>
            {
                true
            }
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
            self.process_timers.retire_thread(identity.process_id, identity.thread_id);
            self.remove_empty_signal_notification(identity.process_id);
            self.signal_masks.remove(&(identity.process_id, identity.thread_id));
            self.signal_delivery_epochs.remove(&(identity.process_id, identity.thread_id));
            self.thread_pending_signals.remove(&(identity.process_id, identity.thread_id));
            self.signal_origins.retain(|(process, thread, _), _| {
                (*process, *thread) != (identity.process_id, identity.thread_id)
            });
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
                .is_some_and(|state| state.pending() != 0
                    || self.process_timers.pending_signal_mask(identity.process_id) != 0)
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
            let newly_unblocked = previous.map_or(!updated, |current| current & !updated);
            if newly_unblocked & (self.signals[&sender.process_id].pending()
                | self.process_timers.pending_signal_mask(sender.process_id)) != 0 {
                self.signal_notifications.insert(sender.process_id);
            }
            if newly_unblocked & self.thread_pending_signals.get(&key).copied().unwrap_or(0) != 0 {
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
            let pending = self.thread_pending_signals.entry(key).or_default();
            if *pending & signal_bit(request.signal) == 0 {
                let real_uid = self.sessions.get(&sender.process_id)
                    .ok_or(protocol::STATUS_ESRCH)?.real_uid;
                self.signal_origins.insert(
                    (sender.process_id, sender.thread_id, request.signal),
                    protocol::signal_origin::Origin {
                        source: protocol::signal_origin::USER, real_uid, process_id: sender.process_id,
                        ..protocol::signal_origin::Origin::system()
                    },
                );
            }
            *pending |= signal_bit(request.signal);
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
                    .unwrap_or(0)
                | self.process_timers.pending_signal_mask(sender.process_id);
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
            let origin_key = (
                process_id, if own_signal != 0 { sender.thread_id } else { 0 }, signal,
            );
            let origin = self.signal_origins.get(&origin_key).copied()
                .ok_or(protocol::STATUS_EIO)?;
            let delivery = self.begin_signal_delivery(sender, signal, origin)?;
            self.signal_origins.remove(&origin_key);
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
            delivery.token
        } else {
            0
        };
        let mut output = vec![0; protocol::SIGNAL_DELIVERY_LEN];
        protocol::encode_signal_delivery(protocol::SignalDelivery { signal, token }, &mut output)
            .map_err(|_| STATUS_EINVAL)?;
        Ok(output)
    }

    /// Atomically accepts one blocked signal for a synchronous signal waiter.
    /// `sender` must come from authenticated native endpoint metadata. EAGAIN
    /// leaves all pending state intact so the transport can retain the request
    /// until a signal arrives; no handler delivery/completion token is created.
    pub fn try_wait_signal(
        &mut self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
        requested: u64,
        expected_epoch: u64,
    ) -> Result<u32, i32> {
        self.try_wait_signal_info(peer, sender, requested, expected_epoch)
            .map(|accepted| accepted.signal)
    }

    /// `Ok(None)` keeps a deferred request. A pending signal is accepted
    /// before testing expiry, so timeout observation cannot discard it.
    pub fn poll_wait_signal_info(
        &mut self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
        requested: u64,
        expected_epoch: u64,
        deadline: Option<u64>,
        now: u64,
    ) -> Result<Option<protocol::signal_wait::Accepted>, i32> {
        match self.try_wait_signal_info(peer, sender, requested, expected_epoch) {
            Err(protocol::STATUS_EAGAIN) if deadline.is_none_or(|deadline| now < deadline) => {
                Ok(None)
            }
            result => result.map(Some),
        }
    }

    pub fn try_wait_signal_info(
        &mut self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
        requested: u64,
        expected_epoch: u64,
    ) -> Result<protocol::signal_wait::Accepted, i32> {
        self.try_wait_signal_info_with_reply(peer, sender, requested, expected_epoch, |_| true)?
            .ok_or(protocol::STATUS_EIO)
    }

    /// An expired wait still selects a pending signal first. Failed reply
    /// publication leaves that exact signal and its origin pending, but is
    /// distinct from a request that must remain deferred awaiting a signal.
    pub fn poll_wait_signal_info_with_reply<R>(
        &mut self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
        requested: u64,
        expected_epoch: u64,
        deadline: Option<u64>,
        now: u64,
        reply: R,
    ) -> Result<SignalWaitCompletion, i32>
    where
        R: FnOnce(protocol::signal_wait::Accepted) -> bool,
    {
        match self.try_wait_signal_info_with_reply(peer, sender, requested, expected_epoch, reply) {
            Err(protocol::STATUS_EAGAIN) if deadline.is_none_or(|deadline| now < deadline) => {
                Ok(SignalWaitCompletion::Pending)
            }
            Ok(Some(_)) => Ok(SignalWaitCompletion::Replied),
            Ok(None) => Ok(SignalWaitCompletion::Undelivered),
            Err(error) => Err(error),
        }
    }

    fn try_wait_signal_info_with_reply<R>(
        &mut self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
        requested: u64,
        expected_epoch: u64,
        reply: R,
    ) -> Result<Option<protocol::signal_wait::Accepted>, i32>
    where
        R: FnOnce(protocol::signal_wait::Accepted) -> bool,
    {
        self.validate_wait_delivery_epoch(peer, sender, expected_epoch)?;
        let key = (sender.process_id, sender.thread_id);
        let blocked = self.signal_masks[&key];
        // Uncatchable signals cannot be selected, including in sigfillset().
        let requested = requested
            & !(signal_bit(protocol::SIGNAL_KILL) | signal_bit(protocol::SIGNAL_STOP));
        if requested & !blocked != 0 {
            return Err(STATUS_EINVAL);
        }
        let own = self.thread_pending_signals.get(&key).copied().unwrap_or(0) & requested;
        if own != 0 {
            let signal = own.trailing_zeros() + 1;
            let origin = self
                .signal_origins
                .get(&(sender.process_id, sender.thread_id, signal))
                .copied()
                .ok_or(protocol::STATUS_EIO)?;
            let accepted = protocol::signal_wait::Accepted { signal, origin };
            if !reply(accepted) {
                return Ok(None);
            }
            *self.thread_pending_signals.get_mut(&key).unwrap() &= !signal_bit(signal);
            self.signal_origins.remove(&(sender.process_id, sender.thread_id, signal));
            return Ok(Some(accepted));
        }
        let state = self.signals.get_mut(&sender.process_id).unwrap();
        let selected = state.pending() & requested;
        if selected == 0 {
            return Err(protocol::STATUS_EAGAIN);
        }
        let signal = selected.trailing_zeros() + 1;
        let origin = self
            .signal_origins
            .get(&(sender.process_id, 0, signal))
            .copied()
            .ok_or(protocol::STATUS_EIO)?;
        let accepted = protocol::signal_wait::Accepted { signal, origin };
        if !reply(accepted) {
            return Ok(None);
        }
        state.pending &= !signal_bit(signal);
        self.signal_origins.remove(&(sender.process_id, 0, signal));
        Ok(Some(accepted))
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
            | self.thread_pending_signals.get(&key).copied().unwrap_or(0)
            | (self.process_timers.pending_signal_mask(sender.process_id)
                & !self.signals[&sender.process_id].ignored);
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
            || self
                .process_wait_states
                .get(&peer.process_id)
                .ok_or(protocol::STATUS_ESRCH)?
                .deliveries
                .get(&delivery.token)
                .map(|owner| owner.signal) != Some(signal)
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
                self.process_wait_states
                    .get_mut(&peer.process_id)
                    .unwrap()
                    .consume_delivery(delivery);
                return Ok(());
            }
        }
        // A later stop cannot overtake an earlier queued native resume.
        // Failure leaves this new stop token available for a retry.
        self.apply_process_resume(peer.process_id, processes)?;
        // The parent may have committed exec without sending a new request.
        // Observe it before consuming the token or suspending the child, so a
        // failed observation leaves this authenticated stop retryable.
        self.refresh_child_notifications_for_child(peer.process_id, processes)?;
        self.refresh_parent_image(peer.process_id, processes)?;
        processes.suspend(process)?;
        // Only commit delivery after the native operation succeeds. The
        // service serializes this transition, so the validated token is stable.
        self.process_wait_states
            .get_mut(&peer.process_id)
            .unwrap()
            .consume_delivery(delivery);
        let stopped = self
            .process_wait_states
            .get_mut(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .stopped(signal);
        if stopped {
            self.notify_parent_of_child_change(
                peer.process_id,
                protocol::signal_origin::ChildStatus {
                    event: protocol::signal_origin::STOPPED,
                    status: signal,
                },
            )?;
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
            protocol::OP_WAITED_CHILD_CPU_USAGE if header.flags == 0 && payload.is_empty() => {
                self.waited_child_cpu_usage(peer).and_then(|usage| {
                    let mut output = vec![0; protocol::WAITED_CHILD_CPU_USAGE_LEN];
                    protocol::encode_waited_child_cpu_usage(protocol::WaitedChildCpuUsage {
                        user_ticks: usage.user_ticks,
                        kernel_ticks: usage.kernel_ticks,
                        ticks_per_second: usage.ticks_per_second,
                    }, &mut output).map_err(|_| protocol::STATUS_EIO)?;
                    Ok(output)
                })
            }
            protocol::OP_UMASK_SET if header.flags == 0 => self.set_umask(peer.process_id, payload),
            protocol::OP_ALARM if header.flags == 0 => self.alarm_payload(peer.process_id, payload),
            protocol::OP_REAL_TIMER_GET if header.flags == 0 && payload.is_empty() => {
                self.real_timer_payload(peer.process_id, None)
            }
            protocol::OP_REAL_TIMER_SET if header.flags == 0 => {
                protocol::interval_timer::decode(payload)
                    .map_err(|_| STATUS_EINVAL)
                    .and_then(|value| self.real_timer_payload(peer.process_id, Some(value)))
            }
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
                .set_process_group(peer.process_id, payload, |_| Err(protocol::STATUS_ENOSYS))
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
            | protocol::OP_TERMINAL_GET_SESSION
            | protocol::OP_TERMINAL_SET_FOREGROUND
            | protocol::OP_SESSION_INFO
            | protocol::OP_WAITED_CHILD_CPU_USAGE
            | protocol::OP_UMASK_SET
            | protocol::OP_GROUPS_GET
            | protocol::OP_OPEN_AT
            | protocol::OP_STAT_AT
            | protocol::OP_CANONICAL_PATH_AT
            | protocol::OP_FSTAT
            | protocol::OP_ACCESS_AT
            | protocol::OP_CHDIR_AT
            | protocol::OP_CHROOT_AT
            | protocol::OP_FCHDIR
            | protocol::OP_GETCWD => Err(STATUS_EINVAL),
            protocol::OP_SET_UID
            | protocol::OP_REAL_TIMER_GET
            | protocol::OP_REAL_TIMER_SET
            | protocol::OP_SET_GID
            | protocol::OP_SET_EFFECTIVE_UID
            | protocol::OP_SET_EFFECTIVE_GID
            | protocol::OP_SET_REAL_EFFECTIVE_UID
            | protocol::OP_SET_REAL_EFFECTIVE_GID
            | protocol::OP_RESET_EFFECTIVE_IDS
            | protocol::OP_GROUPS_SET
            | protocol::OP_FORK_PREPARE
            | protocol::OP_FORK_COMMIT
            | protocol::OP_FORK_CANCEL
            | protocol::OP_RESOURCE_POLICY
            | protocol::OP_PROCESS_CPU_CLOCK
            | protocol::OP_TIMER_CREATE_PROCESS_CPU
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
            | protocol::OP_FUPDATEFL
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
            | protocol::OP_FUTIMENS
            | protocol::OP_UTIMENS_AT => Err(STATUS_EINVAL),
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
        if header.status != 0 {
            return object_error(header.request_id, STATUS_EINVAL);
        }
        let envelope = match mutation_admission::Request::decode(header, handles) {
            Ok(envelope) => envelope,
            Err(status) => return object_error(header.request_id, status),
        };
        let header = envelope.header;
        let handles = envelope.sources;
        let admission = envelope.admission;
        if matches!(
            header.opcode,
            protocol::OP_FORK_PREPARE | protocol::OP_FORK_CANCEL
        ) {
            let result = if header.flags != 0 || header.status != 0 || !handles.is_empty() {
                Err(STATUS_EINVAL)
            } else if header.opcode == protocol::OP_FORK_PREPARE {
                if !payload.is_empty() {
                    Err(STATUS_EINVAL)
                } else {
                    self.prepare_fork(peer, filesystem)
                        .map(|token| token.to_le_bytes().to_vec())
                }
            } else {
                protocol::fork::decode_token(payload)
                    .map_err(|_| STATUS_EINVAL)
                    .and_then(|token| self.cancel_fork(peer, token, filesystem))
                    .map(|()| Vec::new())
            };
            let response = match result {
                Ok(payload) => Response {
                    header: protocol::Header {
                        opcode: protocol::OP_STATUS,
                        request_id: header.request_id,
                        payload_len: payload.len() as u32,
                        ..Default::default()
                    },
                    payload,
                },
                Err(status) => status_response(header.request_id, status),
            };
            return ObjectResponse {
                response,
                handles: Vec::new(),
            };
        }
        if !matches!(
            header.opcode,
            protocol::OP_OPEN_AT
                | protocol::OP_STAT_AT
                | protocol::OP_CANONICAL_PATH_AT
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
                | protocol::OP_FUPDATEFL
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
                | protocol::OP_FUTIMENS
                | protocol::OP_UTIMENS_AT
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
                | protocol::OP_CANONICAL_PATH_AT
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
                | protocol::OP_UTIMENS_AT
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
                open_request::dispatch(header.request_id, &prepared, paths, admission, filesystem)
            }
            protocol::OP_CANONICAL_PATH_AT
            | protocol::OP_STAT_AT
            | protocol::OP_GETCWD
            | protocol::OP_ACCESS_AT
            | protocol::OP_READLINK_AT => {
                path_query::dispatch(self, peer, header, payload, handles, filesystem)
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
            protocol::OP_CHDIR_AT | protocol::OP_CHROOT_AT | protocol::OP_FCHDIR => {
                directory_request::dispatch(self, peer, header, payload, handles, filesystem)
            }
            protocol::OP_FTRUNCATE
            | protocol::OP_FUTIMENS
            | protocol::OP_FCHMOD
            | protocol::OP_FCHOWN
            | protocol::OP_FSYNC
            | protocol::OP_FGETFL
            | protocol::OP_FSETFL
            | protocol::OP_FUPDATEFL => {
                file_request::dispatch(self, peer, header, payload, handles, admission, filesystem)
            }
            protocol::OP_MKDIR_AT
            | protocol::OP_UNLINK_AT
            | protocol::OP_TRUNCATE_AT
            | protocol::OP_SYMLINK_AT
            | protocol::OP_UTIMENS_AT
            | protocol::OP_CHMOD_AT
            | protocol::OP_CHOWN_AT => {
                path_mutation::dispatch(self, peer, header, payload, handles, admission, filesystem)
            }
            protocol::OP_RENAME_AT | protocol::OP_LINK_AT => {
                path_pair::dispatch(self, peer, header, payload, handles, filesystem)
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
            || request.options & protocol::OPEN_EXECUTE != 0
                && (access != protocol::OPEN_READ
                    || request.options
                        & (protocol::OPEN_CREATE
                            | protocol::OPEN_EXCLUSIVE
                            | protocol::OPEN_TRUNCATE
                            | protocol::OPEN_APPEND
                            | protocol::OPEN_DIRECTORY
                            | protocol::OPEN_CURSOR_RECORDS)
                        != 0)
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
            growth_ceiling: self.resource_limits
                .get(&(peer.process_id, protocol::RLIMIT_FSIZE))
                .copied().unwrap_or_default().soft,
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

    pub fn prepare_utimens_at(
        &self,
        peer: PeerIdentity,
        payload: &[u8],
        attached_handles: usize,
    ) -> Result<PreparedFileTimes, i32> {
        let session = self
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let request = protocol::file_time::decode_at(payload).map_err(|_| STATUS_EINVAL)?;
        if attached_handles != usize::from(request.target.base == protocol::OpenBase::AttachedDirectory) {
            return Err(STATUS_EINVAL);
        }
        Ok(PreparedFileTimes {
            target: PreparedStat {
                base: request.target.base,
                flags: request.target.flags,
                path: request.target.path.to_owned(),
                effective_uid: session.effective_uid,
                effective_gid: session.effective_gid,
                supplementary_groups: self
                    .supplementary_groups
                    .get(&peer.process_id)
                    .cloned()
                    .unwrap_or_default(),
            },
            times: request.times,
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
        if requested == protocol::CREDENTIAL_ID_UNCHANGED {
            return Err(STATUS_EINVAL);
        }
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
        if requested == protocol::CREDENTIAL_ID_UNCHANGED {
            return Err(STATUS_EINVAL);
        }
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
        if requested == protocol::CREDENTIAL_ID_UNCHANGED {
            return Err(STATUS_EINVAL);
        }
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
        if requested == protocol::CREDENTIAL_ID_UNCHANGED {
            return Err(STATUS_EINVAL);
        }
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

fn object_mutation_error<H: Copy>(
    request_id: u64,
    error: MutationError<H>,
    queued: bool,
    filesystem: &mut impl FilesystemBackend<H>,
) -> ObjectResponse<H> {
    match error {
        MutationError::Failed(status) => object_error(
            request_id,
            if queued && status == protocol::STATUS_MEMORY_ADMISSION_BUSY {
                protocol::STATUS_EIO
            } else {
                status
            },
        ),
        MutationError::Wait(ticket) if ticket.rights == mutation_admission::TICKET_RIGHTS => {
            ObjectResponse {
                response: status_response(request_id, protocol::STATUS_MEMORY_ADMISSION_BUSY),
                handles: vec![ticket],
            }
        }
        MutationError::Wait(ticket) => {
            filesystem.release_object(AttachedObject {
                handle: ticket.handle,
                rights: ticket.rights,
            });
            object_error(request_id, protocol::STATUS_EIO)
        }
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
