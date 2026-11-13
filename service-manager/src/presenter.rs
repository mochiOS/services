//! Prepare measured presenters on private thread mailboxes. Only completed,
//! authenticated preparations are handed back to the resident dispatcher.
use crate::{native_process::NativeProcess, process_watch::ProcessWatch};
use mochi_user_platform as p;
use std::sync::mpsc::{self, Receiver, TryRecvError};

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Permission,
    Execution,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Permission => "permission",
            Self::Execution => "execution",
        }
    }
}

#[derive(Debug)]
pub(crate) enum PrepareError {
    Native(p::syscall::SysError),
    Readiness(crate::readiness::ReadyError),
    Watch(crate::process_watch::ProcessWatchError),
    Unavailable,
}

impl From<p::syscall::SysError> for PrepareError {
    fn from(error: p::syscall::SysError) -> Self {
        Self::Native(error)
    }
}

pub(crate) struct Prepared {
    process: Option<NativeProcess>,
    watch: Option<ProcessWatch>,
    endpoint: Option<u32>,
    token: u64,
    posix: u32,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(process) = self.process.take() {
            process.terminate();
            crate::launch_rollback::retain_failed_launch(process, self.posix);
        }
        if let Some(endpoint) = self.endpoint {
            let _ = p::handle::close(endpoint);
        }
    }
}

impl Prepared {
    fn prepare(kind: Kind, logger: u64) -> Result<Self, PrepareError> {
        statusln!(
            "service-manager.service: preparing {} presenter",
            kind.name()
        );
        let token = p::service_ready::generate_token()?;
        // ipc::create is bound to this worker thread, never the resident
        // dispatcher's mailbox. Ordinary service requests stay with that loop.
        let target = p::service_ready::Target {
            endpoint: p::ipc::create()?,
            token,
        };
        let posix = p::handle::inherited(mochios_posix_protocol::CONTROL_HANDLE_KEY)?;
        let process = match kind {
            Kind::Permission => {
                crate::service_launcher::spawn_permission_prompt_server(logger, token, target)?
            }
            Kind::Execution => {
                crate::service_launcher::spawn_execution_prompt_server(logger, target)?
            }
        };
        let mut prepared = Self {
            process: Some(process),
            watch: None,
            endpoint: None,
            token,
            posix,
        };
        statusln!(
            "service-manager.service: {} presenter process created",
            kind.name()
        );
        let process = prepared.process.as_ref().unwrap();
        prepared.watch =
            Some(ProcessWatch::open(process.watch_target()).map_err(PrepareError::Watch)?);
        prepared.endpoint = Some(
            crate::readiness::wait_for_private_endpoint(token, process.watch_target())
                .map_err(PrepareError::Readiness)?,
        );
        statusln!("service-manager.service: {} presenter ready", kind.name());
        Ok(prepared)
    }

    pub(crate) fn endpoint(&self) -> u32 {
        self.endpoint.unwrap()
    }

    pub(crate) fn token(&self) -> u64 {
        self.token
    }
}

#[derive(Default)]
pub(crate) struct Slot {
    prepared: Option<Prepared>,
    pending: Option<Receiver<Result<Prepared, PrepareError>>>,
    next_check: u64,
    cleanup_blocked: bool,
}

impl Slot {
    pub(crate) fn maintain(&mut self, kind: Kind, logger: u64) {
        if let Some(pending) = self.pending.as_ref() {
            match pending.try_recv() {
                Ok(Ok(prepared)) => {
                    self.pending = None;
                    self.prepared = Some(prepared);
                    return;
                }
                Ok(Err(error)) => {
                    self.pending = None;
                    statusln!(
                        "service-manager.service: {} presenter preparation failed: {error:?}",
                        kind.name()
                    );
                    return;
                }
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.pending = None;
                    statusln!(
                        "service-manager.service: {} presenter preparation disconnected",
                        kind.name()
                    );
                    return;
                }
            }
        }
        let Ok(now) = p::time::monotonic_nanoseconds() else {
            return;
        };
        if now < self.next_check {
            return;
        }
        self.next_check = now.saturating_add(1_000_000_000);
        if let Some(prepared) = self.prepared.as_ref() {
            match prepared.watch.as_ref().unwrap().exit_status() {
                Ok(None) => return,
                Ok(Some(status)) => {
                    statusln!(
                        "service-manager.service: {} presenter exited status={status}",
                        kind.name()
                    );
                    self.prepared = None;
                    return;
                }
                Err(error) => {
                    statusln!(
                        "service-manager.service: {} presenter status failed: {error:?}",
                        kind.name()
                    );
                    return;
                }
            }
        }
        if crate::service_launcher::has_failed_launch_cleanup() {
            if !self.cleanup_blocked {
                statusln!(
                    "service-manager.service: {} presenter waiting for failed launch cleanup",
                    kind.name()
                );
                self.cleanup_blocked = true;
            }
            return;
        }
        self.cleanup_blocked = false;
        let (sender, receiver) = mpsc::channel();
        match std::thread::Builder::new()
            .name(format!("{}-ui", kind.name()))
            .spawn(move || {
                // A dropped receiver drops the result here, including all
                // retained process/endpoint owners and rollback obligations.
                let _ = sender.send(Prepared::prepare(kind, logger));
            }) {
            Ok(worker) => {
                drop(worker);
                self.pending = Some(receiver);
            }
            Err(error) => {
                statusln!(
                    "service-manager.service: {} presenter worker failed: {error}",
                    kind.name()
                );
            }
        }
    }

    pub(crate) fn is_preparing(&self) -> bool {
        self.pending.is_some()
    }

    /// Only an actual, already-authorized permission request waits for its
    /// presenter. Background maintenance never waits on this channel.
    pub(crate) fn take_ready(&mut self, kind: Kind, logger: u64) -> Result<Prepared, PrepareError> {
        if self.pending.is_none() {
            if self.prepared.is_none() {
                self.next_check = 0;
            }
            self.maintain(kind, logger);
        }
        if let Some(prepared) = self.prepared.take() {
            return Ok(prepared);
        }
        self.pending
            .take()
            .ok_or(PrepareError::Unavailable)?
            .recv()
            .map_err(|_| PrepareError::Unavailable)?
    }
}
