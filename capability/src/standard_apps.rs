//! Broker-owned device provisioning. The Store orchestrates downloads; only this
//! gate can authorize a fixed publisher's first install, using normal one-shot
//! package objects. Interactive installation/update/removal keeps its own gate.
use crate::{
    consent::{Binding, Session},
    consent_peer::{self, Peer},
    package_index::PackageIndex,
};
use mochi_user_platform as p;
use mochios_package_protocol::{provisioning as wire, transaction};
use p::syscall::SysError;
use sha2::{Digest, Sha256};

#[cfg(not(test))]
#[path = "standard_apps/native.rs"]
mod io;
#[cfg(test)]
use crate::standard_apps_io as io;
#[path = "standard_apps/model.rs"]
pub(crate) mod model;

const LEASE_NS: u64 = 180_000_000_000;

fn denied() -> SysError {
    SysError::from_raw(-13)
}

/// Only an immutable, built-in mochiOS Store principal may drive setup. Names,
/// UID zero, installed third-party copies and caller-supplied flags confer none.
pub(crate) fn trusted(peer: &Peer) -> bool {
    let c = &peer.context;
    c.provenance == 1
        && c.subject_key_id == [0; 32]
        && c.package_id.get(..c.package_id_len as usize) == Some(b"org.mochios.appstore")
        && c.developer_id.get(..c.developer_id_len as usize) == Some(b"org.mochios.system")
}

struct Lease {
    owner: Peer,
    session: Session,
    account: (u32, u64),
    deadline: u64,
}

#[derive(Default)]
pub(crate) struct Controller {
    model: Option<model::Model>,
    lease: Option<Lease>,
}

impl Controller {
    fn load(&mut self) -> Result<(), SysError> {
        if self.model.is_none() {
            self.model = Some(io::load()?);
        }
        Ok(())
    }

    fn save(&mut self, model: model::Model) -> Result<(), SysError> {
        // Publish RAM state only after durable replacement succeeds.
        io::save(&model)?;
        self.model = Some(model);
        Ok(())
    }

    pub fn reconcile(&mut self, index: &PackageIndex) -> Result<(), SysError> {
        self.load()?;
        if index.duplicate {
            return Err(denied());
        }
        let mut model = self.model.as_ref().unwrap().clone();
        let mut changed = false;
        for (i, (id, _)) in wire::APPLICATIONS.iter().enumerate() {
            if index.by_package.contains_key(*id) {
                changed |= model.complete(i);
            }
        }
        if changed {
            self.save(model)?;
        }
        Ok(())
    }

    pub fn snapshot(&mut self, bytes: &mut [u8]) -> Result<usize, SysError> {
        self.load()?;
        wire::encode_snapshot(&self.model.as_ref().unwrap().snapshot(), bytes)
            .map_err(|_| SysError::from_raw(-22))
    }

    fn owns(
        &self,
        peer: &Peer,
        session: Session,
        account: (u32, u64),
        now: u64,
    ) -> Result<(), SysError> {
        let lease = self.lease.as_ref().ok_or_else(denied)?;
        if !trusted(peer)
            || lease.owner.instance != peer.instance
            || lease.session != session
            || lease.account != account
            || now >= lease.deadline
            || !p::handle::same_object(lease.owner.process.0, peer.process.0)?
        {
            return Err(denied());
        }
        Ok(())
    }

    pub fn request(
        &mut self,
        request: wire::Request<'_>,
        peer: &Peer,
        session: Session,
        account: (u32, u64),
        now: u64,
    ) -> Result<(), SysError> {
        if !trusted(peer) || account.0 < mochios_user_database::FIRST_REGULAR_UID || session.id == 0
        {
            return Err(denied());
        }
        self.load()?;
        match request {
            wire::Request::Query => {
                let stale = self.lease.as_ref().is_none_or(|lease| {
                    now >= lease.deadline
                        || !p::process::handle_status(lease.owner.process.0)
                            .is_ok_and(|s| s.state != p::process::PROCESS_STATE_EXITED)
                });
                if stale {
                    self.lease = None;
                    let mut model = self.model.as_ref().unwrap().clone();
                    if model.interrupt() {
                        self.save(model)?;
                    }
                }
            }
            wire::Request::Claim => {
                let already_owned = self.owns(peer, session, account, now).is_ok();
                if !already_owned
                    && self.lease.as_ref().is_some_and(|lease| {
                        now < lease.deadline
                            && p::process::handle_status(lease.owner.process.0)
                                .is_ok_and(|s| s.state != p::process::PROCESS_STATE_EXITED)
                    })
                {
                    return Err(SysError::from_raw(-11));
                }
                if !already_owned {
                    let mut model = self.model.as_ref().unwrap().clone();
                    if model.interrupt() {
                        self.save(model)?;
                    }
                    let owner = consent_peer::capture(peer.instance.endpoint)?;
                    if owner.instance != peer.instance
                        || !p::handle::same_object(owner.process.0, peer.process.0)?
                    {
                        return Err(denied());
                    }
                    self.lease = Some(Lease {
                        owner,
                        session,
                        account,
                        deadline: now.saturating_add(LEASE_NS),
                    });
                } else {
                    self.lease.as_mut().unwrap().deadline = now.saturating_add(LEASE_NS);
                }
            }
            wire::Request::Progress {
                index,
                phase,
                percent,
                error,
            } => {
                self.owns(peer, session, account, now)?;
                let mut model = self.model.as_ref().unwrap().clone();
                if !model.update(index, phase, percent, error) {
                    return Err(denied());
                }
                self.save(model)?;
                self.lease.as_mut().unwrap().deadline = now.saturating_add(LEASE_NS);
            }
            wire::Request::Release => {
                self.owns(peer, session, account, now)?;
                self.lease = None;
            }
            wire::Request::Authorize => return Err(denied()),
        }
        Ok(())
    }

    pub fn authorize(
        &mut self,
        peer: &Peer,
        session: Session,
        account: (u32, u64),
        now: u64,
        bytes: &[u8],
        generation: u64,
    ) -> Result<Binding, SysError> {
        self.owns(peer, session, account, now)?;
        let plan = transaction::decode_plan(bytes, 0).map_err(|_| denied())?;
        if self
            .model
            .as_ref()
            .ok_or_else(denied)?
            .eligible(&plan)
            .is_none()
        {
            return Err(denied());
        }
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        Ok(Binding {
            requester: peer.instance,
            session,
            policy_generation: generation,
            source_digest: plan.source_digest,
            prepared_digest: digest,
            requirements_digest: digest,
            action: crate::consent::Action::Operation,
        })
    }

    /// Recheck provisioning at commit. A normal, explicitly approved removal
    /// records setup as satisfied *before* deleting the package, so a crash or
    /// immediate next login cannot silently reinstall a deliberately removed app.
    pub fn before_commit(
        &mut self,
        peer: &Peer,
        session: Session,
        account: (u32, u64),
        now: u64,
        bytes: &[u8],
        provisioning: bool,
    ) -> Result<(), SysError> {
        let plan = transaction::decode_plan(bytes, 0).map_err(|_| denied())?;
        if provisioning {
            self.authorize(peer, session, account, now, bytes, 0)?;
        } else if plan.mutation == transaction::Mutation::Remove {
            if let Some(i) = wire::APPLICATIONS
                .iter()
                .position(|(id, _)| *id == plan.package_id)
            {
                self.load()?;
                let mut model = self.model.as_ref().unwrap().clone();
                if model.complete(i) {
                    self.save(model)?;
                }
            }
        }
        Ok(())
    }
}
