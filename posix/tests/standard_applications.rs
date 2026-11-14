//! Exercise the actual provisioning controller with measured-peer and durable
//! I/O adapters. No real native syscall or package mutation runs on the host.
extern crate alloc;
extern crate self as mochi_user_platform;
use mochios_package_protocol::{provisioning as wire, transaction};
use std::{cell::RefCell, collections::BTreeMap};

pub mod syscall {
    pub use mochi_user_syscall::SysError;
}

mod consent {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Instance {
        pub endpoint: u64,
        pub process: u64,
        pub thread: u64,
        pub revision: u64,
        pub digest: [u8; 32],
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Session {
        pub id: u64,
        pub generation: u64,
    }
    pub enum Action {
        Operation,
    }
    #[allow(dead_code)]
    pub struct Binding {
        pub requester: Instance,
        pub session: Session,
        pub policy_generation: u64,
        pub source_digest: [u8; 32],
        pub prepared_digest: [u8; 32],
        pub requirements_digest: [u8; 32],
        pub action: Action,
    }
}

mod consent_peer {
    pub struct ProcessReference(pub u32);
    pub struct Context {
        pub provenance: u8,
        pub subject_key_id: [u8; 32],
        pub package_id: Vec<u8>,
        pub package_id_len: u32,
        pub developer_id: Vec<u8>,
        pub developer_id_len: u32,
    }
    pub struct Peer {
        pub instance: super::consent::Instance,
        pub context: Context,
        pub process: ProcessReference,
    }
    pub fn capture(id: u64) -> Result<Peer, super::syscall::SysError> {
        Ok(super::peer(id))
    }
}

pub mod handle {
    pub fn same_object(a: u32, b: u32) -> Result<bool, super::syscall::SysError> {
        Ok(a == b)
    }
}

pub mod process {
    pub const PROCESS_STATE_EXITED: u32 = 2;
    pub struct Status {
        pub state: u32,
    }
    pub fn handle_status(id: u32) -> Result<Status, super::syscall::SysError> {
        Ok(Status {
            state: super::IO.with_borrow(|s| if s.dead == Some(id) { 2 } else { 1 }),
        })
    }
}

mod package_index {
    #[derive(Default)]
    pub struct PackageIndex {
        pub duplicate: bool,
        pub by_package: super::BTreeMap<String, ()>,
    }
}

#[path = "../../capability/src/standard_apps.rs"]
mod standard_apps;

#[derive(Default)]
struct Store {
    bytes: Option<Vec<u8>>,
    fail_write: bool,
    dead: Option<u32>,
}
thread_local! { static IO: RefCell<Store> = RefCell::new(Store::default()); }

mod standard_apps_io {
    use super::*;
    pub fn load() -> Result<standard_apps::model::Model, syscall::SysError> {
        IO.with_borrow(|s| match &s.bytes {
            None => Ok(Default::default()),
            Some(bytes) => standard_apps::model::Model::decode(bytes)
                .ok_or_else(|| syscall::SysError::from_raw(-22)),
        })
    }

    pub fn save(model: &standard_apps::model::Model) -> Result<(), syscall::SysError> {
        IO.with_borrow_mut(|s| {
            if s.fail_write {
                return Err(syscall::SysError::from_raw(-5));
            }
            s.bytes = Some(model.encode());
            Ok(())
        })
    }
}

fn peer(id: u64) -> consent_peer::Peer {
    let package_id = b"org.mochios.appstore".to_vec();
    let developer_id = b"org.mochios.system".to_vec();
    consent_peer::Peer {
        instance: consent::Instance {
            endpoint: id,
            process: id,
            thread: id,
            revision: 1,
            digest: [id as u8; 32],
        },
        process: consent_peer::ProcessReference(id as u32),
        context: consent_peer::Context {
            provenance: 1,
            subject_key_id: [0; 32],
            package_id_len: package_id.len() as u32,
            developer_id_len: developer_id.len() as u32,
            package_id,
            developer_id,
        },
    }
}

fn session() -> consent::Session {
    consent::Session {
        id: 1,
        generation: 1,
    }
}

fn reset() {
    IO.with_borrow_mut(|s| *s = Store::default());
}

fn plan(mutation: transaction::Mutation, id: &str, publisher: &str) -> Vec<u8> {
    let mut bytes = vec![0; transaction::MAX_PLAN_BYTES];
    let n = transaction::encode_plan(
        0,
        transaction::Plan {
            mutation,
            source_digest: [4; 32],
            previous_digest: if mutation == transaction::Mutation::Install {
                [0; 32]
            } else {
                [5; 32]
            },
            package_id: id,
            name: "Application",
            version: "1.0",
            developer: publisher,
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(n);
    bytes
}

fn phases(controller: &mut standard_apps::Controller) -> [wire::Phase; 5] {
    let mut bytes = [0; wire::MAX_SNAPSHOT];
    let n = controller.snapshot(&mut bytes).unwrap();
    wire::decode_snapshot(&bytes[..n]).unwrap().map(|r| r.phase)
}

#[test]
fn uid_zero_and_installed_or_forged_store_identities_have_no_setup_authority() {
    reset();
    for case in 0..5 {
        let mut peer = peer(10);
        match case {
            0 => peer.context.provenance = 2,
            1 => peer.context.subject_key_id = [1; 32],
            2 => peer.context.package_id[0] = b'x',
            3 => peer.context.developer_id[0] = b'x',
            4 => peer.context.package_id_len = u32::MAX,
            _ => unreachable!(),
        }
        assert!(
            standard_apps::Controller::default()
                .request(wire::Request::Claim, &peer, session(), (1000, 1), 1)
                .is_err()
        );
    }
    assert!(
        standard_apps::Controller::default()
            .request(wire::Request::Claim, &peer(10), session(), (0, 1), 1)
            .is_err()
    );
}

#[test]
fn leases_exclude_other_processes_and_revoked_or_expired_workers() {
    reset();
    let mut c = standard_apps::Controller::default();
    let owner = peer(10);
    c.request(wire::Request::Claim, &owner, session(), (1000, 1), 1)
        .unwrap();
    assert!(
        c.request(wire::Request::Claim, &peer(11), session(), (1000, 1), 2)
            .is_err()
    );
    let bytes = plan(
        transaction::Mutation::Install,
        wire::APPLICATIONS[0].0,
        wire::PUBLISHER,
    );
    assert!(
        c.authorize(&owner, session(), (1000, 1), 2, &bytes, 1)
            .is_ok()
    );
    assert!(
        c.authorize(&peer(11), session(), (1000, 1), 2, &bytes, 1)
            .is_err()
    );
    assert!(
        c.authorize(
            &owner,
            consent::Session {
                generation: 2,
                ..session()
            },
            (1000, 1),
            2,
            &bytes,
            1
        )
        .is_err()
    );
    assert!(
        c.authorize(&owner, session(), (1000, 2), 2, &bytes, 1)
            .is_err()
    );
    assert!(
        c.authorize(&owner, session(), (1000, 1), 180_000_000_001, &bytes, 1)
            .is_err()
    );
    IO.with_borrow_mut(|s| s.dead = Some(10));
    c.request(wire::Request::Claim, &peer(11), session(), (1000, 1), 3)
        .unwrap();
    assert!(
        c.before_commit(&owner, session(), (1000, 1), 4, &bytes, true)
            .is_err()
    );
}

#[test]
fn ordinary_removal_persists_satisfaction_before_deletion_and_across_users() {
    reset();
    let mut c = standard_apps::Controller::default();
    let id = wire::APPLICATIONS[0].0;
    let removal = plan(transaction::Mutation::Remove, id, wire::PUBLISHER);
    c.before_commit(&peer(10), session(), (1000, 1), 1, &removal, false)
        .unwrap();
    let mut restarted = standard_apps::Controller::default();
    restarted
        .reconcile(&package_index::PackageIndex::default())
        .unwrap();
    assert_eq!(phases(&mut restarted)[0], wire::Phase::Complete);
    restarted
        .request(wire::Request::Claim, &peer(20), session(), (1001, 1), 2)
        .unwrap();
    assert!(
        restarted
            .authorize(
                &peer(20),
                session(),
                (1001, 1),
                3,
                &plan(transaction::Mutation::Install, id, wire::PUBLISHER),
                1
            )
            .is_err()
    );
}

#[test]
fn durable_write_failure_or_corrupt_ledger_never_grants_a_fresh_setup() {
    reset();
    let mut c = standard_apps::Controller::default();
    c.request(wire::Request::Claim, &peer(10), session(), (1000, 1), 1)
        .unwrap();
    IO.with_borrow_mut(|s| s.fail_write = true);
    let mut index = package_index::PackageIndex::default();
    index.by_package.insert(wire::APPLICATIONS[0].0.into(), ());
    assert!(c.reconcile(&index).is_err());
    assert_eq!(phases(&mut c)[0], wire::Phase::Pending);
    let removal = plan(
        transaction::Mutation::Remove,
        wire::APPLICATIONS[0].0,
        wire::PUBLISHER,
    );
    assert!(
        c.before_commit(&peer(10), session(), (1000, 1), 1, &removal, false)
            .is_err()
    );
    IO.with_borrow_mut(|s| {
        s.fail_write = false;
        s.bytes = Some(vec![0; 40]);
    });
    assert!(
        standard_apps::Controller::default()
            .request(wire::Request::Claim, &peer(10), session(), (1000, 1), 1)
            .is_err()
    );
}

#[test]
fn installed_apps_are_skipped_and_progress_cannot_forge_success() {
    reset();
    let mut c = standard_apps::Controller::default();
    let mut index = package_index::PackageIndex::default();
    index.by_package.insert(wire::APPLICATIONS[1].0.into(), ());
    c.reconcile(&index).unwrap();
    c.request(wire::Request::Claim, &peer(10), session(), (1000, 1), 1)
        .unwrap();
    assert_eq!(phases(&mut c)[1], wire::Phase::Complete);
    assert!(
        c.request(
            wire::Request::Progress {
                index: 0,
                phase: wire::Phase::Complete,
                percent: 100,
                error: ""
            },
            &peer(10),
            session(),
            (1000, 1),
            2
        )
        .is_err()
    );
    let bytes = plan(
        transaction::Mutation::Install,
        wire::APPLICATIONS[1].0,
        wire::PUBLISHER,
    );
    assert!(
        c.authorize(&peer(10), session(), (1000, 1), 2, &bytes, 1)
            .is_err()
    );
}

#[test]
fn a_dead_worker_becomes_an_interrupted_retry_instead_of_staying_installing() {
    reset();
    let mut c = standard_apps::Controller::default();
    c.request(wire::Request::Claim, &peer(10), session(), (1000, 1), 1)
        .unwrap();
    c.request(
        wire::Request::Progress {
            index: 0,
            phase: wire::Phase::Installing,
            percent: 100,
            error: "",
        },
        &peer(10),
        session(),
        (1000, 1),
        2,
    )
    .unwrap();
    IO.with_borrow_mut(|s| s.dead = Some(10));
    c.request(wire::Request::Query, &peer(11), session(), (1001, 1), 3)
        .unwrap();
    assert_eq!(phases(&mut c)[0], wire::Phase::Failed);
    c.request(wire::Request::Claim, &peer(11), session(), (1001, 1), 4)
        .unwrap();
    assert!(
        c.authorize(
            &peer(11),
            session(),
            (1001, 1),
            5,
            &plan(
                transaction::Mutation::Install,
                wire::APPLICATIONS[0].0,
                wire::PUBLISHER
            ),
            1
        )
        .is_ok()
    );
}
