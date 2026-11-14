//! Fixed policy and durable state, independent of IPC, storage and the desktop.
use alloc::{string::String, vec::Vec};
use mochios_package_protocol::{provisioning as wire, transaction};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub phase: wire::Phase,
    pub percent: u8,
    pub attempts: u32,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Model(pub [Row; 5]);

impl Default for Model {
    fn default() -> Self {
        Self(core::array::from_fn(|_| Row {
            phase: wire::Phase::Pending,
            percent: 0,
            attempts: 0,
            error: String::new(),
        }))
    }
}

impl Model {
    pub fn snapshot(&self) -> [wire::Progress<'_>; 5] {
        core::array::from_fn(|i| wire::Progress {
            phase: self.0[i].phase,
            percent: self.0[i].percent,
            attempts: self.0[i].attempts,
            error: &self.0[i].error,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = alloc::vec![0; wire::MAX_SNAPSHOT + 32];
        let n = wire::encode_snapshot(&self.snapshot(), &mut bytes).expect("validated progress");
        let digest = checksum(&bytes[..n]);
        bytes[n..n + 32].copy_from_slice(&digest);
        bytes.truncate(n + 32);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let n = bytes.len().checked_sub(32)?;
        if checksum(&bytes[..n]).as_slice() != &bytes[n..] {
            return None;
        }
        let rows = wire::decode_snapshot(&bytes[..n]).ok()?;
        Some(Self(rows.map(|r| Row {
            phase: r.phase,
            percent: r.percent,
            attempts: r.attempts,
            error: r.error.into(),
        })))
    }

    /// Existing installations satisfy setup permanently, including applications
    /// installed manually before the background worker reached them.
    pub fn complete(&mut self, index: usize) -> bool {
        let row = &mut self.0[index];
        if row.phase == wire::Phase::Complete {
            return false;
        }
        row.phase = wire::Phase::Complete;
        row.percent = 100;
        row.error.clear();
        true
    }

    pub fn update(&mut self, index: usize, phase: wire::Phase, percent: u8, error: &str) -> bool {
        let Some(row) = self.0.get_mut(index) else {
            return false;
        };
        if row.phase == wire::Phase::Complete
            || phase == wire::Phase::Complete
            || percent > 100
            || error.len() > wire::MAX_ERROR
            || error.chars().any(char::is_control)
        {
            return false;
        }
        if phase == wire::Phase::Downloading && row.phase != wire::Phase::Downloading {
            row.attempts = row.attempts.saturating_add(1);
        }
        row.phase = phase;
        row.percent = percent;
        row.error = error.into();
        true
    }

    pub fn interrupt(&mut self) -> bool {
        let mut changed = false;
        for row in &mut self.0 {
            if matches!(
                row.phase,
                wire::Phase::Downloading | wire::Phase::Installing
            ) {
                row.phase = wire::Phase::Failed;
                row.percent = 0;
                row.error =
                    "The previous attempt was interrupted. Installation will resume.".into();
                changed = true;
            }
        }
        changed
    }

    /// Publisher information comes from signature.service's prepared object,
    /// never from catalog JSON, an argument or the requester's description.
    pub fn eligible(&self, plan: &transaction::Plan<'_>) -> Option<usize> {
        let i = wire::APPLICATIONS
            .iter()
            .position(|(id, _)| *id == plan.package_id)?;
        (plan.mutation == transaction::Mutation::Install
            && plan.previous_digest == [0; 32]
            && plan.developer == wire::PUBLISHER
            && self.0[i].phase != wire::Phase::Complete)
            .then_some(i)
    }
}

// Bind positional records to the exact application order and publisher. A
// future policy change requires migration, never reinterpretation or reset.
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"mochiOS standard applications policy v1\0");
    for id in core::iter::once(wire::PUBLISHER).chain(wire::APPLICATIONS.iter().map(|(id, _)| *id))
    {
        hash.update((id.len() as u32).to_le_bytes());
        hash.update(id.as_bytes());
    }
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> transaction::Plan<'static> {
        transaction::Plan {
            mutation: transaction::Mutation::Install,
            source_digest: [1; 32],
            previous_digest: [0; 32],
            package_id: wire::APPLICATIONS[0].0,
            name: "Terra",
            version: "1",
            developer: wire::PUBLISHER,
        }
    }

    #[test]
    fn only_the_fixed_publisher_and_five_first_installs_are_eligible() {
        let mut model = Model::default();
        let mut p = plan();
        for (i, (id, _)) in wire::APPLICATIONS.iter().enumerate() {
            p.package_id = id;
            assert_eq!(model.eligible(&p), Some(i));
        }
        p.package_id = "org.attacker.terra";
        assert_eq!(model.eligible(&p), None);
        p = plan();
        p.developer = "another-publisher";
        assert_eq!(model.eligible(&p), None);
        p = plan();
        p.previous_digest = [2; 32];
        assert_eq!(model.eligible(&p), None);
        for mutation in [transaction::Mutation::Update, transaction::Mutation::Remove] {
            p = plan();
            p.mutation = mutation;
            assert_eq!(model.eligible(&p), None);
        }
        model.complete(0);
        assert_eq!(model.eligible(&plan()), None);
        assert!(!model.update(0, wire::Phase::Pending, 0, ""));
    }

    #[test]
    fn completed_applications_survive_restart_without_reinstallation() {
        let mut model = Model::default();
        model.complete(1);
        let restored = Model::decode(&model.encode()).unwrap();
        assert_eq!(restored, model);
        let mut p = plan();
        p.package_id = wire::APPLICATIONS[1].0;
        assert_eq!(restored.eligible(&p), None);
    }

    #[test]
    fn interrupted_work_retries_and_keeps_independent_completion_and_errors() {
        let mut model = Model::default();
        model.complete(1);
        model.update(0, wire::Phase::Downloading, 20, "");
        model.update(0, wire::Phase::Downloading, 50, "");
        assert_eq!(model.0[0].attempts, 1);
        let mut model = Model::decode(&model.encode()).unwrap();
        assert!(model.interrupt());
        assert_eq!(model.0[0].phase, wire::Phase::Failed);
        assert_eq!(model.0[1].phase, wire::Phase::Complete);
        model.update(0, wire::Phase::Downloading, 0, "");
        assert_eq!(model.0[0].attempts, 2);
        assert_eq!(model.0[2].attempts, 0);
        assert!(!model.update(0, wire::Phase::Complete, 100, ""));
    }

    #[test]
    fn partial_or_corrupted_ledgers_never_reset_to_fresh_installation() {
        let bytes = Model::default().encode();
        for n in 0..bytes.len() {
            assert!(Model::decode(&bytes[..n]).is_none());
        }
        for i in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[i] ^= 1;
            assert!(Model::decode(&damaged).is_none());
        }
    }
}
