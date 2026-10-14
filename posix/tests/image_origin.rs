//! Exercises the production origin predicate with native-authority test doubles.
//! This does not claim to exercise ProcessCreate or page-table installation.
#![allow(dead_code)]

mod capability {
    #[derive(Clone)]
    pub struct CapabilitySet(pub u64);
    impl CapabilitySet {
        pub fn is_subset_of(&self, other: &Self) -> bool {
            self.0 & !other.0 == 0
        }
    }
    pub type KernelAuthoritySet = CapabilitySet;
}

#[path = "../../../core/src/task/image_origin.rs"]
mod production;

mod task {
    use crate::capability::{CapabilitySet, KernelAuthoritySet};
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum PrivilegeLevel {
        User,
        Service,
        Core,
    }
    pub mod process {
        use super::*;
        #[derive(Clone, PartialEq, Eq)]
        pub struct ApplicationIdentity {
            pub package: String,
            pub developer: String,
            pub signer: [u8; 32],
            pub provenance: u8,
        }
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub enum PendingExecKind {
            Spawn,
            ImageReplace,
        }
        pub struct PendingExecSecurity {
            pub identity: ApplicationIdentity,
            pub executable_digest: [u8; 32],
            pub capabilities: CapabilitySet,
            pub kernel_authorities: KernelAuthoritySet,
            pub kind: PendingExecKind,
            pub execution_class: mnu_abi::exec::ExecutionClass,
        }
    }
    pub struct Process {
        pub identity: Option<process::ApplicationIdentity>,
        pub digest: Option<[u8; 32]>,
        pub capabilities: CapabilitySet,
        pub authorities: KernelAuthoritySet,
        pub privilege: PrivilegeLevel,
    }
    impl Process {
        pub fn application_identity(&self) -> Option<&process::ApplicationIdentity> {
            self.identity.as_ref()
        }
        pub fn image_digest(&self) -> Option<[u8; 32]> {
            self.digest
        }
        pub fn capabilities(&self) -> &CapabilitySet {
            &self.capabilities
        }
        pub fn kernel_authorities(&self) -> &KernelAuthoritySet {
            &self.authorities
        }
        pub fn privilege(&self) -> PrivilegeLevel {
            self.privilege
        }
    }
}

use capability::CapabilitySet;
use production::ImageOrigin;
use task::process;
use task::process::{ApplicationIdentity, PendingExecKind, PendingExecSecurity};
use task::{PrivilegeLevel, Process};

fn source() -> Process {
    Process {
        identity: Some(ApplicationIdentity {
            package: "example.app".into(),
            developer: "developer".into(),
            signer: [7; 32],
            provenance: 1,
        }),
        digest: Some([9; 32]),
        capabilities: CapabilitySet(0b1010),
        authorities: CapabilitySet(0b1100),
        privilege: PrivilegeLevel::User,
    }
}

fn authorization(process: &Process) -> PendingExecSecurity {
    PendingExecSecurity {
        identity: process.identity.clone().unwrap(),
        executable_digest: process.digest.unwrap(),
        capabilities: process.capabilities.clone(),
        kernel_authorities: process.authorities.clone(),
        kind: PendingExecKind::Spawn,
        execution_class: mnu_abi::exec::ExecutionClass::Unprivileged,
    }
}

#[test]
fn requires_both_identity_and_measurement() {
    let mut process = source();
    process.identity = None;
    assert!(ImageOrigin::capture(&process).is_none());
    let mut process = source();
    process.digest = None;
    assert!(ImageOrigin::capture(&process).is_none());
}

#[test]
fn authority_subset_matrix() {
    let process = source();
    let origin = ImageOrigin::capture(&process).unwrap();
    for capabilities in 0..16 {
        for authorities in 0..16 {
            let mut request = authorization(&process);
            request.capabilities = CapabilitySet(capabilities);
            request.kernel_authorities = CapabilitySet(authorities);
            assert_eq!(
                origin.permits(&request),
                capabilities & !0b1010 == 0 && authorities & !0b1100 == 0
            );
        }
    }
}

#[test]
fn rejects_every_identity_component_and_measurement_change() {
    let process = source();
    let origin = ImageOrigin::capture(&process).unwrap();
    for component in 0..5 {
        let mut request = authorization(&process);
        match component {
            0 => request.identity.package.push('x'),
            1 => request.identity.developer.push('x'),
            2 => request.identity.signer[0] ^= 1,
            3 => request.identity.provenance ^= 1,
            _ => request.executable_digest[0] ^= 1,
        }
        assert!(!origin.permits(&request));
    }
}

#[test]
fn rejects_replace_and_user_privilege_increase() {
    for privilege in [
        PrivilegeLevel::User,
        PrivilegeLevel::Service,
        PrivilegeLevel::Core,
    ] {
        let mut process = source();
        process.privilege = privilege;
        let origin = ImageOrigin::capture(&process).unwrap();
        let mut request = authorization(&process);
        assert!(origin.permits(&request));
        request.execution_class = mnu_abi::exec::ExecutionClass::Privileged;
        assert_eq!(origin.permits(&request), privilege != PrivilegeLevel::User);
        request.kind = PendingExecKind::ImageReplace;
        assert!(!origin.permits(&request));
    }
}

#[test]
fn capture_is_immutable_not_a_live_process_reference() {
    let mut process = source();
    let request = authorization(&process);
    let origin = ImageOrigin::capture(&process).unwrap();
    process.capabilities = CapabilitySet(0);
    process.authorities = CapabilitySet(0);
    process.identity = None;
    process.digest = None;
    assert!(origin.permits(&request));
}

#[test]
fn production_creation_replacement_and_vm_snapshot_preserve_measurement() {
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    assert!(exec.contains("proc.set_image_digest(Sha256::digest(data).into())"));
    assert!(exec.contains("process.set_image_digest(authorization.executable_digest)"));
    let snapshot = include_str!("../../../core/src/mem/address_space.rs");
    assert!(snapshot.contains("ImageOrigin::capture(process)"));
    assert!(snapshot.contains("origin: self.origin"));
    assert!(exec.contains("consume_address_space_for_create(&image, &authorization, &context)"));
    assert!(exec.contains("crate::task::with_process(pid, |_| image.consume(authorization, context))"));
}
