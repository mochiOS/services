use mochi_user_platform::syscall::{self, SysError};
use std::cell::Cell;

thread_local! {
    static INDEX_ERROR: Cell<Option<SysError>> = const { Cell::new(None) };
    static POLICY_ERROR: Cell<Option<SysError>> = const { Cell::new(None) };
    static DUPLICATE: Cell<bool> = const { Cell::new(false) };
}

// Substitute I/O results, exercising the production state commit boundary.
mod package_index {
    use super::*;
    pub(crate) struct PackageIndex {
        pub(crate) duplicate: bool,
        pub(crate) generation: u64,
    }
    pub(crate) fn build_package_index() -> Result<PackageIndex, SysError> {
        build_runtime_package_index()
    }
    pub(crate) fn build_runtime_package_index() -> Result<PackageIndex, SysError> {
        if let Some(error) = INDEX_ERROR.get() {
            return Err(error);
        }
        Ok(PackageIndex {
            duplicate: DUPLICATE.get(),
            generation: 2,
        })
    }
}

mod policy {
    use super::*;
    use package_index::PackageIndex;
    pub(crate) struct AppPromptPolicy {
        pub(crate) generation: u64,
    }
    pub(crate) fn load_app_prompt_policy(_: &PackageIndex) -> AppPromptPolicy {
        AppPromptPolicy { generation: 2 }
    }
    pub(crate) fn load_runtime_app_prompt_policy(
        index: &PackageIndex,
    ) -> Result<AppPromptPolicy, SysError> {
        if let Some(error) = POLICY_ERROR.get() {
            return Err(error);
        }
        Ok(AppPromptPolicy {
            generation: index.generation,
        })
    }
}

#[allow(dead_code)]
#[path = "../../capability/src/state.rs"]
mod state;

#[test]
fn initial_index_failure_and_duplicate_index_do_not_publish_service_state() {
    for (error, duplicate, expected) in [
        (Some(syscall::EIO), false, syscall::EIO),
        (Some(syscall::EACCES), false, syscall::EACCES),
        (
            None,
            true,
            mochios_posix_protocol::STATUS_EEXIST as i64 as u64,
        ),
    ] {
        INDEX_ERROR.set(error.map(|raw| SysError::from_raw(raw as i64)));
        DUPLICATE.set(duplicate);
        assert_eq!(
            state::CapabilityServiceState::new().err(),
            Some(SysError::from_raw(expected as i64))
        );
    }
    INDEX_ERROR.set(None);
    DUPLICATE.set(false);
    assert!(state::CapabilityServiceState::new().is_ok());
}

#[test]
fn publishes_the_new_index_and_policy_only_after_both_reads_succeed() {
    for (index_error, policy_error, duplicate, expected) in [
        (Some(syscall::EIO), None, false, Some(syscall::EIO)),
        (None, Some(syscall::EACCES), false, Some(syscall::EACCES)),
        (
            None,
            None,
            true,
            Some(mochios_posix_protocol::STATUS_EEXIST as i64 as u64),
        ),
        (None, None, false, None),
    ] {
        INDEX_ERROR.set(index_error.map(|raw| SysError::from_raw(raw as i64)));
        POLICY_ERROR.set(policy_error.map(|raw| SysError::from_raw(raw as i64)));
        DUPLICATE.set(duplicate);
        let mut state = state::CapabilityServiceState {
            package_index: package_index::PackageIndex {
                duplicate: false,
                generation: 1,
            },
            app_prompt_policy: policy::AppPromptPolicy { generation: 1 },
        };
        assert_eq!(
            state.refresh_package_index(),
            expected.map_or(Ok(()), |raw| Err(SysError::from_raw(raw as i64)))
        );
        let generation = if expected.is_none() { 2 } else { 1 };
        assert_eq!(state.package_index.generation, generation);
        assert_eq!(state.app_prompt_policy.generation, generation);
    }
}

#[test]
fn runtime_manifest_and_policy_readers_have_no_legacy_file_fallback() {
    let index = include_str!("../../capability/src/package_index.rs");
    let runtime = index
        .split("pub(crate) fn build_runtime_package_index()")
        .nth(1)
        .unwrap()
        .split("\nfn index_manifests")
        .next()
        .unwrap();
    assert!(
        runtime.contains(
            "crate::package_walk::manifest_paths(crate::persistent_grant::read_dir_names)?"
        )
    );
    assert!(runtime.contains("crate::persistent_grant::read_file(&path)?"));
    assert!(!runtime.contains("platform::file::"));
    let policy = include_str!("../../capability/src/policy.rs");
    let runtime = policy
        .split("pub(crate) fn load_runtime_app_prompt_policy(")
        .nth(1)
        .unwrap()
        .split("\nfn parse_app_prompt_policy")
        .next()
        .unwrap();
    assert!(runtime.contains("crate::persistent_grant::read_file(&record.manifest_path)?"));
    assert!(!runtime.contains("platform::file::"));
}
