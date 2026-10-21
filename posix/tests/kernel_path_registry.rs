//! Host checks for removing the unused global kernel path-policy registry.
//! The remaining legacy scoped-grant implementation is compiled unchanged;
//! only interrupt masking and its mutex are replaced by host synchronization.
extern crate self as spin;
extern crate self as x86_64;

pub struct Mutex<T>(std::sync::Mutex<T>);
impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.0.lock().unwrap()
    }
}

pub mod instructions {
    pub mod interrupts {
        pub fn without_interrupts<T>(operation: impl FnOnce() -> T) -> T {
            operation()
        }
    }
}

#[allow(dead_code)]
#[path = "../../../core/src/capability/path.rs"]
mod grants;

#[test]
fn kernel_no_longer_loads_or_resolves_global_filesystem_path_policy() {
    let source = include_str!("../../../core/src/capability/path.rs");
    for removed in [
        "PATH_REGISTRY",
        "PathOwner",
        "PathCapability",
        "fn lookup_path(",
        "fn register_path(",
        "fn register_service_paths(",
        "fn parse_configured_path(",
        "kernel_read_initfs",
        "Capability::FsReadAll",
    ] {
        assert!(!source.contains(removed), "kernel retains {removed}");
    }
    let init = include_str!("../../../core/src/init/mod.rs");
    assert!(!init.contains("path::init_from_kernel_config"));
}

#[test]
fn scoped_grants_are_exact_and_process_local() {
    use grants::*;
    let pid = 0xfeed_u64;
    revoke_scoped_paths(pid);
    grant_scoped_path(
        pid,
        "/home/alice/Documents/../note.txt",
        PathRights::new(PATH_READ),
    )
    .unwrap();
    assert!(scoped_path_allows(pid, "/home/alice/note.txt", PATH_READ));
    assert!(!scoped_path_allows(pid, "/home/alice/other.txt", PATH_READ));
    assert!(!scoped_path_allows(
        pid + 1,
        "/home/alice/note.txt",
        PATH_READ
    ));
    assert!(!scoped_path_allows(pid, "/home/alice/note.txt", PATH_WRITE));
    revoke_scoped_paths(pid);
    assert!(!scoped_path_allows(pid, "/home/alice/note.txt", PATH_READ));
}

#[test]
fn removing_registry_does_not_widen_existing_scoped_grants() {
    use grants::{PATH_READ, PATH_WRITE, PathRights};
    let pid = 0xf001;
    for path in ["", "relative", "/", "/one/.."] {
        assert!(grants::grant_scoped_path(pid, path, PathRights::new(PATH_READ)).is_err());
    }
    assert!(grants::grant_scoped_path(0, "/file", PathRights::new(PATH_READ)).is_err());
    assert!(grants::grant_scoped_path(pid, "/file", PathRights::new(0)).is_err());
    grants::grant_scoped_path(pid, "/scope/./file", PathRights::new(PATH_READ)).unwrap();
    assert!(grants::scoped_path_allows(pid, "/scope/file", PATH_READ));
    assert!(!grants::scoped_path_allows(
        pid,
        "/scope/file/child",
        PATH_READ
    ));
    assert!(!grants::scoped_path_allows(pid, "/scope/file", PATH_WRITE));
    assert!(!grants::scoped_path_allows(
        pid + 1,
        "/scope/file",
        PATH_READ
    ));
    grants::grant_scoped_path(pid, "/scope/file", PathRights::new(PATH_WRITE)).unwrap();
    assert!(grants::scoped_path_allows(
        pid,
        "/scope/file",
        PATH_READ | PATH_WRITE
    ));
    grants::revoke_scoped_paths(pid);
    assert!(!grants::scoped_path_allows(pid, "/scope/file", PATH_READ));
}
