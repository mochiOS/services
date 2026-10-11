extern crate alloc;

use mochi_user_platform::syscall::{self, SysError};
use std::cell::Cell;

thread_local! {
    static IO_CALLS: Cell<usize> = const { Cell::new(0) };
}

mod persistent_grant {
    use super::*;
    pub(crate) fn read_dir_names(path: &str) -> Result<Vec<String>, SysError> {
        IO_CALLS.set(IO_CALLS.get() + 1);
        match path {
            "/system/packages" => Ok(vec!["test".into()]),
            "/system/packages/test" => Ok(vec!["manifest.toml".into()]),
            "/var/lib/packages" => Err(SysError::from_raw(syscall::ENOENT as i64)),
            _ => panic!("unexpected lookup {path}"),
        }
    }
    pub(crate) fn read_file(path: &str) -> Result<Vec<u8>, SysError> {
        IO_CALLS.set(IO_CALLS.get() + 1);
        assert_eq!(path, "/system/packages/test/manifest.toml");
        Ok(include_bytes!("../../capability/manifest.toml").to_vec())
    }
}

#[allow(dead_code)]
#[path = "../../capability/src/package_index.rs"]
mod package_index;
#[path = "../../capability/src/package_walk.rs"]
mod package_walk;

#[test]
fn lookup_uses_only_the_published_index_and_never_a_derived_fallback_path() {
    let index = package_index::build_runtime_package_index().unwrap();
    let calls = IO_CALLS.get();
    let (manifest, path) =
        package_index::package_manifest_by_id(&index, "org.mochios.capability").unwrap();
    assert_eq!(manifest.package_id, "org.mochios.capability");
    assert_eq!(path, "/system/packages/test/manifest.toml");
    for id in [
        "org.mochios.signature",
        "org.mochios.missing",
        "org.mochios.../escape",
    ] {
        assert_eq!(
            package_index::package_manifest_by_id(&index, id).err(),
            Some(SysError::from_raw(syscall::ENOENT as i64))
        );
    }
    assert_eq!(IO_CALLS.get(), calls);
}

#[test]
fn ambiguous_index_rejects_even_an_existing_package_id() {
    let mut index = package_index::build_runtime_package_index().unwrap();
    index.duplicate = true;
    let calls = IO_CALLS.get();
    assert_eq!(
        package_index::package_manifest_by_id(&index, "org.mochios.capability").err(),
        Some(SysError::from_raw(syscall::EEXIST as i64))
    );
    assert_eq!(IO_CALLS.get(), calls);
}

#[test]
fn bootstrap_traversal_and_reads_propagate_errors_instead_of_skipping_them() {
    let source = include_str!("../../capability/src/package_index.rs");
    assert!(!source.contains("walk_package_tree"));
    assert!(!source.contains("platform::package::read_manifest"));
    assert!(source.contains("manifest_paths(platform::file::read_dir_names)?"));
    assert!(source.contains("platform::file::read_to_end_path(&manifest_path)?"));
}
