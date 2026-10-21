//! Exercise the production account-home creator against the host filesystem.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn home_creation_claims_only_a_new_directory_before_initialization_or_rollback() {
    let source = include_str!("../../secure-ui/src/setup.rs");
    let mut program = probe::program();
    // Include the actual host I/O-to-wire boundary too. This probe does not
    // run target libc errno conversion (covered separately by setup_storage_status).
    let storage = include_str!("../../secure-ui/src/storage_status.rs");
    program.push_str(&format!(
        "mod storage_status {{use std::io; mod newlib_errno {{pub const EIO:i32={};}}\n",
        mochios_posix_client::newlib_errno::EIO,
    ));
    program.push_str(&storage[storage.find("pub(crate) fn io_status(").unwrap()..]);
    program.push_str("}\n");
    program.push_str(
        r#"
use std::{io, path::Path, cell::{Cell, RefCell}};
use std::os::unix::fs::{PermissionsExt, symlink};
struct UserRecord { home: String, uid: u32, gid: u32 }
#[derive(Debug, PartialEq)]
enum SetupError { Storage(i32) }
thread_local! {
    static CHOWN_CALLS: Cell<usize> = const { Cell::new(0) };
    static ROLLBACK_CALLS: Cell<usize> = const { Cell::new(0) };
    static COMPETING_HOME: RefCell<Option<std::path::PathBuf>> = const { RefCell::new(None) };
}
mod fs {
    pub use std::fs::*;
    // Schedule a competing creator between path inspection and creation while
    // retaining real host mkdir/error behavior at the production boundary.
    pub fn create_dir_all(path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        if let Some(home) = super::COMPETING_HOME.take() {
            std::fs::create_dir_all(home.join("Desktop"))?;
        }
        std::fs::create_dir_all(path)
    }
}
// Ownership changes are the only privileged operation replaced in this test.
fn chown(_: impl AsRef<Path>, _: Option<u32>, _: Option<u32>) -> io::Result<()> {
    CHOWN_CALLS.set(CHOWN_CALLS.get() + 1);
    Ok(())
}
fn remove_home(_: &UserRecord) { ROLLBACK_CALLS.set(ROLLBACK_CALLS.get() + 1); }
"#,
    );
    program.push_str(probe::between(
        source,
        "const HOME_DIRECTORIES:",
        "\npub(crate) struct AccountSetup",
    ));
    program.push_str(probe::between(
        source,
        "fn create_home(",
        "\nfn remove_home(",
    ));
    program.push_str(
        r#"
fn user(path: &Path) -> UserRecord {
    UserRecord { home: path.to_str().unwrap().into(), uid: 1000, gid: 1000 }
}
fn rejected_untouched(path: &Path) {
    CHOWN_CALLS.set(0);
    ROLLBACK_CALLS.set(0);
    assert_eq!(create_home(&user(path)), Err(SetupError::Storage(-17)));
    assert_eq!(CHOWN_CALLS.get(), 0);
    assert_eq!(ROLLBACK_CALLS.get(), 0);
}
fn main() {
    let root = std::env::temp_dir().join(format!("account-home-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let home = root.join("homes/new-account");
    create_home(&user(&home)).unwrap();
    assert_eq!(CHOWN_CALLS.get(), HOME_DIRECTORIES.len() + 1);
    assert_eq!(fs::metadata(&home).unwrap().permissions().mode() & 0o777, 0o700);
    for name in HOME_DIRECTORIES {
        assert_eq!(fs::metadata(home.join(name)).unwrap().permissions().mode() & 0o777, 0o700);
    }
    // A pre-existing empty home must not be adopted, even though create_dir_all
    // would have reported success. Nor may a later failure roll it back.
    let existing = root.join("existing");
    fs::create_dir(&existing).unwrap();
    fs::set_permissions(&existing, fs::Permissions::from_mode(0o751)).unwrap();
    rejected_untouched(&existing);
    assert_eq!(fs::read_dir(&existing).unwrap().count(), 0);
    assert_eq!(fs::metadata(&existing).unwrap().permissions().mode() & 0o777, 0o751);
    let file = root.join("file");
    fs::write(&file, b"keep").unwrap();
    rejected_untouched(&file);
    assert_eq!(fs::read(&file).unwrap(), b"keep");
    let link = root.join("link");
    symlink(&existing, &link).unwrap();
    rejected_untouched(&link);
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert_eq!(fs::read_dir(&existing).unwrap().count(), 0);
    let dangling = root.join("dangling");
    symlink(root.join("absent"), &dangling).unwrap();
    rejected_untouched(&dangling);
    assert!(!root.join("absent").exists());
    let competing = root.join("competing");
    COMPETING_HOME.set(Some(competing.clone()));
    rejected_untouched(&competing);
    assert!(competing.join("Desktop").is_dir());
    assert_eq!(fs::read_dir(&competing).unwrap().count(), 1);
    // Simultaneous setup attempts: only the winner may initialize the home.
    let raced = root.join("raced");
    let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
    let attempts: Vec<_> = (0..2).map(|_| {
        let gate = gate.clone();
        let raced = raced.clone();
        std::thread::spawn(move || {
            gate.wait();
            let result = create_home(&user(&raced));
            assert_eq!(ROLLBACK_CALLS.get(), 0);
            assert_eq!(CHOWN_CALLS.get(), if result.is_ok() { 7 } else { 0 });
            result
        })
    }).collect();
    let results: Vec<_> = attempts.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|r| **r == Err(SetupError::Storage(-17))).count(), 1);
    assert_eq!(fs::read_dir(&raced).unwrap().count(), HOME_DIRECTORIES.len());
    fs::remove_dir_all(root).unwrap();
}
"#,
    );
    probe::run(&program);
}
