use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use mochios_certificate_database::STATE_LEN;
use mochios_certificate_database::storage::{
    STATE_PATH, StorageBackend, StorageError, TRUST_A_PATH,
};
use mochios_developer_ca_trust::MAX_SNAPSHOT_BYTES;
use update::filesystem::FileBackend;

static TEST_ID: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "mochios-update-filesystem-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn creates_database_directory_and_round_trips_known_files() {
    let root = TestRoot::new();
    let mut backend = FileBackend::for_root(&root.0).unwrap();
    assert!(root.0.join("libraries/certificate").is_dir());
    assert_eq!(backend.read(TRUST_A_PATH), Ok(None));

    backend.write_sync(TRUST_A_PATH, b"snapshot").unwrap();

    assert_eq!(backend.read(TRUST_A_PATH), Ok(Some(b"snapshot".to_vec())));
}

#[test]
fn rejects_unknown_paths_and_invalid_state_lengths() {
    let root = TestRoot::new();
    let mut backend = FileBackend::for_root(&root.0).unwrap();

    assert_eq!(backend.read("/etc/passwd"), Err(StorageError::Backend));
    assert_eq!(
        backend.write_sync("/etc/passwd", b"x"),
        Err(StorageError::Backend)
    );
    assert_eq!(
        backend.write_sync(STATE_PATH, &[0; STATE_LEN - 1]),
        Err(StorageError::InvalidSnapshot)
    );
}

#[test]
fn rejects_oversized_snapshot_reads_and_writes() {
    let root = TestRoot::new();
    let mut backend = FileBackend::for_root(&root.0).unwrap();
    let oversized = vec![0; MAX_SNAPSHOT_BYTES + 1];
    assert_eq!(
        backend.write_sync(TRUST_A_PATH, &oversized),
        Err(StorageError::InvalidSnapshot)
    );

    fs::write(
        root.0.join("libraries/certificate/trust-a.json"),
        &oversized,
    )
    .unwrap();
    assert_eq!(
        backend.read(TRUST_A_PATH),
        Err(StorageError::InvalidSnapshot)
    );
}
