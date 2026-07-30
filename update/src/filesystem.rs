use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use mochios_certificate_database::STATE_LEN;
use mochios_certificate_database::storage::{
    DATABASE_DIRECTORY, REVOCATIONS_A_PATH, REVOCATIONS_B_PATH, STATE_PATH, StorageBackend,
    StorageError, TRUST_A_PATH, TRUST_B_PATH,
};
use mochios_developer_ca_trust::MAX_SNAPSHOT_BYTES;

pub struct FileBackend {
    root: PathBuf,
}

impl FileBackend {
    pub fn system() -> Result<Self, StorageError> {
        Self::for_root(Path::new("/"))
    }

    pub fn for_root(root: &Path) -> Result<Self, StorageError> {
        let backend = Self {
            root: root.to_path_buf(),
        };
        std::fs::create_dir_all(backend.resolve_directory()).map_err(|_| StorageError::Backend)?;
        Ok(backend)
    }

    fn resolve(&self, path: &str) -> Result<PathBuf, StorageError> {
        if !matches!(
            path,
            STATE_PATH | TRUST_A_PATH | TRUST_B_PATH | REVOCATIONS_A_PATH | REVOCATIONS_B_PATH
        ) {
            return Err(StorageError::Backend);
        }
        let relative = path.strip_prefix('/').ok_or(StorageError::Backend)?;
        Ok(self.root.join(relative))
    }

    fn resolve_directory(&self) -> PathBuf {
        self.root.join(DATABASE_DIRECTORY.trim_start_matches('/'))
    }

    fn limit(path: &str) -> Result<usize, StorageError> {
        match path {
            STATE_PATH => Ok(STATE_LEN),
            TRUST_A_PATH | TRUST_B_PATH | REVOCATIONS_A_PATH | REVOCATIONS_B_PATH => {
                Ok(MAX_SNAPSHOT_BYTES)
            }
            _ => Err(StorageError::Backend),
        }
    }
}

impl StorageBackend for FileBackend {
    fn read(&mut self, path: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let limit = Self::limit(path)?;
        let resolved = self.resolve(path)?;
        let mut file = match File::open(resolved) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StorageError::Backend),
        };
        let read_limit = u64::try_from(limit)
            .map_err(|_| StorageError::Backend)?
            .saturating_add(1);
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|_| StorageError::Backend)?;
        if bytes.len() > limit {
            return Err(StorageError::InvalidSnapshot);
        }
        Ok(Some(bytes))
    }

    fn write_sync(&mut self, path: &str, bytes: &[u8]) -> Result<(), StorageError> {
        let limit = Self::limit(path)?;
        if bytes.len() > limit || (path == STATE_PATH && bytes.len() != STATE_LEN) {
            return Err(StorageError::InvalidSnapshot);
        }
        let resolved = self.resolve(path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(resolved)
            .map_err(|_| StorageError::Backend)?;
        file.write_all(bytes).map_err(|_| StorageError::Backend)?;
        file.sync_all().map_err(|_| StorageError::Backend)
    }
}
