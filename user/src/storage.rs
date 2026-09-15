use std::fs::{self, OpenOptions};
use std::fmt;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mochios_user_database::UserDatabase;

#[derive(Debug)]
pub struct SaveError {
    operation: &'static str,
    source: io::Error,
}

impl SaveError {
    fn new(operation: &'static str, source: io::Error) -> Self {
        Self { operation, source }
    }

    pub fn operation(&self) -> &'static str {
        self.operation
    }

    pub fn errno(&self) -> u64 {
        self.source
            .raw_os_error()
            .unwrap_or(mochi_user_syscall::EIO as i32) as u64
    }
}

impl fmt::Display for SaveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.operation, self.source)
    }
}

impl std::error::Error for SaveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub fn load(path: &Path) -> io::Result<UserDatabase> {
    match fs::read(path) {
        Ok(bytes) => parse(&bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            for recovery in [temporary_path(path), backup_path(path)] {
                match fs::read(&recovery) {
                    Ok(bytes) => return parse(&bytes),
                    Err(candidate) if candidate.kind() == io::ErrorKind::NotFound => {}
                    Err(candidate) => return Err(candidate),
                }
            }
            Ok(UserDatabase::with_root())
        }
        Err(error) => Err(error),
    }
}

pub fn save(path: &Path, database: &UserDatabase) -> Result<(), SaveError> {
    let bytes = database
        .encode()
        .map_err(|error| SaveError::new("encode", io::Error::new(io::ErrorKind::InvalidData, error)))?;
    let parent = path.parent().ok_or_else(|| {
        SaveError::new(
            "validate-path",
            io::Error::new(io::ErrorKind::InvalidInput, "user database has no parent"),
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| SaveError::new("create-parent", error))?;

    let temporary = temporary_path(path);
    let backup = backup_path(path);
    remove_if_present(&temporary).map_err(|error| SaveError::new("remove-temporary", error))?;
    write_synced(&temporary, &bytes)?;
    remove_if_present(&backup).map_err(|error| SaveError::new("remove-backup", error))?;
    let had_database = match fs::rename(path, &backup) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            remove_if_present(&temporary)
                .map_err(|cleanup| SaveError::new("cleanup-temporary", cleanup))?;
            return Err(SaveError::new("backup-database", error));
        }
    };
    if let Err(error) = fs::rename(&temporary, path) {
        if had_database {
            let _ = fs::rename(&backup, path);
        }
        return Err(SaveError::new("install-database", error));
    }
    if had_database {
        remove_if_present(&backup).map_err(|error| SaveError::new("remove-backup", error))?;
    }
    Ok(())
}

fn parse(bytes: &[u8]) -> io::Result<UserDatabase> {
    UserDatabase::parse(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), SaveError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| SaveError::new("create-temporary", error))?;
    file.write_all(bytes)
        .map_err(|error| SaveError::new("write-temporary", error))?;
    file.sync_all()
        .map_err(|error| SaveError::new("sync-temporary", error))
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension("db.new")
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("db.backup")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mochios-user-service-{name}-{nonce}.db"))
    }

    #[test]
    fn save_and_load_round_trip() {
        let path = test_path("round-trip");
        let database = UserDatabase::with_root();
        save(&path, &database).unwrap();
        assert_eq!(load(&path).unwrap(), database);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_primary_recovers_backup() {
        let path = test_path("backup");
        let database = UserDatabase::with_root();
        write_synced(&backup_path(&path), &database.encode().unwrap()).unwrap();
        assert_eq!(load(&path).unwrap(), database);
        fs::remove_file(backup_path(&path)).unwrap();
    }
}
