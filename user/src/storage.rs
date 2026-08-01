use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mochios_user_database::UserDatabase;

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

pub fn save(path: &Path, database: &UserDatabase) -> io::Result<()> {
    let bytes = database
        .encode()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "user database has no parent")
    })?;
    fs::create_dir_all(parent)?;

    let temporary = temporary_path(path);
    let backup = backup_path(path);
    remove_if_present(&temporary)?;
    write_synced(&temporary, &bytes)?;
    remove_if_present(&backup)?;
    let had_database = match fs::rename(path, &backup) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            remove_if_present(&temporary)?;
            return Err(error);
        }
    };
    if let Err(error) = fs::rename(&temporary, path) {
        if had_database {
            let _ = fs::rename(&backup, path);
        }
        return Err(error);
    }
    if had_database {
        remove_if_present(&backup)?;
    }
    Ok(())
}

fn parse(bytes: &[u8]) -> io::Result<UserDatabase> {
    UserDatabase::parse(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
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
