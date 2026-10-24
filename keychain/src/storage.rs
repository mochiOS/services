use crate::vault::MAX_FILE;
use mochios_keychain_protocol::{Error, Result};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
pub trait Storage {
    fn load(&mut self, uid: u32) -> Result<Option<Vec<u8>>>;
    fn commit(&mut self, uid: u32, blob: &[u8]) -> Result<()>;
}
pub struct Disk {
    root: PathBuf,
    owner: u32,
    #[cfg(target_os = "linux")]
    _writer_guard: std::fs::File,
}
impl Disk {
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .map_err(|_| Error::Storage)?;
        let m = fs::symlink_metadata(&root).map_err(|_| Error::Storage)?;
        // SAFETY: geteuid has no pointer arguments or preconditions.
        let owner = unsafe { libc::geteuid() };
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != owner || m.mode() & 0o077 != 0 {
            return Err(Error::Storage);
        }
        #[cfg(target_os = "linux")]
        let writer = {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(root.join(".writer"))
                .map_err(|_| Error::Storage)?;
            validate_file(&file.metadata().map_err(|_| Error::Storage)?, owner)?;
            file.try_lock().map_err(|_| Error::Busy)?;
            file
        };
        Ok(Self {
            root,
            owner,
            #[cfg(target_os = "linux")]
            _writer_guard: writer,
        })
    }
    fn path(&self, uid: u32) -> PathBuf {
        self.root.join(format!("{uid}.vault"))
    }
}
impl Storage for Disk {
    fn load(&mut self, uid: u32) -> Result<Option<Vec<u8>>> {
        let p = self.path(uid);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&p)
        {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(file) => file,
            _ => return Err(Error::Storage),
        };
        // Validate the opened object, not a pathname checked before open().
        validate_file(&file.metadata().map_err(|_| Error::Storage)?, self.owner)?;
        let mut b = vec![];
        file.take((MAX_FILE + 1) as u64)
            .read_to_end(&mut b)
            .map_err(|_| Error::Storage)?;
        if b.len() > MAX_FILE {
            return Err(Error::Limit);
        }
        Ok(Some(b))
    }
    fn commit(&mut self, uid: u32, b: &[u8]) -> Result<()> {
        if b.len() > MAX_FILE {
            return Err(Error::Limit);
        }
        publish(&self.path(uid), b).map_err(|_| Error::Storage)
    }
}
fn validate_file(m: &fs::Metadata, owner: u32) -> Result<()> {
    if !m.is_file()
        || m.uid() != owner
        || m.nlink() != 1
        || m.len() > MAX_FILE as u64
        || m.permissions().mode() & 0o077 != 0
    {
        return Err(Error::Storage);
    }
    Ok(())
}
// Only ciphertext is written. The service locks its cached vault after ANY write error,
// including a post-rename directory-sync failure, so uncertain publication cannot leave stale state.
fn publish(p: &Path, b: &[u8]) -> std::io::Result<()> {
    let tmp = p.with_extension("pending");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(b)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, p)?;
        fs::File::open(p.parent().unwrap())?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
