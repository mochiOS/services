use crate::vault::MAX_FILE;
use mochios_keychain_protocol::{Error, Result};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
    #[cfg(target_os = "linux")]
    _writer_guard: std::fs::File,
}
impl Disk {
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root).map_err(|_| Error::Storage)?;
        let m = fs::symlink_metadata(&root).map_err(|_| Error::Storage)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(Error::Storage);
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::Storage)?;
        #[cfg(target_os = "linux")]
        let writer = {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(root.join(".writer"))
                .map_err(|_| Error::Storage)?;
            file.try_lock().map_err(|_| Error::Busy)?;
            file
        };
        Ok(Self {
            root,
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
        match fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(m)
                if m.is_file()
                    && !m.file_type().is_symlink()
                    && m.len() <= MAX_FILE as u64
                    && m.permissions().mode() & 0o077 == 0 => {}
            _ => return Err(Error::Storage),
        }
        let mut b = vec![];
        fs::File::open(p)
            .map_err(|_| Error::Storage)?
            .take((MAX_FILE + 1) as u64)
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
