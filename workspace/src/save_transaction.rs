//! Retains one destination across repeated saves. The backend owns the pinned
//! directory; callers can supply content, but cannot substitute a destination.
pub trait Backend {
    type File;
    type Error;
    fn create(&mut self, name: &str, mode: u32) -> Result<Self::File, Self::Error>;
    fn sync_file(&mut self, file: &Self::File) -> Result<(), Self::Error>;
    fn rename(&mut self, from: &str, to: &str) -> Result<(), Self::Error>;
    /// Removing a missing stage succeeds, including after an uncertain rename.
    fn remove(&mut self, name: &str) -> Result<(), Self::Error>;
    fn sync_directory(&mut self) -> Result<(), Self::Error>;
}

pub struct Transaction<F> {
    destination: String,
    mode: u32,
    stage: Option<(String, F)>,
}
impl<F> Transaction<F> {
    pub fn new(destination: String, mode: u32) -> Self {
        Self {
            destination,
            mode,
            stage: None,
        }
    }
    pub fn begin<B: Backend<File = F>>(
        &mut self,
        backend: &mut B,
        name: String,
    ) -> Result<&F, B::Error> {
        self.abort(backend)?;
        let file = backend.create(&name, self.mode)?;
        self.stage = Some((name, file));
        Ok(&self.stage.as_ref().unwrap().1)
    }
    pub fn abort<B: Backend<File = F>>(&mut self, backend: &mut B) -> Result<(), B::Error> {
        if let Some((name, _)) = self.stage.as_ref() {
            backend.remove(name)?;
            self.stage.take();
        }
        Ok(())
    }
    pub fn commit<B: Backend<File = F>>(&mut self, backend: &mut B) -> Result<bool, B::Error> {
        let Some((name, file)) = self.stage.as_ref() else {
            return Ok(false);
        };
        backend.sync_file(file)?;
        backend.rename(name, &self.destination)?;
        self.stage.take();
        backend.sync_directory()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Write},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Disk {
        directory: PathBuf,
        fail: &'static str,
    }
    impl Disk {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "mochi-save-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("chosen.txt"), b"previous").unwrap();
            fs::write(directory.join("sibling.txt"), b"other").unwrap();
            Self {
                directory,
                fail: "",
            }
        }
        fn fault(&self, step: &str) -> io::Result<()> {
            if self.fail == step {
                Err(io::Error::other(step))
            } else {
                Ok(())
            }
        }
    }
    impl Drop for Disk {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }
    impl Backend for Disk {
        type File = File;
        type Error = io::Error;
        fn create(&mut self, name: &str, _: u32) -> io::Result<File> {
            self.fault("create")?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.directory.join(name))
        }
        fn sync_file(&mut self, file: &File) -> io::Result<()> {
            self.fault("file-sync")?;
            file.sync_all()
        }
        fn rename(&mut self, from: &str, to: &str) -> io::Result<()> {
            self.fault("rename")?;
            fs::rename(self.directory.join(from), self.directory.join(to))
        }
        fn remove(&mut self, name: &str) -> io::Result<()> {
            self.fault("unlink")?;
            match fs::remove_file(self.directory.join(name)) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                result => result,
            }
        }
        fn sync_directory(&mut self) -> io::Result<()> {
            self.fault("directory-sync")?;
            File::open(&self.directory)?.sync_all()
        }
    }
    #[test]
    fn interrupted_save_preserves_previous_contents_and_siblings() {
        for failure in ["create", "file-sync", "rename"] {
            let mut disk = Disk::new();
            let mut transaction = Transaction::new("chosen.txt".into(), 0o600);
            if failure == "create" {
                disk.fail = failure;
                assert!(transaction.begin(&mut disk, ".stage".into()).is_err());
            } else {
                let mut file = transaction.begin(&mut disk, ".stage".into()).unwrap();
                file.write_all(b"replacement").unwrap();
                disk.fail = failure;
                assert!(transaction.commit(&mut disk).is_err());
            }
            disk.fail = "";
            transaction.abort(&mut disk).unwrap();
            assert_eq!(
                fs::read(disk.directory.join("chosen.txt")).unwrap(),
                b"previous"
            );
            assert_eq!(
                fs::read(disk.directory.join("sibling.txt")).unwrap(),
                b"other"
            );
            assert!(!disk.directory.join(".stage").exists());
        }
    }
    #[test]
    fn repeated_saves_keep_the_selected_destination_and_report_uncertain_durability() {
        let mut disk = Disk::new();
        let mut transaction = Transaction::new("chosen.txt".into(), 0o600);
        transaction.begin(&mut disk, ".abandoned".into()).unwrap();
        let mut file = transaction.begin(&mut disk, ".next".into()).unwrap();
        file.write_all(b"first").unwrap();
        assert!(!disk.directory.join(".abandoned").exists());
        assert_eq!(transaction.commit(&mut disk).unwrap(), true);
        assert_eq!(transaction.commit(&mut disk).unwrap(), false);
        let mut file = transaction.begin(&mut disk, ".again".into()).unwrap();
        file.write_all(b"second").unwrap();
        disk.fail = "directory-sync";
        assert!(transaction.commit(&mut disk).is_err());
        disk.fail = "";
        transaction.abort(&mut disk).unwrap();
        assert_eq!(
            fs::read(disk.directory.join("chosen.txt")).unwrap(),
            b"second"
        );
        assert_eq!(
            fs::read(disk.directory.join("sibling.txt")).unwrap(),
            b"other"
        );
        assert!(!disk.directory.join(".again").exists());
    }
}
