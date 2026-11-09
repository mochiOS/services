//! Private, bounded report storage using retained directory Handles. No libc
//! session discovery is needed in this early-started service.
use crate::posix_io::with_client;
use mochi_user_platform as p;
use mochios_posix_client::{ObjectHandleAttachment as Attachment, OpenAtBase, StatAtBase};
use mochios_posix_protocol as wire;

pub const MAX_REPORT_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
type Result<T> = p::syscall::SysResult<T>;
fn invalid() -> p::syscall::SysError {
    p::syscall::SysError::from_raw(p::syscall::EIO as i64)
}

struct Owned(Attachment<u32>);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = p::handle::close(self.0.handle);
    }
}

pub struct Directory(Owned);
impl Directory {
    pub fn open(category: &str) -> Result<Self> {
        if !matches!(category, "crashes" | "images") {
            return Err(invalid());
        }
        let root = Owned(with_client(|c| {
            c.open_at(
                OpenAtBase::ProcessRoot,
                wire::OPEN_READ | wire::OPEN_DIRECTORY | wire::OPEN_NOFOLLOW,
                0,
                "/var/lib/diagnostics",
            )
        })?);
        Self::check_private(&root)?;
        match with_client(|c| c.mkdir_at(OpenAtBase::Directory(root.0), 0o700, category)) {
            Ok(()) => {}
            Err(error) if error.raw() == -17 => {}
            Err(error) => return Err(error),
        }
        let child = Owned(with_client(|c| {
            c.open_at(
                OpenAtBase::Directory(root.0),
                wire::OPEN_READ | wire::OPEN_DIRECTORY | wire::OPEN_NOFOLLOW,
                0,
                category,
            )
        })?);
        Self::check_private(&child)?;
        Ok(Self(child))
    }

    fn check_private(file: &Owned) -> Result<()> {
        let info = with_client(|c| c.fstat(file.0))?;
        if info.mode & 0xf000 != 0x4000 || info.uid != 0 || info.mode & 0o077 != 0 {
            return Err(invalid());
        }
        Ok(())
    }

    fn valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 160
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    }

    pub fn names(&self) -> Result<Vec<String>> {
        let iterator = Owned(with_client(|c| c.open_at(
            OpenAtBase::Directory(self.0.0),
            wire::OPEN_READ | wire::OPEN_DIRECTORY | wire::OPEN_NOFOLLOW, 0, ".",
        ))?);
        let mut names = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = p::handle::read(iterator.0.handle, &mut buffer)?;
            if count == 0 { break; }
            if count > buffer.len() { return Err(invalid()); }
            for entry in mochios_posix_client::directory::DirectoryEntries::new(&buffer[..count]) {
                let entry = entry.map_err(|_| invalid())?;
                if Self::valid_name(entry.name) && entry.name.ends_with(".json") {
                    if names.len() >= 4096 { return Err(invalid()); }
                    names.push(entry.name.to_owned());
                }
            }
        }
        Ok(names)
    }

    fn sync(&self) -> Result<()> {
        with_client(|c| c.fsync(self.0.0))
    }

    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        if !Self::valid_name(name) {
            return Err(invalid());
        }
        let file = Owned(with_client(|c| {
            c.open_at(
                OpenAtBase::Directory(self.0.0),
                wire::OPEN_READ | wire::OPEN_NOFOLLOW,
                0,
                name,
            )
        })?);
        let info = with_client(|c| c.fstat(file.0))?;
        if info.mode & 0xf000 != 0x8000
            || info.uid != 0
            || info.mode & 0o077 != 0
            || info.link_count != 1
            || !(0..=MAX_REPORT_BYTES as i64).contains(&info.size)
        {
            return Err(invalid());
        }
        let mut bytes = vec![0; info.size as usize];
        let mut offset = 0;
        while offset < bytes.len() {
            let count = p::handle::read_at(file.0.handle, &mut bytes[offset..], offset as u64)?;
            if count == 0 || count > bytes.len() - offset {
                return Err(invalid());
            }
            offset += count;
        }
        Ok(bytes)
    }

    pub fn store(&self, name: &str, bytes: &[u8], limit: usize) -> Result<()> {
        if !Self::valid_name(name) || !name.ends_with(".json") || bytes.len() > MAX_REPORT_BYTES {
            return Err(invalid());
        }
        // Replaying a retained native record after a sync failure is idempotent.
        match self.read(name) {
            Ok(existing) if existing == bytes => return self.sync(),
            Ok(_) => return Err(invalid()),
            Err(error) if error.raw() == p::syscall::ENOENT as i64 => {}
            Err(error) => return Err(error),
        }
        self.prune(
            limit.saturating_sub(1),
            MAX_TOTAL_BYTES.saturating_sub(bytes.len() as u64),
        )?;
        let pending = format!("{name}.pending");
        // The directory is retained, root-owned and private. A pending file is
        // never published or interpreted as a completed report.
        match with_client(|c| c.unlink_at(StatAtBase::Directory(self.0.0), 0, &pending)) {
            Ok(()) => {}
            Err(error) if error.raw() == p::syscall::ENOENT as i64 => {}
            Err(error) => return Err(error),
        }
        let file = Owned(with_client(|c| {
            c.open_at(
                OpenAtBase::Directory(self.0.0),
                wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE | wire::OPEN_NOFOLLOW,
                0o600,
                &pending,
            )
        })?);
        let written = (|| {
            let mut offset = 0;
            while offset < bytes.len() {
                let count = p::handle::write(file.0.handle, &bytes[offset..])?;
                if count == 0 || count > bytes.len() - offset {
                    return Err(invalid());
                }
                offset += count;
            }
            with_client(|c| c.fsync(file.0))?;
            with_client(|c| {
                c.rename_at(
                    StatAtBase::Directory(self.0.0),
                    &pending,
                    StatAtBase::Directory(self.0.0),
                    name,
                )
            })?;
            self.sync()
        })();
        if written.is_err() {
            let _ = with_client(|c| c.unlink_at(StatAtBase::Directory(self.0.0), 0, &pending));
        }
        written
    }

    fn prune(&self, limit: usize, byte_limit: u64) -> Result<()> {
        let iterator = Owned(with_client(|c| {
            c.open_at(
                OpenAtBase::Directory(self.0.0),
                wire::OPEN_READ | wire::OPEN_DIRECTORY | wire::OPEN_NOFOLLOW,
                0,
                ".",
            )
        })?);
        let mut entries = Vec::new();
        let mut abandoned = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = p::handle::read(iterator.0.handle, &mut buffer)?;
            if count == 0 {
                break;
            }
            if count > buffer.len() {
                return Err(invalid());
            }
            for entry in mochios_posix_client::directory::DirectoryEntries::new(&buffer[..count]) {
                let entry = entry.map_err(|_| invalid())?;
                if !Self::valid_name(entry.name) {
                    continue;
                }
                if entry.name.ends_with(".json.pending") {
                    if abandoned.len() >= 4096 {
                        return Err(invalid());
                    }
                    abandoned.push(entry.name.to_owned());
                    continue;
                }
                if !entry.name.ends_with(".json") {
                    continue;
                }
                if entries.len() >= 4096 {
                    return Err(invalid());
                }
                let status = with_client(|c| {
                    c.stat_at(
                        StatAtBase::Directory(self.0.0),
                        wire::STAT_NOFOLLOW,
                        entry.name,
                    )
                })?;
                if status.mode & 0xf000 != 0x8000 || status.uid != 0 || status.size < 0 {
                    return Err(invalid());
                }
                entries.push((
                    status.modification_time_seconds,
                    status.modification_time_nanoseconds,
                    entry.name.to_owned(),
                    status.size as u64,
                ));
            }
        }
        for name in abandoned {
            with_client(|c| c.unlink_at(StatAtBase::Directory(self.0.0), 0, name))?;
        }
        entries.sort();
        let mut bytes = entries
            .iter()
            .try_fold(0u64, |sum, entry| sum.checked_add(entry.3))
            .ok_or_else(invalid)?;
        let mut count = entries.len();
        for (_, _, name, size) in entries {
            if count <= limit && bytes <= byte_limit {
                break;
            }
            with_client(|c| c.unlink_at(StatAtBase::Directory(self.0.0), 0, name))?;
            count -= 1;
            bytes -= size;
        }
        Ok(())
    }
}
