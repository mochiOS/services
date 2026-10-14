use mochi_user_platform as platform;

use crate::diagnostic_drain::{Backend, Batch, Drain};
use crate::posix_io::AppendFile;

// Persistence policy belongs here, never in the kernel or its configuration.
const AUDIT_PATH: &str = "/var/log/audit.log";

struct NativeBackend {
    file: Option<AppendFile>,
}

impl NativeBackend {
    fn file(&mut self) -> platform::syscall::SysResult<&mut AppendFile> {
        if self.file.is_none() {
            crate::ensure_log_parent(AUDIT_PATH)?;
            self.file = Some(AppendFile::open(AUDIT_PATH, 0o640)?);
        }
        self.file
            .as_mut()
            .ok_or(platform::syscall::SysError::from_raw(
                platform::syscall::EIO as i64,
            ))
    }
}

impl Backend for NativeBackend {
    type Error = platform::syscall::SysError;

    fn read(&mut self, cursor: u64, bytes: &mut [u8]) -> Result<Batch, Self::Error> {
        let (bytes, metadata) = platform::diagnostic::read(cursor, bytes)?;
        Ok(Batch {
            bytes,
            next_cursor: metadata.next_cursor,
            dropped: metadata.dropped,
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.file()?.write(bytes)
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        self.file()?.sync()
    }
}

pub fn start() -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("diagnostic-persist".into())
        .spawn(|| {
            let mut backend = NativeBackend { file: None };
            let mut drain = Drain::new();
            let mut last_error = None;
            loop {
                match drain.step(&mut backend) {
                    Ok(_) => last_error = None,
                    Err(error) => {
                        let message =
                            format!("logger.service: diagnostic persistence failed: {error:?}\n");
                        if last_error.as_ref() != Some(&message) {
                            let _ = platform::io::write(platform::io::STDERR, message.as_bytes());
                            last_error = Some(message);
                        }
                    }
                }
                // Bounded work per tick also leaves ordinary service logging
                // responsive during recovery from a diagnostic burst.
                let _ = platform::thread::sleep_milliseconds(250);
            }
        })
        .map(|_| ())
}
