//! Development-only Unix transport. Trusted launcher pins executable inodes;
//! clients cannot declare their identity or administrator role in IPC payloads.
use crate::{Peer, Random, Service, storage::Disk};
use mochios_keychain_protocol::{Application, Error, MAX_FRAME, Result};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;
pub struct Entropy;
impl Random for Entropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        getrandom::getrandom(out).map_err(|_| Error::Unavailable)
    }
}
pub struct Registration {
    pub path: PathBuf,
    pub package: String,
    pub manager: bool,
}
struct Pin {
    device: u64,
    inode: u64,
    package: String,
    manager: bool,
}
pub struct Policy {
    uid: u32,
    signer: [u8; 32],
    pins: Vec<Pin>,
}
impl Policy {
    pub fn new(registrations: &[Registration], root: &Path) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let signer = Sha256::digest(root.as_os_str().as_encoded_bytes()).into();
        let mut pins = vec![];
        for r in registrations {
            let m = fs::metadata(&r.path).map_err(|_| Error::Invalid)?;
            if !m.is_file() {
                return Err(Error::Invalid);
            }
            let application = Application {
                package: r.package.clone(),
                signer,
                provenance: 3,
            };
            application.validate()?;
            if pins
                .iter()
                .any(|p: &Pin| p.device == m.dev() && p.inode == m.ino())
            {
                return Err(Error::Invalid);
            }
            pins.push(Pin {
                device: m.dev(),
                inode: m.ino(),
                package: r.package.clone(),
                manager: r.manager,
            });
        }
        Ok(Self {
            uid: unsafe { libc::geteuid() },
            signer,
            pins,
        })
    }
    fn peer(&self, stream: &UnixStream) -> Result<Peer> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        // SAFETY: getsockopt writes a fixed-size ucred to the supplied live buffer.
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } != 0
            || len as usize != std::mem::size_of_val(&cred)
            || cred.uid != self.uid
            || cred.pid <= 0
        {
            return Err(Error::Denied);
        }
        let m = fs::metadata(format!("/proc/{}/exe", cred.pid)).map_err(|_| Error::Denied)?;
        let pin = self
            .pins
            .iter()
            .find(|p| p.device == m.dev() && p.inode == m.ino())
            .ok_or(Error::Denied)?;
        Ok(Peer {
            uid: cred.uid,
            application: Application {
                package: pin.package.clone(),
                signer: self.signer,
                provenance: 3,
            },
            access: true,
            manager: pin.manager,
            session_control: false,
        })
    }
}
pub fn serve_one<S: crate::storage::Storage, R: Random>(
    mut stream: UnixStream,
    policy: &Policy,
    service: &mut Service<S, R>,
) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::Unavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::Unavailable)?;
    let peer = policy.peer(&stream)?;
    let mut prefix = [0; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| Error::Unavailable)?;
    let n = u32::from_le_bytes(prefix) as usize;
    if n > MAX_FRAME {
        return Err(Error::Limit);
    }
    let mut request = Zeroizing::new(vec![0; n]);
    stream
        .read_exact(&mut request)
        .map_err(|_| Error::Unavailable)?;
    let current = policy.peer(&stream)?;
    if current.uid != peer.uid || current.application != peer.application {
        return Err(Error::Denied);
    }
    let reply = service.dispatch(&current, &request);
    stream
        .write_all(&(reply.len() as u32).to_le_bytes())
        .and_then(|_| stream.write_all(&reply))
        .map_err(|_| Error::Unavailable)
}
pub fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut socket = None;
    let mut root = None;
    let mut registrations = vec![];
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next().map(PathBuf::from),
            "--data-root" => root = args.next().map(PathBuf::from),
            "--client" | "--manager" => {
                let path = args.next().ok_or(Error::Invalid)?.into();
                let package = args.next().ok_or(Error::Invalid)?;
                registrations.push(Registration {
                    path,
                    package,
                    manager: a == "--manager",
                });
            }
            _ => return Err(Error::Invalid),
        }
    }
    let socket = socket.ok_or(Error::Invalid)?;
    let root = root.ok_or(Error::Invalid)?;
    let parent = socket.parent().ok_or(Error::Invalid)?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|_| Error::Storage)?;
    if !parent_meta.is_dir()
        || parent_meta.file_type().is_symlink()
        || parent_meta.uid() != unsafe { libc::geteuid() }
        || parent_meta.mode() & 0o077 != 0
    {
        return Err(Error::Denied);
    }
    let policy = Policy::new(&registrations, &root)?;
    let disk = Disk::new(root)?;
    // Do not unlink an existing endpoint: a second daemon must never replace the first.
    let listener = UnixListener::bind(&socket).map_err(|_| Error::Unavailable)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(|_| Error::Storage)?;
    let mut service = Service::new(disk, Entropy);
    for stream in listener.incoming().flatten() {
        let _ = serve_one(stream, &policy, &mut service);
    }
    let _ = fs::remove_file(socket);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use appcore::keychain::{Keychain, Secret, Transport};
    struct SocketTransport(PathBuf);
    impl Transport for SocketTransport {
        fn exchange(&self, frame: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            let mut s = UnixStream::connect(&self.0).map_err(|_| Error::Unavailable)?;
            s.write_all(&(frame.len() as u32).to_le_bytes())
                .and_then(|_| s.write_all(frame))
                .map_err(|_| Error::Unavailable)?;
            let mut n = [0; 4];
            s.read_exact(&mut n).map_err(|_| Error::Unavailable)?;
            let mut out = Zeroizing::new(vec![0; u32::from_le_bytes(n) as usize]);
            s.read_exact(&mut out).map_err(|_| Error::Unavailable)?;
            Ok(out)
        }
    }
    #[test]
    fn appcore_round_trip_over_real_unix_peer_credentials() {
        let root = std::env::temp_dir().join(format!("keychain-uds-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let policy = Policy::new(
            &[Registration {
                path: std::env::current_exe().unwrap(),
                package: "org.mochios.test-keychain".into(),
                manager: true,
            }],
            &root,
        )
        .unwrap();
        let disk = Disk::new(root.join("data")).unwrap();
        let worker = std::thread::spawn(move || {
            let mut service = Service::new(disk, Entropy);
            for _ in 0..6 {
                serve_one(listener.accept().unwrap().0, &policy, &mut service).unwrap();
            }
        });
        let k = Keychain::with_transport(SocketTransport(socket));
        assert!(!k.status().unwrap().initialized);
        k.manager()
            .initialize(Secret::new(b"host-test-master-password".to_vec()))
            .unwrap();
        let id = k
            .put(
                "test",
                "test account",
                "test label",
                Secret::new(b"host-secret".to_vec()),
            )
            .unwrap();
        assert_eq!(k.get(id).unwrap().expose(), b"host-secret");
        k.manager().lock().unwrap();
        worker.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn peer_cannot_claim_an_unregistered_executable() {
        let policy = Policy::new(&[], Path::new("/tmp")).unwrap();
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(matches!(policy.peer(&a), Err(Error::Denied)));
    }
}
