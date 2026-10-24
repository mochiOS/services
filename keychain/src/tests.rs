use super::*;
use std::{cell::RefCell, rc::Rc};
#[derive(Clone, Default)]
struct Memory {
    files: Rc<RefCell<BTreeMap<u32, Vec<u8>>>>,
    fail: Rc<std::cell::Cell<bool>>,
}
impl Storage for Memory {
    fn load(&mut self, u: u32) -> Result<Option<Vec<u8>>> {
        Ok(self.files.borrow().get(&u).cloned())
    }
    fn commit(&mut self, u: u32, b: &[u8]) -> Result<()> {
        if self.fail.get() {
            return Err(Error::Storage);
        }
        self.files.borrow_mut().insert(u, b.to_vec());
        Ok(())
    }
}
struct Rng(u8);
impl Random for Rng {
    fn fill(&mut self, b: &mut [u8]) -> Result<()> {
        for x in b {
            self.0 = self.0.wrapping_add(1);
            *x = self.0;
        }
        Ok(())
    }
}
fn peer(package: &str, uid: u32, manager: bool) -> Peer {
    Peer {
        uid,
        application: Application {
            package: package.into(),
            signer: [1; 32],
            provenance: 1,
        },
        access: true,
        manager,
        session_control: false,
    }
}
fn pass() -> Secret {
    Secret::new(b"correct horse battery staple".to_vec())
}
fn put() -> Request {
    Request::Put {
        service: "google.oauth".into(),
        account: "person@example.test".into(),
        label: "Gmail".into(),
        secret: Secret::new(b"refresh-secret-never-on-disk".to_vec()),
    }
}
fn initialize(s: &mut Service<Memory, Rng>, p: &Peer) {
    assert!(
        s.execute(p, Request::Initialize { password: pass() })
            .is_ok()
    );
}
fn secret(s: &mut Service<Memory, Rng>, p: &Peer, id: wire::ItemId) -> Vec<u8> {
    match s.execute(p, Request::Get { id }).unwrap() {
        Reply::Secret(v) => v.expose().to_vec(),
        _ => panic!("bad reply"),
    }
}
#[test]
fn encrypted_storage_owner_user_signer_boundaries_and_grant_revocation() {
    let mem = Memory::default();
    let mut s = Service::new(mem.clone(), Rng(1));
    let admin = peer("org.mochios.keychain", 1000, true);
    let mail = peer("org.mochios.mail", 1000, false);
    let terra = peer("org.mochios.terra", 1000, false);
    initialize(&mut s, &admin);
    let Reply::Id(id) = s.execute(&mail, put()).unwrap() else {
        panic!()
    };
    assert_eq!(secret(&mut s, &mail, id), b"refresh-secret-never-on-disk");
    assert!(matches!(
        s.execute(&terra, Request::Get { id }),
        Err(Error::Missing)
    ));
    let mut signer = mail.clone();
    signer.application.signer = [9; 32];
    assert!(matches!(
        s.execute(&signer, Request::Get { id }),
        Err(Error::Missing)
    ));
    let mut other = mail.clone();
    other.uid = 1001;
    assert!(matches!(
        s.execute(&other, Request::Get { id }),
        Err(Error::Locked)
    ));
    let mut denied = admin.clone();
    denied.access = false;
    assert!(matches!(
        s.execute(&denied, Request::Status),
        Err(Error::Denied)
    ));
    assert!(matches!(
        s.execute(
            &mail,
            Request::Reveal {
                id,
                password: pass()
            }
        ),
        Err(Error::Denied)
    ));
    let disk = mem.files.borrow()[&1000].clone();
    for text in [
        b"refresh-secret-never-on-disk".as_slice(),
        b"person@example.test",
        b"Gmail",
        b"org.mochios.mail",
    ] {
        assert!(!disk.windows(text.len()).any(|w| w == text));
    }
    assert!(
        s.execute(
            &admin,
            Request::Grant {
                id,
                target: terra.application.clone(),
                revoke: false,
                password: pass()
            }
        )
        .is_ok()
    );
    assert_eq!(secret(&mut s, &terra, id), b"refresh-secret-never-on-disk");
    assert!(matches!(
        s.execute(&terra, Request::Delete { id }),
        Err(Error::Missing)
    ));
    s.execute(
        &admin,
        Request::Grant {
            id,
            target: terra.application.clone(),
            revoke: true,
            password: pass(),
        },
    )
    .unwrap();
    assert!(matches!(
        s.execute(&terra, Request::Get { id }),
        Err(Error::Missing)
    ));
}
#[test]
fn restart_wrong_password_tampering_and_rekey_keep_data() {
    let mem = Memory::default();
    let admin = peer("org.mochios.keychain", 1000, true);
    let mut s = Service::new(mem.clone(), Rng(2));
    initialize(&mut s, &admin);
    let Reply::Id(id) = s.execute(&admin, put()).unwrap() else {
        panic!()
    };
    drop(s);
    let mut s = Service::new(mem.clone(), Rng(8));
    assert!(matches!(
        s.execute(&admin, Request::Get { id }),
        Err(Error::Locked)
    ));
    assert!(matches!(
        s.execute(
            &admin,
            Request::Unlock {
                password: Secret::new(b"wrong-password".to_vec())
            }
        ),
        Err(Error::Authentication)
    ));
    s.execute(&admin, Request::Unlock { password: pass() })
        .unwrap();
    assert_eq!(secret(&mut s, &admin, id), b"refresh-secret-never-on-disk");
    s.execute(
        &admin,
        Request::ChangePassword {
            old: pass(),
            new: Secret::new(b"new very long password".to_vec()),
        },
    )
    .unwrap();
    s.execute(&admin, Request::Lock).unwrap();
    assert!(matches!(
        s.execute(&admin, Request::Unlock { password: pass() }),
        Err(Error::Authentication)
    ));
    s.execute(
        &admin,
        Request::Unlock {
            password: Secret::new(b"new very long password".to_vec()),
        },
    )
    .unwrap();
    let mut control = admin.clone();
    control.session_control = true;
    s.execute(&control, Request::LockAll).unwrap();
    assert!(matches!(
        s.execute(&admin, Request::Get { id }),
        Err(Error::Locked)
    ));
    let before = mem.files.borrow()[&1000].clone();
    mem.files.borrow_mut().get_mut(&1000).unwrap()[80] ^= 1;
    assert!(matches!(
        s.execute(
            &admin,
            Request::Unlock {
                password: Secret::new(b"new very long password".to_vec())
            }
        ),
        Err(Error::Authentication)
    ));
    assert_ne!(mem.files.borrow()[&1000], before);
}
#[test]
fn write_failure_locks_cache_and_never_claims_success() {
    let mem = Memory::default();
    let admin = peer("org.mochios.keychain", 1000, true);
    let mut s = Service::new(mem.clone(), Rng(3));
    initialize(&mut s, &admin);
    let before = mem.files.borrow()[&1000].clone();
    mem.fail.set(true);
    assert!(matches!(s.execute(&admin, put()), Err(Error::Storage)));
    assert_eq!(mem.files.borrow()[&1000], before);
    assert!(matches!(
        s.execute(
            &admin,
            Request::List {
                manager: true,
                offset: 0,
                generation: 0
            }
        ),
        Err(Error::Locked)
    ));
}
#[test]
fn malformed_frames_and_cross_user_file_swaps_fail_closed() {
    let a = peer("org.mochios.keychain", 1, true);
    let mem = Memory::default();
    let mut s = Service::new(mem.clone(), Rng(4));
    initialize(&mut s, &a);
    let blob = mem.files.borrow()[&1].clone();
    mem.files.borrow_mut().insert(2, blob);
    let b = peer("org.mochios.keychain", 2, true);
    assert!(matches!(
        s.execute(&b, Request::Unlock { password: pass() }),
        Err(Error::Corrupt)
    ));
    for n in 0..32 {
        let f = vec![7; n];
        assert!(wire::Reply::decode(&s.dispatch(&a, &f), 0).is_err());
    }
}
#[test]
fn entropy_failure_never_creates_a_vault() {
    struct NoRandom;
    impl Random for NoRandom {
        fn fill(&mut self, _: &mut [u8]) -> Result<()> {
            Err(Error::Unavailable)
        }
    }
    let mem = Memory::default();
    let mut s = Service::new(mem.clone(), NoRandom);
    let p = peer("org.mochios.keychain", 1000, true);
    assert!(matches!(
        s.execute(&p, Request::Initialize { password: pass() }),
        Err(Error::Unavailable)
    ));
    assert!(mem.files.borrow().is_empty());
}
#[cfg(target_os = "linux")]
#[test]
fn host_storage_refuses_a_second_writer_and_keeps_private_modes() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("keychain-storage-{}", std::process::id()));
    let mut one = crate::storage::Disk::new(root.clone()).unwrap();
    assert!(matches!(
        crate::storage::Disk::new(root.clone()),
        Err(Error::Busy)
    ));
    one.commit(1000, b"ciphertext-only-fixture").unwrap();
    assert_eq!(
        std::fs::metadata(root.join("1000.vault"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    drop(one);
    let mut reopened = crate::storage::Disk::new(root.clone()).unwrap();
    assert_eq!(
        reopened.load(1000).unwrap().unwrap(),
        b"ciphertext-only-fixture"
    );
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}
