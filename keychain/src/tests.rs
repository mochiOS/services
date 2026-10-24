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
        s.execute(
            p,
            Request::Initialize {
                epoch: s.session_epoch,
                password: pass()
            }
        )
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
                epoch: s.session_epoch,
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
                epoch: s.session_epoch,
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
            epoch: s.session_epoch,
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
                epoch: s.session_epoch,
                password: Secret::new(b"wrong-password".to_vec())
            }
        ),
        Err(Error::Authentication)
    ));
    s.execute(
        &admin,
        Request::Unlock {
            epoch: s.session_epoch,
            password: pass(),
        },
    )
    .unwrap();
    assert_eq!(secret(&mut s, &admin, id), b"refresh-secret-never-on-disk");
    s.execute(
        &admin,
        Request::ChangePassword {
            epoch: s.session_epoch,
            old: pass(),
            new: Secret::new(b"new very long password".to_vec()),
        },
    )
    .unwrap();
    s.execute(&admin, Request::Lock).unwrap();
    assert!(matches!(
        s.execute(
            &admin,
            Request::Unlock {
                epoch: s.session_epoch,
                password: pass()
            }
        ),
        Err(Error::Authentication)
    ));
    s.execute(
        &admin,
        Request::Unlock {
            epoch: s.session_epoch,
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
                epoch: s.session_epoch,
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
        s.execute(
            &b,
            Request::Unlock {
                epoch: s.session_epoch,
                password: pass()
            }
        ),
        Err(Error::Corrupt)
    ));
    for n in 0..32 {
        let f = vec![7; n];
        assert!(wire::Reply::decode(&s.dispatch(&a, &f), 0).is_err());
    }
}

#[test]
fn largest_records_and_catalogue_fit_native_ipc_and_page_through_appcore() {
    let admin = peer("org.mochios.keychain", 1000, true);
    let mut service = Service::new(Memory::default(), Rng(11));
    initialize(&mut service, &admin);
    let mut data = Data::empty();
    for n in 1..=4u8 {
        data.entries.push(Entry {
            meta: Item {
                id: [n; 16],
                owner: Application {
                    package: "o".repeat(128),
                    signer: [1; 32],
                    provenance: 1,
                },
                service: format!("{}{}", "s".repeat(127), n),
                account: "a".repeat(256),
                label: "l".repeat(128),
                grants: (0..MAX_GRANTS)
                    .map(|i| Application {
                        package: format!("{}{:02}{:02}", "g".repeat(124), n, i),
                        signer: [2; 32],
                        provenance: 2,
                    })
                    .collect(),
            },
            secret: Secret::new(vec![7; wire::MAX_SECRET]),
        });
    }
    service.save(1000, data).unwrap();
    struct Inline {
        service: RefCell<Service<Memory, Rng>>,
        peer: Peer,
    }
    impl appcore::keychain::Transport for Inline {
        fn exchange(&self, frame: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            assert!(frame.len() <= 8192);
            let reply = self.service.borrow_mut().dispatch(&self.peer, frame);
            assert!(reply.len() <= 8192);
            Ok(reply)
        }
    }
    let client = appcore::keychain::Keychain::with_transport(Inline {
        service: RefCell::new(service),
        peer: admin,
    });
    assert_eq!(client.manager().items().unwrap().len(), 4);
    assert_eq!(client.manager().applications().unwrap().len(), 66);
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
        s.execute(
            &p,
            Request::Initialize {
                epoch: s.session_epoch,
                password: pass()
            }
        ),
        Err(Error::Unavailable)
    ));
    assert!(mem.files.borrow().is_empty());
}

#[test]
fn native_session_gate_rejects_unlocks_queued_before_lock_or_for_another_user() {
    let mut s = Service::session_controlled(Memory::default(), Rng(31)).unwrap();
    let admin = peer("org.mochios.keychain", 1000, true);
    let mut controller = peer("org.mochios.service-manager", 0, false);
    controller.session_control = true;
    controller.access = false;
    assert!(matches!(
        s.execute(&admin, Request::ActivateSession { uid: 1000 }),
        Err(Error::Denied)
    ));
    assert!(matches!(
        s.execute(
            &admin,
            Request::Initialize {
                epoch: 1,
                password: pass()
            }
        ),
        Err(Error::Locked)
    ));
    s.execute(&controller, Request::ActivateSession { uid: 1000 })
        .unwrap();
    let previous_epoch = s.session_epoch;
    initialize(&mut s, &admin);
    s.execute(&controller, Request::LockAll).unwrap();
    assert!(matches!(
        s.execute(
            &admin,
            Request::Unlock {
                epoch: previous_epoch,
                password: pass()
            }
        ),
        Err(Error::Locked)
    ));
    s.execute(&controller, Request::ActivateSession { uid: 1001 })
        .unwrap();
    assert!(matches!(
        s.execute(
            &admin,
            Request::Unlock {
                epoch: s.session_epoch,
                password: pass()
            }
        ),
        Err(Error::Locked)
    ));
    s.execute(&controller, Request::ActivateSession { uid: 1000 })
        .unwrap();
    assert!(matches!(
        s.execute(
            &admin,
            Request::Unlock {
                epoch: previous_epoch,
                password: pass()
            }
        ),
        Err(Error::Conflict)
    ));
    assert!(!s.unlocked.contains_key(&1000));
    s.execute(
        &admin,
        Request::Unlock {
            epoch: s.session_epoch,
            password: pass(),
        },
    )
    .unwrap();
    assert!(s.unlocked.contains_key(&1000));
    for request in [
        Request::Reveal {
            epoch: previous_epoch,
            id: [1; 16],
            password: pass(),
        },
        Request::ManageDelete {
            epoch: previous_epoch,
            id: [1; 16],
            password: pass(),
        },
        Request::Grant {
            epoch: previous_epoch,
            id: [1; 16],
            target: admin.application.clone(),
            revoke: false,
            password: pass(),
        },
        Request::ChangePassword {
            epoch: previous_epoch,
            old: pass(),
            new: pass(),
        },
    ] {
        assert!(matches!(s.execute(&admin, request), Err(Error::Conflict)));
    }
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

#[cfg(target_os = "linux")]
#[test]
fn storage_rejects_lock_symlinks_and_multiply_linked_vaults() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = std::env::temp_dir().join(format!("keychain-links-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = root.join("other-file");
    std::fs::write(&target, b"must not be used as a vault lock").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, root.join(".writer")).unwrap();
    assert!(matches!(
        crate::storage::Disk::new(root.clone()),
        Err(Error::Storage)
    ));
    std::fs::remove_file(root.join(".writer")).unwrap();
    let mut disk = crate::storage::Disk::new(root.clone()).unwrap();
    std::fs::hard_link(&target, root.join("1000.vault")).unwrap();
    assert!(matches!(disk.load(1000), Err(Error::Storage)));
    drop(disk);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn replacing_disk_vault_cannot_reauthenticate_a_different_unlocked_vault() {
    let mem = Memory::default();
    let admin = peer("org.mochios.keychain", 1000, true);
    let mut s = Service::new(mem.clone(), Rng(21));
    initialize(&mut s, &admin);
    let old_file = mem.files.borrow()[&1000].clone();
    let Reply::Id(id) = s.execute(&admin, put()).unwrap() else {
        panic!()
    };
    s.execute(
        &admin,
        Request::ChangePassword {
            epoch: s.session_epoch,
            old: pass(),
            new: Secret::new(b"replacement vault password".to_vec()),
        },
    )
    .unwrap();
    mem.files.borrow_mut().insert(1000, old_file);
    assert!(matches!(
        s.execute(
            &admin,
            Request::Reveal {
                epoch: s.session_epoch,
                id,
                password: pass()
            }
        ),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        s.execute(&admin, Request::Get { id }),
        Err(Error::Locked)
    ));
}
