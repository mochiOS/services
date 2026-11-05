//! Exercise the actual selection, consumed approval, persistent codec and
//! image-install authorization; only storage and credential I/O are injected.
use super::*;
use execution_grant::Key;
use platform_real::capability::consent::Choice;

fn saved(code: Vec<u8>) -> Vec<u8> {
    setup(code.clone());
    let request = approvals::pending(&empty_state(), code);
    let approval = approvals::approval(request.binding(), Choice::AllowPersistently);
    request
        .complete(approval, &approvals::peer(202), approvals::session(), 3)
        .unwrap();
    STATE.with_borrow(|s| {
        assert_eq!(s.issue_calls, 1);
        assert_eq!(s.grant_writes, 1);
        s.grant_bytes.clone().unwrap()
    })
}

fn fresh(code: Vec<u8>, database: &[u8], uid: u32) -> execution_approval::Selection {
    setup(code.clone());
    STATE.with_borrow_mut(|s| {
        s.uid = uid;
        s.grant_bytes = Some(database.to_vec());
    });
    signed_image::select_snapshot(&empty_state(), None, &code).unwrap()
}

#[test]
fn always_survives_a_new_controller_and_exec_key_without_widening_the_requester() {
    let code = approvals::code();
    let db = saved(code.clone());
    let selection = fresh(code, &db, 1000);
    assert!(
        selection
            .authorize_remembered(&approvals::peer(202), "another-invocation")
            .unwrap()
    );
    STATE.with_borrow(|s| {
        assert_eq!(s.issue_calls, 1);
        assert_eq!(s.grant_writes, 0);
        assert_eq!(s.issued[0].1, "another-invocation");
        assert_eq!(s.issued_caps[0], b"net.connect\0");
        assert!(
            String::from_utf8_lossy(&s.issued[0].2)
                .contains("__MNU_EXEC_AUTH_KIND=image-install\0")
        );
    });
}

#[test]
fn changed_file_changed_user_and_new_requirements_need_new_consent() {
    let original = approvals::code();
    let db = saved(original.clone());
    for (code, uid) in [
        (original.clone(), 1001),
        (
            declared("[[binary]]\npath='main'\nrequires=['net.listen']\n"),
            1000,
        ),
        (
            declared("[[binary]]\npath='renamed'\nrequires=['net.connect']\n"),
            1000,
        ),
    ] {
        let selected = fresh(code, &db, uid);
        assert!(
            !selected
                .authorize_remembered(&approvals::peer(202), "next")
                .unwrap()
        );
        no_issue();
    }

    // Installed declarations can change without changing the executable's
    // bytes. The exact canonical requirements must still match.
    let code = fixture::unsigned();
    setup(code.clone());
    let mut state = empty_state();
    install_code(
        &mut state,
        "org.mochios.fixture",
        "/system/bin/fixture",
        &code,
        "application",
        &["net.connect"],
    );
    let request = approvals::pending(&state, code.clone());
    let decision = approvals::approval(request.binding(), Choice::AllowPersistently);
    request
        .complete(decision, &approvals::peer(202), approvals::session(), 3)
        .unwrap();
    install_code(
        &mut state,
        "org.mochios.fixture",
        "/system/bin/fixture",
        &code,
        "application",
        &["net.connect", "net.listen"],
    );
    let selected = signed_image::select_snapshot(&state, None, &code).unwrap();
    STATE.with_borrow_mut(|s| {
        s.issued.clear();
        s.issue_calls = 0;
    });
    assert!(
        !selected
            .authorize_remembered(&approvals::peer(202), "next")
            .unwrap()
    );
    no_issue();
}

#[test]
fn key_binds_publisher_provenance_and_exact_caps_but_not_argument_order() {
    let identity = || resolver::ApplicationIdentity {
        package_id: "local.example".into(),
        developer_id: "local.developer".into(),
        subject_key_id: [1; 32],
        provenance: mochios_signature_protocol::InstallProvenance::Development,
    };
    let caps = vec!["net.connect".into(), "fs.read.tmp".into()];
    let original = Key::new(1000, &identity(), &caps, [7; 32]).unwrap();
    assert_eq!(
        original,
        Key::new(
            1000,
            &identity(),
            &[caps[1].clone(), caps[0].clone(), caps[1].clone()],
            [7; 32]
        )
        .unwrap()
    );
    for field in 0..6 {
        let mut changed = identity();
        let mut caps = caps.clone();
        match field {
            0 => changed.package_id.push('x'),
            1 => changed.developer_id.push('x'),
            2 => changed.subject_key_id[0] ^= 1,
            3 => changed.provenance = mochios_signature_protocol::InstallProvenance::BuiltIn,
            4 => {
                caps.pop();
            }
            _ => caps.push("net.listen".into()),
        }
        assert_ne!(original, Key::new(1000, &changed, &caps, [7; 32]).unwrap());
    }
}

#[test]
fn storage_and_identity_failures_never_succeed_as_allow_once() {
    for stage in 0..3 {
        let code = approvals::code();
        setup(code.clone());
        let request = approvals::pending(&empty_state(), code);
        let approval = approvals::approval(request.binding(), Choice::AllowPersistently);
        STATE.with_borrow_mut(|s| match stage {
            0 => s.grant_write_error = Some(SysError::from(NativeError::BackingFailure.into_raw())),
            1 => s.grant_read_error = Some(SysError::from(NativeError::BackingFailure.into_raw())),
            _ => s.uid += 1,
        });
        assert!(
            request
                .complete(approval, &approvals::peer(202), approvals::session(), 3)
                .is_err()
        );
        STATE.with_borrow(|s| {
            assert!(s.grant_bytes.is_none());
            assert_eq!(s.issue_calls, 0);
        });
        no_issue();
    }
    let code = approvals::code();
    let db = saved(code.clone());
    let selection = fresh(code, &db, 1000);
    STATE.with_borrow_mut(|s| {
        s.uid_error = Some(SysError::from(NativeError::AccessDenied.into_raw()))
    });
    assert!(
        selection
            .authorize_remembered(&approvals::peer(202), "next")
            .is_err()
    );
    no_issue();
}

#[test]
fn once_is_never_saved_and_process_scope_is_not_offered() {
    let code = approvals::code();
    setup(code.clone());
    let request = approvals::pending(&empty_state(), code);
    assert!(request.choices().contains(Choice::AllowPersistently));
    assert!(!request.choices().contains(Choice::AllowForProcess));
    let decision = approvals::approval(request.binding(), Choice::AllowOnce);
    request
        .complete(decision, &approvals::peer(202), approvals::session(), 3)
        .unwrap();
    STATE.with_borrow(|s| {
        assert!(s.grant_bytes.is_none());
        assert_eq!(s.grant_writes, 0);
    });
}

#[test]
fn strict_database_rejects_every_truncation_and_corruption_without_issuing_authority() {
    let code = approvals::code();
    let db = saved(code.clone());
    for end in 0..db.len() {
        assert!(execution_grant::decode(&db[..end]).is_err());
    }
    for offset in 0..db.len() {
        let mut changed = db.clone();
        changed[offset] ^= 1;
        assert!(execution_grant::decode(&changed).is_err());
    }
    let mut changed = db.clone();
    changed.push(0);
    assert!(execution_grant::decode(&changed).is_err());
    let selected = fresh(code, &changed, 1000);
    assert!(
        selected
            .authorize_remembered(&approvals::peer(202), "next")
            .is_err()
    );
    no_issue();
}

fn seal(bytes: &mut Vec<u8>) {
    let mut hash = Sha256::new();
    hash.update(b"mochiOS remembered execution database v1\0");
    hash.update(&*bytes);
    bytes.extend_from_slice(&hash.finalize());
}

#[test]
fn duplicate_unordered_reserved_and_oversized_databases_are_rejected_even_with_valid_checksum() {
    let db = saved(approvals::code());
    for change in 0..4 {
        let mut bytes = db[..db.len() - 32].to_vec();
        match change {
            0 => bytes[12] = 1,
            1 => bytes[20] = 1,
            _ => {
                bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
                let mut record = bytes[16..].to_vec();
                if change == 3 {
                    record[..4].copy_from_slice(&999u32.to_le_bytes());
                }
                bytes.extend_from_slice(&record);
            }
        }
        seal(&mut bytes);
        assert!(execution_grant::decode(&bytes).is_err());
    }
    assert!(execution_grant::decode(&vec![0; execution_grant::MAX_BYTES + 1]).is_err());
}

#[test]
fn duplicate_approval_is_idempotent_and_full_database_never_truncates_old_grants() {
    let db = saved(approvals::code());
    let key = execution_grant::decode(&db).unwrap()[0];
    execution_grant::remember(key).unwrap();
    STATE.with_borrow(|s| {
        assert_eq!(s.grant_writes, 1);
        assert_eq!(s.grant_bytes.as_deref(), Some(db.as_slice()));
    });
    let mut full = b"MEXGRNT1".to_vec();
    full.extend_from_slice(&4096u32.to_le_bytes());
    full.extend_from_slice(&[0; 4]);
    for uid in 0u32..4096 {
        full.extend_from_slice(&uid.to_le_bytes());
        full.extend_from_slice(&[0; 4]);
        full.extend_from_slice(&[0x11; 32]);
        full.extend_from_slice(&[0x22; 32]);
        full.extend_from_slice(&[0x33; 32]);
    }
    seal(&mut full);
    assert_eq!(full.len(), execution_grant::MAX_BYTES);
    assert_eq!(execution_grant::decode(&full).unwrap().len(), 4096);
    STATE.with_borrow_mut(|s| {
        s.grant_bytes = Some(full.clone());
        s.grant_writes = 0;
    });
    assert_eq!(
        execution_grant::remember(key).unwrap_err().native_error(),
        Some(NativeError::LimitExceeded)
    );
    STATE.with_borrow(|s| {
        assert_eq!(s.grant_writes, 0);
        assert_eq!(s.grant_bytes.as_deref(), Some(full.as_slice()));
    });
}
