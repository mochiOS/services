use super::*;
use mochios_capability_protocol::library_image as library_wire;

fn request(code: Vec<u8>) -> (Vec<u8>, ipc::IpcObjectHandles) {
    let length = code.len() as u64;
    let (_, attached) = setup(code);
    let mut request = vec![0; library_wire::REQUEST_LEN];
    library_wire::encode(length, &mut request).unwrap();
    (request, attached)
}

fn declared(kind: &str, caps: &[&str]) -> Vec<u8> {
    let text = format!(
        "[package]\nid='local.library'\nname='fixture'\nversion='1'\n[[binary]]\npath='/tmp/library.so'\nkind='{kind}'\nrequires={caps:?}\n"
    );
    let bytes = mochios_elf_signature::embed_manifest(&fixture::unsigned(), &text).unwrap();
    sign_adhoc(&bytes).unwrap()
}

#[test]
fn same_domain_library_requires_neither_spawn_nor_an_execution_permit() {
    for code in [
        sign_adhoc(&fixture::unsigned()).unwrap(),
        declared("library", &[]),
    ] {
        let digest: [u8; 32] = Sha256::digest(&code).into();
        let (bytes, attached) = request(code);
        STATE.with_borrow_mut(|s| s.allowed = false);
        assert_eq!(
            library_image::verify(&empty_state(), 77, &bytes, &attached),
            Ok(digest)
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.peer_captures, 2);
            assert!(s.issued.is_empty());
            assert_eq!(s.grant_writes, 0);
        });
    }
}

#[test]
fn library_requirements_are_only_a_ceiling_check_and_never_a_grant() {
    for allowed in [false, true] {
        let (bytes, attached) = request(declared("library", &["net.connect"]));
        if allowed {
            STATE.with_borrow_mut(|s| {
                s.library_caps.insert("net.connect".into());
            });
        }
        assert_eq!(
            library_image::verify(&empty_state(), 77, &bytes, &attached).is_ok(),
            allowed
        );
        no_issue();
        STATE.with_borrow(|s| assert_eq!(s.grant_writes, 0));
    }
    for (kind, caps) in [
        ("application", &[][..]),
        ("service", &[][..]),
        ("library", &["capabilities.manage"][..]),
        ("library", &["unknown.capability"][..]),
    ] {
        let (bytes, attached) = request(declared(kind, caps));
        STATE.with_borrow_mut(|s| {
            s.library_caps.extend(caps.iter().map(|s| s.to_string()));
        });
        assert!(library_image::verify(&empty_state(), 77, &bytes, &attached).is_err());
        no_issue();
    }
}

#[test]
fn installed_library_uses_authenticated_code_and_certificate_allowance() {
    let code = fixture::unsigned();
    let digest = Sha256::digest(&code).into();
    let (bytes, attached) = request(code.clone());
    let mut state = empty_state();
    install_code(
        &mut state,
        "org.mochios.library",
        "/system/lib/example.so",
        &code,
        "library",
        &["fs.read.all"],
    );
    assert!(library_image::verify(&state, 77, &bytes, &attached).is_err());
    STATE.with_borrow_mut(|s| {
        s.library_caps.insert("fs.read.all".into());
    });
    assert_eq!(
        library_image::verify(&state, 77, &bytes, &attached),
        Ok(digest)
    );
    no_issue();
    STATE.with_borrow_mut(|s| {
        s.files
            .get_mut("/system/packages/org.mochios.library/manifest.toml")
            .unwrap()
            .extend_from_slice(b"\n# unsigned change");
    });
    assert!(library_image::verify(&state, 77, &bytes, &attached).is_err());
    no_issue();
}

#[test]
fn unsigned_tampered_changed_peer_and_invalid_attachments_fail_closed() {
    for case in 0..12 {
        let mut code = sign_adhoc(&fixture::unsigned()).unwrap();
        if case == 0 {
            code = fixture::unsigned();
        }
        if case == 1 {
            code[0x80] ^= 1;
        }
        let (mut bytes, mut attached) = request(code);
        match case {
            2 => attached.count = 0,
            3 => attached.count = 2,
            4 => attached.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            5 => attached.handles[0].handle = 0,
            6 => attached.handles[0].reserved = 1,
            7 => attached.handles[0].rights |= mnu_abi::HANDLE_RIGHT_WRITE,
            8 => attached.handles[0].rights = 0,
            9 => bytes[16] = 1,
            10 => STATE.with_borrow_mut(|s| s.changed_peer = true),
            11 => STATE.with_borrow_mut(|s| s.extent += 1),
            _ => {}
        }
        assert!(
            library_image::verify(&empty_state(), 77, &bytes, &attached).is_err(),
            "case {case}"
        );
        no_issue();
    }
}

#[test]
fn library_wire_rejects_extensions_and_error_replies_with_digests() {
    let (bytes, _) = request(sign_adhoc(&fixture::unsigned()).unwrap());
    for length in 0..bytes.len() {
        assert!(library_wire::decode(&bytes[..length]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(library_wire::decode(&extra).is_err());
    let digest = [3; 32];
    assert_eq!(
        library_wire::decode_reply(&library_wire::reply(0, Some(&digest))),
        Ok((0, &digest))
    );
    let mut error = library_wire::reply(13, Some(&digest));
    assert_eq!(library_wire::decode_reply(&error), Ok((13, &[0; 32])));
    error[8] = 1;
    assert!(library_wire::decode_reply(&error).is_err());
}
