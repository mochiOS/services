//! Real standalone replacement: no inherited named grants or trusted identity.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-standalone-image: requires mochiOS");
}

#[cfg(target_os = "mochios")]
#[path = "support/standalone_elf.rs"]
mod payload;
#[cfg(target_os = "mochios")]
#[path = "support/signed_elf.rs"]
mod signed_elf;

#[cfg(target_os = "mochios")]
mod native {
    use super::payload;
    use mochi_user_platform as p;
    use mochi_user_syscall::{self as s, NativeError, SyscallNumber as S};
    use mochios_capability_protocol::signed_image as wire;
    use mochios_elf_signature::{
        SuppliedPublicKey, embed_manifest, sign_adhoc, sign_ed25519, verify_image,
    };
    use sha2::{Digest, Sha256};

    fn ram(bytes: &[u8]) -> p::memory_object::MemoryObject {
        let object = p::memory_object::MemoryObject::create_resizable(bytes.len() as u64).unwrap();
        let mut offset = 0;
        while offset < bytes.len() {
            let n = p::handle::write_at(object.handle(), &bytes[offset..], offset as u64).unwrap();
            assert!(n != 0 && n <= bytes.len() - offset);
            offset += n;
        }
        object
    }

    fn authorize(image: u32, length: u64, key: Option<&[u8; 32]>, version: u32) -> u64 {
        let endpoint = p::process::find_by_name("capability.service").unwrap();
        let mut request = [0; 512];
        let n = wire::encode(
            &wire::Request {
                source_length: length,
                public_key: key,
                identity: "standalone-329",
            },
            &mut request,
        )
        .unwrap();
        request[4..8].copy_from_slice(&version.to_le_bytes());
        let mut handles = p::ipc::IpcObjectHandles::default();
        handles.count = 1;
        handles.handles[0] = p::ipc::IpcObjectHandle {
            handle: image,
            reserved: 0,
            rights: p::memory_object::READONLY_BUFFER_RIGHTS,
        };
        let mut reply = [0; 8];
        let message =
            p::ipc::call_object_handles(endpoint as u32, &request[..n], &mut reply, &mut handles)
                .unwrap();
        assert_eq!(message as u32, 8);
        assert_eq!(handles.count, 0);
        assert_eq!(handles.delivery_flags, 0);
        u64::from_le_bytes(reply)
    }

    fn startup() -> Vec<u8> {
        let mut bytes = vec![0; mnu_abi::process_image::MAX_IMAGE_BYTES];
        let n = mochios_posix_client::process_image::encode_initial_stack(
            &[b"standalone-329"],
            &[],
            b"standalone-329",
            [0; 16],
            &mut bytes,
        )
        .unwrap();
        bytes.truncate(n);
        bytes
    }

    fn replace(signed: &[u8], public: Option<&[u8; 32]>, mutate: bool) {
        let mut pair = s::StreamPair::default();
        s::call1(S::StreamPairCreate, &mut pair as *mut _ as u64).unwrap();
        let original = p::process::thread_security_context(0).unwrap();
        let expected_session = mochios_posix_client::Client::from_launch_context()
            .unwrap()
            .session_info()
            .unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::alarm(90);
            }
            p::handle::close(pair.read).unwrap();
            p::handle::set_context_handle(payload::REPORT_KEY, pair.write).unwrap();
            let image = ram(signed);
            assert_eq!(
                authorize(image.handle(), signed.len() as u64, public, wire::VERSION),
                0
            );
            let before = p::process::thread_security_context(0).unwrap();
            if mutate {
                p::handle::write_at(image.handle(), &[1], 0xf0).unwrap();
            }
            let error =
                s::image::replace_bounded(image.handle(), "standalone-329", &startup(), u64::MAX)
                    .unwrap_err();
            assert!(mutate, "valid standalone replacement failed: {error:?}");
            assert_eq!(error.native_error(), Some(NativeError::AccessDenied));
            assert_eq!(p::process::thread_security_context(0).unwrap(), before);
            p::handle::write_at(image.handle(), &[signed[0xf0]], 0xf0).unwrap();
            let error =
                s::image::replace_bounded(image.handle(), "standalone-329", &startup(), u64::MAX)
                    .unwrap_err();
            assert_eq!(error.native_error(), Some(NativeError::AccessDenied));
            unsafe { libc::_exit(0) }
        }
        p::handle::close(pair.write).unwrap();
        let mut report = [0; payload::REPORT_BYTES];
        let mut received = 0;
        while received < report.len() {
            let n = p::handle::read(pair.read, &mut report[received..]).unwrap();
            if n == 0 {
                break;
            }
            received += n;
        }
        p::handle::close(pair.read).unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, if mutate { 0 } else { 37 << 8 });
        if mutate {
            assert_eq!(received, 0);
            return;
        }
        assert_eq!(received, report.len());
        // The ABI structure contains only integer/byte fields, all overwritten
        // by the native observation. Unaligned loading avoids a buffer cast.
        let context = unsafe {
            core::ptr::read_unaligned(report.as_ptr().cast::<s::ThreadSecurityContext>())
        };
        let digest: [u8; 32] = Sha256::digest(signed).into();
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            &context.package_id[..context.package_id_len as usize],
            format!("local.elf.{hex}").as_bytes()
        );
        assert_eq!(
            &context.developer_id[..context.developer_id_len as usize],
            b"org.mochios.local"
        );
        assert_eq!(
            context.provenance,
            mochios_signature_protocol::InstallProvenance::Development as u8
        );
        let resolver = public.map(SuppliedPublicKey::new).transpose().unwrap();
        let evidence = verify_image(
            signed,
            resolver
                .as_ref()
                .map(|k| k as &dyn mochios_elf_signature::PublicKeyResolver),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(
            context.subject_key_id,
            evidence.signature().key_id.unwrap_or([0; 32])
        );
        let (header, body) =
            mochios_posix_protocol::decode(&report[payload::CONTEXT_BYTES..]).unwrap();
        assert_eq!(header.opcode, mochios_posix_protocol::OP_STATUS);
        assert_eq!(header.request_id, payload::REQUEST_ID);
        assert_eq!(header.status, 0);
        assert_eq!(
            mochios_posix_protocol::decode_session_info(body).unwrap(),
            expected_session
        );
        assert_eq!(p::process::thread_security_context(0).unwrap(), original);
    }

    pub fn run() {
        unsafe {
            libc::alarm(240);
        }
        let unsigned = payload::unsigned();
        let adhoc = sign_adhoc(&unsigned).unwrap();
        let header = "[package]\nid='org.mochios.msh'\nname='msh'\nversion='1'\nvendor='org.mochios.system'\nprovenance='built-in'\n";
        for (declaration, expected) in [
            (
                format!("{header}[[binary]]\npath='main'\nrequires=['net.connect']\n"),
                95,
            ),
            (
                format!("{header}[[binary]]\npath='main'\nrequires=['capabilities.manage']\n"),
                13,
            ),
            (
                format!("{header}[[binary]]\npath='main'\nrequires=['unknown.capability']\n"),
                22,
            ),
            (
                format!("{header}[[binary]]\npath='one'\n[[binary]]\npath='two'\n"),
                22,
            ),
        ] {
            let signed = sign_adhoc(&embed_manifest(&unsigned, &declaration).unwrap()).unwrap();
            let image = ram(&signed);
            assert_eq!(
                authorize(image.handle(), signed.len() as u64, None, wire::VERSION),
                expected
            );
            let error =
                s::image::replace_bounded(image.handle(), "standalone-329", &startup(), u64::MAX)
                    .unwrap_err();
            assert_eq!(error.native_error(), Some(NativeError::AccessDenied));
        }
        let image = ram(&adhoc);
        assert_eq!(authorize(image.handle(), adhoc.len() as u64, None, 1), 22);
        drop(image);
        println!(
            "standalone-image-329: PASS pending consent, protected/unknown capabilities, ambiguous manifest and retired wire version refuse authorization"
        );
        replace(&adhoc, None, false);
        let spoof = sign_adhoc(
            &embed_manifest(
                &unsigned,
                &format!("{header}[[binary]]\npath='/system/bin/msh'\nrequires=[]\n"),
            )
            .unwrap(),
        )
        .unwrap();
        replace(&spoof, None, false);
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let signed = sign_ed25519(&unsigned, &key).unwrap();
        replace(&signed, Some(&key.verifying_key().to_bytes()), false);
        println!(
            "standalone-image-329: PASS all named grants absent, separate measured development identity, verified key and real POSIX IPC after replacement"
        );
        replace(&adhoc, None, true);
        unsafe {
            libc::alarm(0);
        }
        println!(
            "standalone-image-329: PASS changed source refused, failed permit consumed, old process and parent authority preserved"
        );
    }
}

#[cfg(target_os = "mochios")]
fn main() {
    native::run();
}
