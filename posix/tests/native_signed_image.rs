//! Real IPC attachment/type checks and commit-time binding for signed RAM ELF.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-signed-image: requires mochiOS");
}

#[cfg(target_os = "mochios")]
#[path = "support/signed_elf.rs"]
mod fixture;

#[cfg(target_os = "mochios")]
mod native {
    use mochi_user_platform as p;
    use mochi_user_syscall::{self as s, NativeError, SyscallNumber as S};
    use mochios_capability_protocol::signed_image as wire;
    use mochios_elf_signature::{sign_adhoc, sign_ed25519};

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

    fn authorize(
        handle: u32,
        length: u64,
        key: Option<&[u8; 32]>,
        rights: u64,
        identity: &str,
    ) -> u64 {
        let endpoint = p::process::find_by_name("capability.service").unwrap();
        let mut bytes = [0; 512];
        let n = wire::encode(
            &wire::Request {
                source_length: length,
                public_key: key,
                identity,
            },
            &mut bytes,
        )
        .unwrap();
        let mut attached = p::ipc::IpcObjectHandles::default();
        attached.count = 1;
        attached.handles[0] = p::ipc::IpcObjectHandle {
            handle,
            reserved: 0,
            rights,
        };
        let mut reply = [0; 8];
        let received =
            p::ipc::call_object_handles(endpoint as u32, &bytes[..n], &mut reply, &mut attached)
                .unwrap();
        assert_eq!(attached.count, 0);
        assert_eq!(attached.delivery_flags, 0);
        assert_eq!(received as u32, 8);
        u64::from_le_bytes(reply)
    }

    fn exit_image() -> Vec<u8> {
        let mut elf = super::fixture::unsigned();
        elf[24..32].copy_from_slice(&0x400080u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5u32.to_le_bytes());
        elf[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[96..104].copy_from_slice(&0x90u64.to_le_bytes());
        elf[104..112].copy_from_slice(&0x90u64.to_le_bytes());
        elf[112..120].copy_from_slice(&4096u64.to_le_bytes());
        // _start: ProcessExit(37); ud2. The syscall selector comes from the
        // native ABI; no Linux exit number or libc startup is assumed.
        let mut code = vec![0xbf, 37, 0, 0, 0, 0xb8];
        code.extend_from_slice(&(S::ProcessExit as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
        elf[0x80..0x80 + code.len()].copy_from_slice(&code);
        elf[0x100 + 128 + 32..0x100 + 128 + 40].copy_from_slice(&(code.len() as u64).to_le_bytes());
        sign_adhoc(&elf).unwrap()
    }

    fn replacement(signed: &[u8], mutate: bool) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let object = ram(signed);
            let key = "signed-image-323:replace";
            assert_eq!(
                authorize(
                    object.handle(),
                    signed.len() as u64,
                    None,
                    p::memory_object::READONLY_BUFFER_RIGHTS,
                    key
                ),
                0
            );
            if mutate {
                // A retained writer changes a byte outside PT_LOAD after the
                // broker verified it. Native commit must still reject it.
                p::handle::write_at(object.handle(), &[1], 0xf0).unwrap();
            }
            let mut startup = vec![0; mnu_abi::process_image::MAX_IMAGE_BYTES];
            let n = mochios_posix_client::process_image::encode_initial_stack(
                &[b"signed-image-323"],
                &[],
                key.as_bytes(),
                [0; 16],
                &mut startup,
            )
            .unwrap();
            let error = s::image::replace_bounded(object.handle(), key, &startup[..n], u64::MAX)
                .unwrap_err();
            assert!(mutate, "valid signed image failed to replace: {error:?}");
            assert_eq!(error.raw(), NativeError::AccessDenied.into_raw() as i64);
            p::handle::write_at(object.handle(), &[signed[0xf0]], 0xf0).unwrap();
            let retry = s::image::replace_bounded(object.handle(), key, &startup[..n], u64::MAX)
                .unwrap_err();
            assert_eq!(
                retry.raw(),
                NativeError::AccessDenied.into_raw() as i64,
                "failed permits must be consumed"
            );
            unsafe { libc::_exit(0) }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, if mutate { 0 } else { 37 << 8 });
    }

    pub fn run() {
        unsafe {
            libc::alarm(120);
        }
        let unsigned = super::fixture::unsigned();
        let signed = sign_adhoc(&unsigned).unwrap();
        let rights = p::memory_object::READONLY_BUFFER_RIGHTS;
        let object = ram(&signed);
        assert_eq!(
            authorize(
                object.handle(),
                signed.len() as u64,
                None,
                rights,
                "signed-image-323:valid"
            ),
            0
        );
        println!("signed-image-323: PASS signed RAM authorization");
        let object = ram(&unsigned);
        assert_ne!(
            authorize(
                object.handle(),
                unsigned.len() as u64,
                None,
                rights,
                "signed-image-323:unsigned"
            ),
            0
        );
        let mut tampered = signed.clone();
        tampered[0xf0] ^= 1;
        let object = ram(&tampered);
        assert_ne!(
            authorize(
                object.handle(),
                tampered.len() as u64,
                None,
                rights,
                "signed-image-323:tampered"
            ),
            0
        );
        println!("signed-image-323: PASS unsigned and tampered refusal");
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let keyed = sign_ed25519(&unsigned, &key).unwrap();
        let object = ram(&keyed);
        assert_ne!(
            authorize(
                object.handle(),
                keyed.len() as u64,
                None,
                rights,
                "signed-image-323:no-key"
            ),
            0
        );
        let wrong = ed25519_dalek::SigningKey::from_bytes(&[24; 32])
            .verifying_key()
            .to_bytes();
        assert_ne!(
            authorize(
                object.handle(),
                keyed.len() as u64,
                Some(&wrong),
                rights,
                "signed-image-323:wrong-key"
            ),
            0
        );
        assert_eq!(
            authorize(
                object.handle(),
                keyed.len() as u64,
                Some(&key.verifying_key().to_bytes()),
                rights,
                "signed-image-323:keyed"
            ),
            0
        );
        println!("signed-image-323: PASS explicit keyed integrity without grants");
        let object = ram(&signed);
        assert_ne!(
            authorize(
                object.handle(),
                signed.len() as u64,
                None,
                p::handle::HANDLE_RIGHT_READ,
                "signed-image-323:rights"
            ),
            0
        );
        assert_ne!(
            authorize(
                object.handle(),
                signed.len() as u64 + 1,
                None,
                rights,
                "signed-image-323:length"
            ),
            0
        );
        println!("signed-image-323: PASS attachment rights and exact extent");
        // This endpoint has no Provider server. The broker must reject its
        // object by native type alone, without attempting a callback to us.
        let endpoint = p::ipc::create_handle().unwrap();
        let provider = p::handle::create_provider_object(
            endpoint,
            323,
            rights | p::handle::HANDLE_RIGHT_TRANSFER,
        )
        .unwrap();
        assert_ne!(
            authorize(
                provider,
                signed.len() as u64,
                None,
                rights,
                "signed-image-323:provider"
            ),
            0
        );
        p::handle::close(provider).unwrap();
        p::handle::close(endpoint).unwrap();
        println!("signed-image-323: PASS Provider refused without owner IO");
        replacement(&exit_image(), false);
        println!("signed-image-323: PASS verified native replacement and exit37");
        replacement(&exit_image(), true);
        println!("signed-image-323: PASS post-verification mutation and permit replay refusal");
        unsafe {
            libc::alarm(0);
        }
        println!("signed-image-323: PASS all boundaries");
    }
}

#[cfg(target_os = "mochios")]
fn main() {
    native::run();
}
