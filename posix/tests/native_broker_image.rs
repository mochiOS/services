//! Diagnostic role gate: trusted code, then same identity after image change.
//! Requires capability built with mochios_verified_launch_probe_305.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("broker-image: SKIP (requires mochiOS)");
}
#[cfg(target_os = "mochios")]
mod native {
    use mochi_user_platform as p;
    use mochi_user_syscall as s;
    use mochios_posix_client::{Client, OpenAtBase, StatAtBase};
    use mochios_posix_protocol as w;
    use sha2::{Digest, Sha256};
    const CONTEXT: u64 = 0x42524f4b45523301;
    const KEY: &str = "broker-image-301";
    unsafe extern "C" {
        fn _exit(code: i32) -> !;
        fn geteuid() -> u32;
        fn alarm(seconds: u32) -> u32;
    }
    fn context() -> u64 {
        let context = p::process::thread_security_context(0).unwrap();
        assert_eq!(
            &context.package_id[..context.package_id_len as usize],
            b"org.mochios.msh"
        );
        assert_eq!(
            &context.developer_id[..context.developer_id_len as usize],
            b"org.mochios.system"
        );
        assert_eq!(context.provenance, 1);
        assert_eq!(context.subject_key_id, [0; 32]);
        let mut digest = Sha256::new();
        digest.update(context.process_id.to_le_bytes());
        digest.update(context.thread_id.to_le_bytes());
        digest.update(context.package_id);
        digest.update(context.developer_id);
        u64::from_le_bytes(digest.finalize()[..8].try_into().unwrap())
    }
    fn gate() -> u64 {
        let service = p::process::find_by_name("capability.service").unwrap();
        let mut reply = [0; 8];
        // Inspect the real role adapter without reviving the retired scalar
        // approval protocol. This diagnostic operation never grants authority.
        let request = u32::from_le_bytes(*b"MR05").to_le_bytes();
        let message = p::ipc::call(service, &request, &mut reply).unwrap();
        assert_eq!(message as u32, 8);
        u64::from_le_bytes(reply)
    }
    pub fn run() {
        unsafe {
            alarm(60);
        }
        let expected = context();
        let info = p::process::image_info(None).unwrap();
        if std::env::args().any(|s| s == "--changed") {
            assert_eq!(expected, p::handle::inherited_value(CONTEXT).unwrap());
            assert_eq!(info.image_revision, 1);
            assert_eq!(gate(), 13);
            println!(
                "broker-image-native: PASS inherited builtin identity cannot authenticate changed code euid={}",
                unsafe { geteuid() }
            );
            unsafe { _exit(0) }
        }
        assert_eq!(info.image_revision, 0);
        assert_eq!(gate(), 0);
        let client = Client::from_launch_context().unwrap();
        let mut bytes = std::fs::read("/system/bin/msh").unwrap();
        bytes.extend_from_slice(b"changed-broker-301");
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        assert_ne!(digest, info.digest);
        let path = format!("/tmp/broker-image-301-{}", info.process_id);
        let file = client
            .open_at(
                OpenAtBase::ProcessRoot,
                w::OPEN_READ | w::OPEN_WRITE | w::OPEN_CREATE | w::OPEN_EXCLUSIVE,
                0o700,
                path.as_bytes(),
            )
            .unwrap();
        let mut offset = 0;
        while offset < bytes.len() {
            let end = bytes.len().min(offset + mnu_abi::provider::MAX_DATA_LEN);
            let n = p::handle::write_at(file.handle, &bytes[offset..end], offset as u64).unwrap();
            assert!(n > 0);
            offset += n;
        }
        client
            .unlink_at(StatAtBase::ProcessRoot, 0, path.as_bytes())
            .unwrap();
        p::handle::set_context_value(CONTEXT, expected).unwrap();
        let mut request = [0; 300];
        let length =
            p::capability::encode_authorize_exec_object_request(KEY, &digest, &mut request)
                .unwrap();
        let mut objects = p::ipc::IpcObjectHandles::default();
        objects.count = 1;
        objects.handles[0] = p::ipc::IpcObjectHandle {
            handle: file.handle,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_READ,
        };
        let mut reply = [0; 8];
        let endpoint = p::process::find_by_name("capability.service").unwrap() as u32;
        let message =
            p::ipc::call_object_handles(endpoint, &request[..length], &mut reply, &mut objects)
                .unwrap();
        assert_eq!(message as u32, 8);
        assert_eq!(objects.count, 0);
        assert_eq!(u64::from_le_bytes(reply), 0);
        let mut startup = vec![0; mnu_abi::process_image::MAX_IMAGE_BYTES];
        let n = mochios_posix_client::process_image::encode_initial_stack(
            &[b"msh", b"--changed"],
            &[],
            KEY.as_bytes(),
            [0; 16],
            &mut startup,
        )
        .unwrap();
        let error =
            s::image::replace_bounded(file.handle, KEY, &startup[..n], u64::MAX).unwrap_err();
        panic!("replacement returned {error:?}");
    }
}
#[cfg(target_os = "mochios")]
fn main() {
    native::run();
}
