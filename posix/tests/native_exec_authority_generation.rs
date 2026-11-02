//! Native revoke/restore races before permit consumption and during image I/O.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("exec-authority-generation: requires mochiOS");
}

#[cfg(target_os = "mochios")]
mod native {
    use mochi_user_platform as p;
    use mochi_user_syscall::{self as syscall, NativeError, SyscallNumber as S};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };

    const CAPABILITY: &[u8] = b"fs.write.tmp";
    const KEY: &str = "exec-authority-generation335";

    fn has_capability() -> bool {
        p::capability::query(CAPABILITY.as_ptr() as u64, CAPABILITY.len() as u64).unwrap() == 1
    }

    fn revoke_and_restore(helper: u64) {
        assert!(has_capability());
        syscall::call2(
            S::CapDrop,
            CAPABILITY.as_ptr() as u64,
            CAPABILITY.len() as u64,
        )
        .unwrap();
        assert!(!has_capability());
        let mut response = [0; 8];
        let received = p::ipc::call(helper, b"restore335", &mut response).unwrap();
        assert_eq!(received as u32, 8);
        assert_eq!(u64::from_le_bytes(response), 0);
        assert!(has_capability());
    }

    fn authorize(image: u32, bytes: &[u8]) {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes).into();
        let mut request = [0; 300];
        let n = p::capability::encode_authorize_exec_object_request(KEY, &digest, &mut request)
            .unwrap();
        let endpoint = p::process::find_by_name("capability.service").unwrap();
        let mut attached = p::ipc::IpcObjectHandles::default();
        attached.count = 1;
        attached.handles[0] = p::ipc::IpcObjectHandle {
            handle: image,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_READ,
        };
        let mut response = [0; 8];
        let message = p::ipc::call_object_handles(
            endpoint as u32,
            &request[..n],
            &mut response,
            &mut attached,
        )
        .unwrap();
        assert_eq!(message as u32, 8);
        assert_eq!(attached.count, 0);
        assert_eq!(attached.delivery_flags, 0);
        assert_eq!(u64::from_le_bytes(response), 0);
    }

    fn delayed_restore(
        bytes: Vec<u8>,
        helper: u64,
    ) -> (u32, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        use mnu_abi::provider as w;
        let (tx, rx) = mpsc::channel();
        let restored = Arc::new(AtomicBool::new(false));
        let observation = restored.clone();
        let worker = std::thread::spawn(move || {
            let endpoint = p::ipc::create_handle().unwrap();
            let object =
                p::handle::create_provider_object(endpoint, 335, mnu_abi::HANDLE_RIGHT_READ)
                    .unwrap();
            tx.send(object).unwrap();
            let mut request = [0; w::REQUEST_HEADER_LEN + w::MAX_DATA_LEN];
            let mut response = [0; w::RESPONSE_HEADER_LEN + w::MAX_DATA_LEN];
            loop {
                let mut attached = p::ipc::IpcObjectHandles::default();
                let message =
                    p::ipc::wait_object_handles(u64::from(endpoint), &mut request, &mut attached)
                        .unwrap();
                assert_eq!(attached.count, 0);
                assert_eq!(attached.delivery_flags, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT);
                let (header, data) =
                    w::RequestHeader::decode(&request[..message as u32 as usize]).unwrap();
                assert_eq!(header.object_id, 335);
                assert!(data.is_empty());
                if header.opcode == w::OP_RELEASE {
                    break;
                }
                if !observation.load(Ordering::Acquire) {
                    revoke_and_restore(helper);
                    observation.store(true, Ordering::Release);
                }
                let source = match header.opcode {
                    w::OP_MEMORY_OBJECT => &[][..],
                    w::OP_READ_AT => {
                        let offset = usize::try_from(header.basis).unwrap();
                        bytes.get(offset..).unwrap_or(&[])
                    }
                    other => panic!("unexpected provider request {other}"),
                };
                let n = source
                    .len()
                    .min(header.length as usize)
                    .min(w::MAX_DATA_LEN);
                let n = w::ResponseHeader {
                    opcode: header.opcode,
                    status: 0,
                    object_id: 335,
                    value: n as u64,
                    data_length: n as u32,
                }
                .encode(&source[..n], &mut response)
                .unwrap();
                p::ipc::reply(message >> 32, &response[..n]).unwrap();
            }
            p::handle::close(endpoint).unwrap();
        });
        (rx.recv().unwrap(), restored, worker)
    }

    fn wait_status(pid: i32) -> i32 {
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        status
    }

    fn wait(pid: i32, expected: i32) {
        let status = wait_status(pid);
        assert!(libc::WIFEXITED(status), "unexpected wait status {status}");
        assert_eq!(libc::WEXITSTATUS(status), expected);
    }

    fn run_case(bytes: &[u8], case: u8) {
        unsafe { libc::alarm(120) };
        let helper = p::ipc::create().unwrap();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::alarm(90) };
            let object =
                p::memory_object::MemoryObject::create_resizable(bytes.len() as u64).unwrap();
            for (index, chunk) in bytes.chunks(256 * 1024).enumerate() {
                assert_eq!(
                    p::handle::write_at(object.handle(), chunk, (index * 256 * 1024) as u64)
                        .unwrap(),
                    chunk.len()
                );
            }
            let delayed = (case == 2).then(|| delayed_restore(bytes.to_vec(), helper));
            authorize(object.handle(), bytes);
            if case == 1 {
                revoke_and_restore(helper);
            }
            let old = p::process::thread_security_context(0).unwrap();
            let mut startup = vec![0; mnu_abi::process_image::MAX_IMAGE_BYTES];
            let length = mochios_posix_client::process_image::encode_initial_stack(
                &[b"exec-authority-generation", b"--replaced"],
                &[],
                b"exec-authority-generation335",
                [0; 16],
                &mut startup,
            )
            .unwrap();
            let image = delayed.as_ref().map_or(object.handle(), |d| d.0);
            let error = syscall::image::replace_bounded(image, KEY, &startup[..length], u64::MAX)
                .unwrap_err();
            assert_ne!(case, 0, "valid unchanged permit must execute the image");
            assert_eq!(error.raw(), NativeError::AccessDenied.into_raw() as i64);
            assert!(
                has_capability(),
                "the exact original grant set was restored"
            );
            let current = p::process::thread_security_context(0).unwrap();
            assert_eq!(old.process_id, current.process_id);
            assert_eq!(old.package_id, current.package_id);
            if let Some((provider, restored, worker)) = delayed {
                assert!(restored.load(Ordering::Acquire));
                p::handle::close(provider).unwrap();
                syscall::call0(S::ThreadYield).unwrap();
                worker.join().unwrap();
            }
            assert!(
                syscall::image::replace_bounded(
                    object.handle(),
                    KEY,
                    &startup[..length],
                    u64::MAX,
                )
                .is_err()
            );
            unsafe { libc::_exit(0) };
        }
        if case != 0 {
            let mut request = [0; 32];
            let message = p::ipc::wait(helper, &mut request).unwrap();
            assert_eq!(&request[..message as u32 as usize], b"restore335");
            syscall::call3(
                S::CapTransfer,
                message >> 32,
                CAPABILITY.as_ptr() as u64,
                CAPABILITY.len() as u64,
            )
            .unwrap();
            p::ipc::reply(message >> 32, &0u64.to_le_bytes()).unwrap();
        }
        wait(child, if case == 0 { 37 } else { 0 });
        unsafe { libc::_exit(0) };
    }

    pub fn main() {
        if std::env::args().nth(1).as_deref() == Some("--replaced") {
            assert!(has_capability());
            unsafe { libc::_exit(37) };
        }
        let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let mut failures = 0;
        for (case, label) in [
            (
                0,
                "unchanged measured image executes with its declared grants",
            ),
            (1, "revoke/restore invalidates the stored permit"),
            (
                2,
                "revoke/restore during image I/O invalidates the consumed permit",
            ),
        ] {
            let helper = unsafe { libc::fork() };
            assert!(helper >= 0);
            if helper == 0 {
                run_case(&bytes, case);
            }
            let status = wait_status(helper);
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                println!("exec-authority-generation-335: PASS {label}");
            } else {
                failures += 1;
                println!("exec-authority-generation-335: FAIL {label}, status={status}");
            }
        }
        assert_eq!(failures, 0);
    }
}

#[cfg(target_os = "mochios")]
fn main() {
    native::main();
}
