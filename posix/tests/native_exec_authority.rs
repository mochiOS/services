//! Native image replacement must not restore authority dropped after admission.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("exec-authority: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
mod native {
    use mnu_abi::{SyscallNumber as S, provider};
    use mochi_user_platform as platform;
    use mochi_user_syscall as syscall;
    use mochios_posix_client::{Client, OpenAtBase};
    use mochios_posix_protocol as wire;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };

    const IMAGE: &str = "/system/services/compositor.service";
    const READ: &[u8] = b"fs.read.all";
    const MARKER: u64 = 0x455845435245564f;
    unsafe extern "C" {
        fn fork() -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(code: i32) -> !;
        fn alarm(seconds: u32) -> u32;
    }

    fn revoke() {
        assert_eq!(
            platform::capability::query(READ.as_ptr() as u64, READ.len() as u64).unwrap(),
            1
        );
        syscall::call2(S::CapDrop, READ.as_ptr() as u64, READ.len() as u64).unwrap();
        assert_eq!(
            platform::capability::query(READ.as_ptr() as u64, READ.len() as u64).unwrap(),
            0
        );
    }

    fn authorize() {
        let endpoint = platform::process::find_by_name("capability.service").unwrap();
        let request = platform::capability::encode_authorize_exec_request(IMAGE).unwrap();
        let mut reply = [0; 8];
        let message = platform::ipc::call(endpoint, &request, &mut reply).unwrap();
        assert_eq!(message as u32, 8);
        assert_eq!(u64::from_le_bytes(reply), 0);
    }

    // The first provider request is issued only after the pending permit was
    // consumed. Revocation here deterministically exercises the second check.
    fn delayed_revocation(image: u32) -> (u32, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let mut bytes = Vec::new();
        loop {
            let mut part = [0; provider::MAX_DATA_LEN];
            let count = platform::handle::read_at(image, &mut part, bytes.len() as u64).unwrap();
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&part[..count]);
            assert!(bytes.len() <= 64 * 1024 * 1024);
        }
        let (tx, rx) = mpsc::channel();
        let revoked = Arc::new(AtomicBool::new(false));
        let worker_revoked = revoked.clone();
        let worker = std::thread::spawn(move || {
            let endpoint = platform::ipc::create_handle().unwrap();
            let proxy =
                platform::handle::create_provider_object(endpoint, 198, mnu_abi::HANDLE_RIGHT_READ)
                    .unwrap();
            tx.send(proxy).unwrap();
            let mut request = [0; provider::REQUEST_HEADER_LEN + provider::MAX_DATA_LEN];
            let mut response = [0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
            loop {
                let mut objects = platform::ipc::IpcObjectHandles::default();
                let message = platform::ipc::wait_object_handles(
                    u64::from(endpoint),
                    &mut request,
                    &mut objects,
                )
                .unwrap();
                assert_eq!(objects.count, 0);
                assert_eq!(objects.delivery_flags, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT);
                let (header, data) =
                    provider::RequestHeader::decode(&request[..message as u32 as usize]).unwrap();
                assert_eq!(header.object_id, 198);
                assert!(data.is_empty());
                if header.opcode == provider::OP_RELEASE {
                    break;
                }
                if !worker_revoked.load(Ordering::Acquire) {
                    revoke();
                    worker_revoked.store(true, Ordering::Release);
                }
                let data = match header.opcode {
                    provider::OP_MEMORY_OBJECT => &[][..],
                    provider::OP_READ_AT => {
                        let start = usize::try_from(header.basis).unwrap().min(bytes.len());
                        let end = start
                            .saturating_add(header.length as usize)
                            .min(bytes.len());
                        &bytes[start..end]
                    }
                    other => panic!("unexpected provider request {other}"),
                };
                let count = provider::ResponseHeader {
                    opcode: header.opcode,
                    status: 0,
                    object_id: 198,
                    value: data.len() as u64,
                    data_length: data.len() as u32,
                }
                .encode(data, &mut response)
                .unwrap();
                platform::ipc::reply(message >> 32, &response[..count]).unwrap();
            }
            platform::handle::close(endpoint).unwrap();
        });
        (rx.recv().unwrap(), revoked, worker)
    }

    fn child(case: usize) {
        unsafe {
            alarm(60);
        }
        let client = Client::from_launch_context().unwrap();
        let image = client
            .open_at(
                OpenAtBase::ProcessRoot,
                wire::OPEN_READ | wire::OPEN_EXECUTE,
                0,
                IMAGE,
            )
            .unwrap()
            .handle;
        // A buggy kernel could successfully enter this same probe. A native
        // inherited marker makes that a failure rather than recursively testing.
        let mut pair = mnu_abi::StreamPair::default();
        syscall::call1(S::StreamPairCreate, &mut pair as *mut _ as u64).unwrap();
        syscall::call2(S::ContextHandleSet, MARKER, u64::from(pair.read)).unwrap();
        let delayed = (case == 2).then(|| delayed_revocation(image));
        authorize();
        if case != 2 {
            revoke();
        }
        let mut startup = vec![0; mnu_abi::process_image::MAX_IMAGE_BYTES];
        let length = mochios_posix_client::process_image::encode_initial_stack(
            &[b"exec-authority"],
            &[],
            IMAGE.as_bytes(),
            [0; 16],
            &mut startup,
        )
        .unwrap();
        let source = if case == 0 {
            0
        } else {
            delayed.as_ref().map_or(image, |d| d.0)
        };
        let error = syscall::image::replace_bounded(source, IMAGE, &startup[..length], u64::MAX)
            .unwrap_err();
        assert_eq!(
            error.raw(),
            mnu_abi::status::Error::AccessDenied.into_raw() as i64
        );
        assert_eq!(
            platform::capability::query(READ.as_ptr() as u64, READ.len() as u64).unwrap(),
            0
        );
        let mut byte = [0];
        assert_eq!(platform::handle::read_at(image, &mut byte, 0).unwrap(), 1);
        assert_eq!(byte, [0x7f]);
        if let Some((proxy, revoked, worker)) = delayed {
            assert!(revoked.load(Ordering::Acquire));
            platform::handle::close(proxy).unwrap();
            worker.join().unwrap();
        }
        for handle in [image, pair.read, pair.write] {
            platform::handle::close(handle).unwrap();
        }
        unsafe {
            _exit(0);
        }
    }

    pub fn run() {
        if platform::handle::inherited(MARKER).is_ok() {
            platform::io::stdout(b"exec-authority: FAIL stale permit replaced image\n").unwrap();
            unsafe {
                _exit(99);
            }
        }
        platform::io::stdout(b"exec-authority: starting native revocation checks\n").unwrap();
        for (case, name) in [
            "revoked permit rejected before invalid image lookup",
            "revoked permit rejected with a valid image",
            "revocation during image read rejected before commit",
        ]
        .iter()
        .enumerate()
        {
            let pid = unsafe { fork() };
            assert!(pid >= 0);
            if pid == 0 {
                child(case);
            }
            let mut status = 0;
            assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
            assert_eq!(status, 0, "native case {case}");
            platform::io::stdout(format!("exec-authority: PASS {name}\n").as_bytes()).unwrap();
        }
    }
}

#[cfg(target_os = "mochios")]
fn main() {
    native::run();
}
