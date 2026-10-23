//! Real IPC/stream completion probe, run in the existing compositor test slot.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("cpu-sleep: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as platform;
    use mochios_posix_client::{Client, ClientError};
    use mochios_posix_protocol::{self as protocol, cpu_sleep as wire};
    use std::sync::{Arc, Barrier};

    fn cpu() -> u128 {
        posix_service::process_timer_request::cpu_nanoseconds(
            platform::process::execution_usage(None).unwrap(),
        )
        .unwrap()
    }
    fn complete(handle: u32) {
        let deadline = platform::time::monotonic_nanoseconds().unwrap() + 5_000_000_000;
        let mut items = [mnu_abi::HandleWaitItem {
            handle,
            interests: mnu_abi::HANDLE_SIGNAL_READABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
            ..Default::default()
        }];
        platform::process::wait_many(&mut items, deadline).unwrap();
        let mut packet = [0; wire::COMPLETION_LEN];
        let count = platform::handle::read(handle, &mut packet).unwrap();
        assert_eq!(count, packet.len());
        assert_eq!(wire::decode_completion(&packet), Ok(Ok(())));
        items[0].interests = mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
        platform::process::wait_many(&mut items, deadline).unwrap();
        assert_eq!(platform::handle::read(handle, &mut packet).unwrap(), 0);
        platform::handle::close(handle).unwrap();
    }

    platform::io::stdout(b"cpu-sleep: starting native IPC/Handle checks\n").unwrap();
    let client = Client::from_launch_context().unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let released = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let worker_barrier = barrier.clone();
    let worker_deadline = released.clone();
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        let deadline = u128::from(worker_deadline.load(std::sync::atomic::Ordering::Acquire));
        let mut value = 1u64;
        while cpu() < deadline {
            for n in 0..100_000 {
                value = std::hint::black_box(value.wrapping_mul(17).wrapping_add(n));
            }
        }
        std::hint::black_box(value);
    });
    let pending = client
        .begin_process_cpu_sleep(wire::Request {
            process: 0,
            absolute: false,
            nanoseconds: 200_000_000,
        })
        .unwrap();
    assert_eq!(pending.completion.rights, wire::COMPLETION_RIGHTS);
    let handle = pending.completion.handle;
    let mut poll = [mnu_abi::HandleWaitItem {
        handle,
        interests: mnu_abi::HANDLE_SIGNAL_READABLE,
        ..Default::default()
    }];
    assert_eq!(
        platform::process::wait_many(&mut poll, mnu_abi::HANDLE_WAIT_POLL)
            .unwrap_err()
            .native_error(),
        Some(mnu_abi::status::Error::NotReady)
    );
    assert_eq!(
        platform::handle::write(handle, b"x")
            .unwrap_err()
            .native_error(),
        Some(mnu_abi::status::Error::AccessDenied)
    );
    assert_eq!(
        platform::handle::duplicate(handle, wire::COMPLETION_RIGHTS)
            .unwrap_err()
            .native_error(),
        Some(mnu_abi::status::Error::AccessDenied)
    );
    released.store(
        u64::try_from(pending.deadline_ns + 20_000_000).unwrap(),
        std::sync::atomic::Ordering::Release,
    );
    barrier.wait();
    complete(handle);
    assert!(cpu() >= pending.deadline_ns);
    worker.join().unwrap();
    let immediate = client
        .begin_process_cpu_sleep(wire::Request {
            process: 0,
            absolute: true,
            nanoseconds: 0,
        })
        .unwrap();
    assert_eq!(immediate.deadline_ns, 0);
    complete(immediate.completion.handle);
    platform::io::stdout(b"cpu-sleep: PASS CPU advancement wakes a sleeping owner, rights attenuation, atomic record and EOF\n").unwrap();

    // Saturate the first limit reached: the POSIX quota or native storage.
    // Native stream capacity can be smaller and is shared with other users.
    // Keep the chosen CPU deadline far beyond all diagnostic work.
    let mut abandoned = Vec::new();
    let mut rejected = None;
    for _ in 0..=posix_service::cpu_sleep::MAX_WAITS_PER_PROCESS {
        match client.begin_process_cpu_sleep(wire::Request {
            process: 0,
            absolute: false,
            nanoseconds: 1_000_000_000_000,
        }) {
            Ok(pending) => abandoned.push(pending.completion.handle),
            Err(ClientError::Remote(status @ (-12 | protocol::STATUS_EAGAIN))) => {
                rejected = Some(status);
                break;
            }
            Err(error) => panic!("unexpected CPU sleep admission failure: {error:?}"),
        }
    }
    assert!(!abandoned.is_empty());
    assert!(rejected.is_some(), "wait quota was not enforced");
    println!(
        "cpu-sleep: admission limit count={} status={}",
        abandoned.len(),
        rejected.unwrap()
    );
    for handle in abandoned {
        platform::handle::close(handle).unwrap();
    }
    let mut recovered = false;
    for _ in 0..100 {
        match client.begin_process_cpu_sleep(wire::Request {
            process: 0,
            absolute: false,
            nanoseconds: 0,
        }) {
            Ok(pending) => {
                complete(pending.completion.handle);
                recovered = true;
                break;
            }
            Err(ClientError::Remote(-12 | protocol::STATUS_EAGAIN)) => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(error) => panic!("CPU sleep recovery failed: {error:?}"),
        }
    }
    assert!(recovered);
    platform::io::stdout(
        b"cpu-sleep: PASS abandoned completion Handles release waiter quota without cancel RPC\n",
    )
    .unwrap();
}
