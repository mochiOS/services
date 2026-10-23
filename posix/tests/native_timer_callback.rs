//! Actual deferred IPC delivery; does not claim libc SIGEV_THREAD dispatch.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("timer-callback: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as platform;
    use mochios_posix_client::Client;
    use mochios_posix_protocol::{
        self as protocol,
        process_timer::{Clock, Notification, Value},
    };
    use std::sync::{Arc, Barrier};

    let client = Client::from_launch_context().unwrap();
    client
        .thread_signal_mask(protocol::SIGNAL_MASK_BLOCK, u64::MAX)
        .unwrap();
    let first = client
        .timer_create(Clock::Monotonic, Notification::Thread { cookie: 123 })
        .unwrap();
    let gate = Arc::new(Barrier::new(2));
    let worker_gate = gate.clone();
    let worker = std::thread::spawn(move || {
        let client = Client::from_launch_context().unwrap();
        client
            .thread_signal_mask(protocol::SIGNAL_MASK_BLOCK, u64::MAX)
            .unwrap();
        worker_gate.wait();
        let event = client.timer_wait_callback().unwrap();
        assert_eq!((event.timer, event.cookie, event.overrun), (first, 123, 0));
    });
    gate.wait();
    // The timer is unarmed while the other thread enters its blocking RPC.
    std::thread::sleep(std::time::Duration::from_millis(50));
    client
        .timer_set(
            first,
            false,
            Value {
                remaining_ns: 100_000_000,
                interval_ns: 0,
            },
        )
        .unwrap();
    worker.join().unwrap();
    client.timer_delete(first).unwrap();
    platform::io::stdout(
        b"timer-callback: PASS deferred reply wakes blocked receiver with all signals masked\n",
    )
    .unwrap();

    // Equal cookies are never authority: the returned timer ID is independent.
    let first = client
        .timer_create(Clock::Monotonic, Notification::Thread { cookie: 456 })
        .unwrap();
    let second = client
        .timer_create(Clock::Monotonic, Notification::Thread { cookie: 456 })
        .unwrap();
    for id in [first, second] {
        client
            .timer_set(
                id,
                false,
                Value {
                    remaining_ns: 1,
                    interval_ns: 10_000_000,
                },
            )
            .unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    let one = client.timer_wait_callback().unwrap();
    let two = client.timer_wait_callback().unwrap();
    assert_eq!((one.timer, two.timer), (first, second));
    assert_eq!((one.cookie, two.cookie), (456, 456));
    assert!(one.overrun > 0 && two.overrun > 0);
    assert_eq!(client.timer_overrun(first).unwrap(), one.overrun);
    assert_eq!(client.timer_overrun(second).unwrap(), two.overrun);
    for id in [first, second] {
        client.timer_delete(id).unwrap();
    }
    platform::io::stdout(
        b"timer-callback: PASS independent timer identity, fair selection and accepted overruns\n",
    )
    .unwrap();

    let deleted = client
        .timer_create(Clock::Monotonic, Notification::Thread { cookie: 789 })
        .unwrap();
    client
        .timer_set(
            deleted,
            false,
            Value {
                remaining_ns: 1,
                interval_ns: 0,
            },
        )
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    client.timer_delete(deleted).unwrap();
    let replacement = client
        .timer_create(Clock::Monotonic, Notification::Thread { cookie: 790 })
        .unwrap();
    assert_ne!(deleted, replacement);
    client
        .timer_set(
            replacement,
            false,
            Value {
                remaining_ns: 1,
                interval_ns: 0,
            },
        )
        .unwrap();
    let event = client.timer_wait_callback().unwrap();
    assert_eq!((event.timer, event.cookie), (replacement, 790));
    client.timer_delete(replacement).unwrap();
    platform::io::stdout(b"timer-callback: PASS deletion discards pending callback without retargeting replacement\n").unwrap();
}
