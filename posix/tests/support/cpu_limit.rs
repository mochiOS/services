use super::*;
use posix_service::cpu_limit::{Action, observe};

fn sample(user: u64, kernel: u64) -> mnu_abi::ProcessExecutionUsage {
    mnu_abi::ProcessExecutionUsage {
        user_ticks: user,
        kernel_ticks: kernel,
        ticks_per_second: 500,
        reserved: 0,
    }
}
fn set(service: &mut PosixService, peer: PeerIdentity, soft: u64, hard: u64) -> i32 {
    let mut bytes = [0; protocol::RESOURCE_LIMIT_REQUEST_LEN];
    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_CPU,
            flags: protocol::RESOURCE_LIMIT_SET,
            limit: protocol::ResourceLimit { soft, hard },
        },
        &mut bytes,
    )
    .unwrap();
    service
        .handle(
            peer,
            protocol::Header {
                opcode: protocol::OP_RESOURCE_LIMIT,
                ..Default::default()
            },
            &bytes,
        )
        .header
        .status
}

#[test]
fn exact_accounting_uses_user_plus_kernel_ticks_and_not_rounded_seconds() {
    let limit = protocol::ResourceLimit { soft: 1, hard: 5 };
    assert_eq!(observe(sample(400, 100), limit, None), Ok(Action::None));
    assert_eq!(
        observe(sample(400, 101), limit, None),
        Ok(Action::Notify {
            cpu_nanoseconds: 1_002_000_000
        })
    );
    assert_eq!(
        observe(sample(1000, 0), limit, Some(1_200_000_000)),
        Ok(Action::None)
    );
    assert_eq!(
        observe(sample(1100, 0), limit, Some(1_200_000_000)),
        Ok(Action::Notify {
            cpu_nanoseconds: 2_200_000_000
        })
    );
    assert_eq!(observe(sample(2501, 0), limit, None), Ok(Action::Terminate));
    assert_eq!(
        observe(
            sample(0, 0),
            protocol::ResourceLimit { soft: 0, hard: 0 },
            None
        ),
        Ok(Action::None)
    );
    assert_eq!(
        observe(
            sample(1, 0),
            protocol::ResourceLimit { soft: 0, hard: 0 },
            None
        ),
        Ok(Action::Terminate)
    );
}

#[test]
fn malformed_metrics_and_limits_fail_and_large_tick_totals_do_not_wrap() {
    let mut usage = sample(1, 1);
    usage.ticks_per_second = 0;
    assert_eq!(
        observe(usage, protocol::ResourceLimit::INFINITY, None),
        Err(-5)
    );
    usage.ticks_per_second = 500;
    usage.reserved = 1;
    assert_eq!(
        observe(usage, protocol::ResourceLimit::INFINITY, None),
        Err(-5)
    );
    assert_eq!(
        observe(
            sample(1, 1),
            protocol::ResourceLimit { soft: 2, hard: 1 },
            None
        ),
        Err(-22)
    );
    let usage = mnu_abi::ProcessExecutionUsage {
        user_ticks: u64::MAX,
        kernel_ticks: u64::MAX,
        ticks_per_second: 1,
        reserved: 0,
    };
    assert_eq!(
        observe(usage, protocol::ResourceLimit::INFINITY, None),
        Ok(Action::None)
    );
    assert_eq!(
        observe(
            usage,
            protocol::ResourceLimit {
                soft: 1,
                hard: u64::MAX - 1
            },
            None
        ),
        Ok(Action::Terminate)
    );
}

#[test]
fn live_service_generates_one_notice_per_additional_cpu_second() {
    let (mut service, _, _, child, _, mut processes) = orphan_family();
    assert!(!service.has_finite_cpu_limits());
    assert_eq!(set(&mut service, child, 1, 5), 0);
    assert!(service.has_finite_cpu_limits());
    processes.usage.insert(142, Ok(sample(600, 0)));
    assert_eq!(service.enforce_cpu_limits(&mut processes), Ok(1));
    assert_eq!(
        dequeue_signal(&mut service, child).signal,
        protocol::SIGNAL_XCPU
    );
    assert_eq!(service.enforce_cpu_limits(&mut processes), Ok(0));
    processes.usage.insert(142, Ok(sample(1000, 0)));
    assert_eq!(service.enforce_cpu_limits(&mut processes), Ok(0));
    processes.usage.insert(142, Ok(sample(1100, 0)));
    assert_eq!(service.enforce_cpu_limits(&mut processes), Ok(1));
    assert_eq!(
        dequeue_signal(&mut service, child).signal,
        protocol::SIGNAL_XCPU
    );
    assert!(processes.terminated.is_empty());
}

#[test]
fn hard_limit_terminates_without_target_cooperation_and_wait_reports_sigkill() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    assert_eq!(set(&mut service, child, 1, 2), 0);
    processes.usage.insert(142, Ok(sample(1001, 0)));
    assert_eq!(service.enforce_cpu_limits(&mut processes), Ok(1));
    assert_eq!(processes.terminated, [(142, 137)]);
    assert!(!service.has_finite_cpu_limits());
    assert_eq!(service.enforce_cpu_limits(&mut processes), Ok(0));
    let waited = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(waited.status, protocol::SIGNAL_KILL);
}

#[test]
fn failed_termination_is_retried_without_falsifying_an_ordinary_exit() {
    let (mut service, _, parent, child, mut fs, mut processes) = orphan_family();
    assert_eq!(set(&mut service, child, 0, 0), 0);
    processes.usage.insert(142, Ok(sample(1, 0)));
    processes.terminate_error = Some(-5);
    assert_eq!(service.enforce_cpu_limits(&mut processes), Err(-5));
    assert!(service.has_finite_cpu_limits());
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 7 });
    let waited = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(waited.status, 7 << 8);
}

#[test]
fn one_bad_process_sample_does_not_disable_another_process_budget() {
    let (mut service, _, parent, child, _, mut processes) = orphan_family();
    assert_eq!(set(&mut service, parent, 1, 5), 0);
    assert_eq!(set(&mut service, child, 1, 5), 0);
    processes.usage.insert(141, Err(-5));
    processes.usage.insert(142, Ok(sample(600, 0)));
    assert_eq!(service.enforce_cpu_limits(&mut processes), Err(-5));
    assert_eq!(
        dequeue_signal(&mut service, child).signal,
        protocol::SIGNAL_XCPU
    );
    assert_eq!(service.enforce_cpu_limits(&mut processes), Err(-5));
    assert_eq!(dequeue_signal(&mut service, child).signal, 0);
}

#[test]
fn only_a_successful_limit_change_rearms_soft_notification() {
    let (mut service, _, _, child, _, mut processes) = orphan_family();
    assert_eq!(set(&mut service, child, 1, 5), 0);
    processes.usage.insert(142, Ok(sample(600, 0)));
    assert_eq!(service.enforce_cpu_limits(&mut processes), Ok(1));
    assert_eq!(
        dequeue_signal(&mut service, child).signal,
        protocol::SIGNAL_XCPU
    );
    assert_eq!(set(&mut service, child, 3, 2), -22);
    assert_eq!(service.enforce_cpu_limits(&mut processes), Ok(0));
    assert_eq!(set(&mut service, child, 1, 5), 0);
    assert_eq!(service.enforce_cpu_limits(&mut processes), Ok(1));
    assert_eq!(
        dequeue_signal(&mut service, child).signal,
        protocol::SIGNAL_XCPU
    );
}

#[test]
fn reactor_deadline_includes_cpu_sweeps_without_waiting_for_new_rpcs() {
    let main = include_str!("../../src/main.rs");
    assert!(main.contains("service.enforce_cpu_limits(&mut processes)"));
    assert!(main.contains("deadline.min(cpu_deadline)"));
    assert!(
        main.find("service.enforce_cpu_limits").unwrap()
            < main
                .find("deliver_signal_notifications(&mut service")
                .unwrap()
    );
}
