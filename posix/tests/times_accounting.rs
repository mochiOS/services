use mochios_posix_client::newlib_errno::{EIO, EOVERFLOW};
use mochios_posix_client::{Client, Transport, accounting};
use mochios_posix_protocol as protocol;

#[test]
fn clock_units_match_sdk_and_keep_native_precision_until_conversion() {
    assert_eq!(accounting::CLOCK_TICKS_PER_SECOND, 1000);
    assert_eq!(
        mochios_posix_client::configuration::local_limit(2),
        Some(1000)
    );
    assert_eq!(accounting::clock_ticks(1, 500), Ok(2));
    assert_eq!(accounting::clock_ticks(10, 3), Ok(3333));
    assert_eq!(
        accounting::clock_ticks(2 * u128::from(u64::MAX), u64::MAX),
        Ok(2000)
    );
    assert_eq!(accounting::clock_ticks(0, 0), Ok(0));
    assert_eq!(accounting::clock_ticks(1u128 << 63, 1000), Ok(1u64 << 63));
    assert_eq!(
        accounting::clock_ticks(u128::from(u64::MAX), 1000),
        Err(EOVERFLOW)
    );
    assert_eq!(accounting::clock_ticks(1, 0), Err(EIO));
    assert_eq!(accounting::clock_ticks(u128::MAX, 1), Err(EOVERFLOW));
    assert_eq!(accounting::elapsed_clock_ticks(7, 123_456_789), Ok(7123));
    assert_eq!(accounting::elapsed_clock_ticks(0, 1_000_000_000), Err(EIO));
    assert_eq!(accounting::elapsed_clock_ticks(u64::MAX, 0), Err(EOVERFLOW));
    let sdk = include_str!("../../../libraries/newlib/newlib/libc/include/time.h");
    assert!(sdk.contains("#define _CLOCKS_PER_SEC_ 1000"));
    let libc = include_str!("../../../libraries/libc/newlib/mochios.rs");
    assert!(libc.contains("pub type clock_t = c_ulong;"));
    let types = include_str!("../../../libraries/newlib/newlib/libc/include/sys/_types.h");
    assert!(types.lines().any(|line| line.split_whitespace().take(3).eq(["#define", "_CLOCK_T_", "unsigned"])));
}

#[test]
fn child_accounting_wire_is_exact_and_preserves_wide_counters() {
    let usage = protocol::WaitedChildCpuUsage {
        user_ticks: (1u128 << 100) + 7,
        kernel_ticks: (1u128 << 80) + 11,
        ticks_per_second: 500,
    };
    let mut bytes = [0; protocol::WAITED_CHILD_CPU_USAGE_LEN];
    protocol::encode_waited_child_cpu_usage(usage, &mut bytes).unwrap();
    assert_eq!(&bytes[..16], &usage.user_ticks.to_le_bytes());
    assert_eq!(&bytes[16..32], &usage.kernel_ticks.to_le_bytes());
    assert_eq!(protocol::decode_waited_child_cpu_usage(&bytes), Ok(usage));
    assert!(protocol::decode_waited_child_cpu_usage(&bytes[..39]).is_err());
    assert!(protocol::decode_waited_child_cpu_usage(&[0; 41]).is_err());
    assert!(protocol::encode_waited_child_cpu_usage(usage, &mut bytes[..39]).is_err());
    assert!(
        protocol::encode_waited_child_cpu_usage(
            protocol::WaitedChildCpuUsage {
                ticks_per_second: 0,
                ..usage
            },
            &mut bytes
        )
        .is_err()
    );
    bytes[32..].fill(0);
    assert!(protocol::decode_waited_child_cpu_usage(&bytes).is_err());
    protocol::encode_waited_child_cpu_usage(protocol::WaitedChildCpuUsage::default(), &mut bytes)
        .unwrap();
    assert_eq!(
        protocol::decode_waited_child_cpu_usage(&bytes),
        Ok(protocol::WaitedChildCpuUsage::default())
    );
}

struct CpuReply;
impl Transport for CpuReply {
    type Error = ();
    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_WAITED_CHILD_CPU_USAGE);
        assert_eq!(header.flags, 0);
        assert!(
            payload.is_empty(),
            "no PID, TID, FD or pointer may be supplied"
        );
        let mut bytes = [0; protocol::WAITED_CHILD_CPU_USAGE_LEN];
        protocol::encode_waited_child_cpu_usage(
            protocol::WaitedChildCpuUsage {
                user_ticks: 17,
                kernel_ticks: 23,
                ticks_per_second: 500,
            },
            &mut bytes,
        )
        .unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: bytes.len() as u32,
                ..Default::default()
            },
            &bytes,
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_queries_only_its_authenticated_process_without_transferring_local_pointers() {
    let result = Client::new(CpuReply).waited_child_cpu_usage().unwrap();
    assert_eq!(
        (
            result.user_ticks,
            result.kernel_ticks,
            result.ticks_per_second
        ),
        (17, 23, 500)
    );
}

#[test]
fn runtime_writes_only_after_all_samples_and_conversion_succeed_and_clock_stays_native() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let times = source
        .split("fn _times(")
        .nth(1)
        .unwrap()
        .split("fn elapsed_clock_ticks(")
        .next()
        .unwrap();
    assert!(times.contains("syscall::execution::usage(None)"));
    assert!(times.contains(".waited_child_cpu_usage()"));
    assert!(
        times.find("tms_cstime: clock_ticks").unwrap()
            < times.find("time_memory::write_accounting(buf, value)").unwrap()
    );
    assert!(!times.contains("SyscallNumber::TimeNow"));
    let clock = source
        .split("fn clock()")
        .nth(1)
        .unwrap()
        .split("fn times(")
        .next()
        .unwrap();
    assert!(clock.contains("syscall::execution::usage(None)"));
    assert!(!clock.contains("posix_client()"));
    assert!(!clock.contains("_times("));
}
