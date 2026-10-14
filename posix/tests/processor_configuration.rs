use mnu_abi::{ProcessorInfo, SyscallNumber};
use mochios_posix_client::configuration::processor_count;

#[test]
fn processor_snapshot_is_generic_fixed_layout_and_sysconf_translation_is_local() {
    assert_eq!(std::mem::size_of::<ProcessorInfo>(), 16);
    assert_eq!(std::mem::align_of::<ProcessorInfo>(), 4);
    assert_eq!(SyscallNumber::ProcessorDescribe as u64, 692);
    for (configured, online) in [(1, 1), (2, 2), (8, 3), (64, 32), (u32::MAX, 1)] {
        let info = ProcessorInfo {
            configured,
            online,
            reserved: [0; 2],
        };
        assert_eq!(processor_count(9, info), Ok(configured));
        assert_eq!(processor_count(10, info), Ok(online));
        assert_eq!(processor_count(8, info), Err(-22));
    }
}

#[test]
fn absent_or_inconsistent_processor_information_is_not_faked_as_one_cpu() {
    for info in [
        ProcessorInfo::default(),
        ProcessorInfo {
            configured: 2,
            online: 0,
            reserved: [0; 2],
        },
        ProcessorInfo {
            configured: 2,
            online: 3,
            reserved: [0; 2],
        },
        ProcessorInfo {
            configured: 2,
            online: 2,
            reserved: [1, 0],
        },
        ProcessorInfo {
            configured: 2,
            online: 2,
            reserved: [0, 1],
        },
    ] {
        assert_eq!(processor_count(9, info), Err(-5));
        assert_eq!(processor_count(10, info), Err(-5));
    }
}
