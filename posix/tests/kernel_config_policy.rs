//! Compile the actual kernel configuration parser on the host. Only boot I/O,
//! one-time initialization and the timer conversion are replaced here.
extern crate alloc;
extern crate self as spin;

pub struct Once<T>(std::sync::OnceLock<T>);
impl<T> Once<T> {
    pub const fn new() -> Self {
        Self(std::sync::OnceLock::new())
    }

    pub fn call_once(&self, initialize: impl FnOnce() -> T) -> &T {
        self.0.get_or_init(initialize)
    }
}

#[macro_export]
macro_rules! warn {
    ($($argument:tt)*) => { eprintln!($($argument)*) };
}

mod init {
    pub mod boot_data {
        pub fn boot_module_bytes() -> &'static [u8] {
            static MODULE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
            MODULE.get_or_init(|| {
                crate::module(include_bytes!(
                    "../../../core/examples/fs/rootfs/config/kernel.conf"
                ))
            })
        }
    }
}

mod interrupt {
    pub mod timer {
        pub fn ms_to_ticks_ceil(milliseconds: u64) -> u64 {
            milliseconds
        }
    }
}

#[allow(dead_code)]
mod config {
    include!("../../../core/src/config.rs");

    pub fn apply(config: &mut KernelConfig, key: &str, value: &str) {
        apply_key_value(config, key, value);
    }

    pub fn load(bytes: &[u8]) -> KernelConfig {
        load_kernel_config(bytes)
    }
}

fn module(configuration: &[u8]) -> Vec<u8> {
    use mnu_abi::boot_module as abi;
    let mut bytes = vec![0; abi::HEADER_LEN + configuration.len() + 8];
    bytes[..8].copy_from_slice(&abi::MAGIC);
    bytes[8..12].copy_from_slice(&abi::VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&(abi::HEADER_LEN as u32).to_le_bytes());
    for (offset, value) in [
        (16, abi::HEADER_LEN as u64),
        (24, (abi::HEADER_LEN + configuration.len()) as u64),
        (32, 8),
        (40, configuration.len() as u64),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[abi::HEADER_LEN..abi::HEADER_LEN + configuration.len()].copy_from_slice(configuration);
    bytes
}

#[test]
fn configuration_has_no_filesystem_service_retry_policy() {
    let source = include_str!("../../../core/src/config.rs");
    let example = include_str!("../../../core/examples/fs/rootfs/config/kernel.conf");
    for removed in ["FsConfig", "service_retry_count", "service_retry_ms"] {
        assert!(!source.contains(removed), "kernel retains {removed}");
        assert!(!example.contains(removed), "example retains {removed}");
    }
}

#[test]
fn generic_kernel_settings_still_load_and_validate_values() {
    let loaded = config::kernel();
    assert_eq!(loaded.ipc.mailbox_cap, 64);
    assert_eq!(loaded.ipc.max_msg_size, 4128);
    assert_eq!(loaded.exec.kernel_thread_stack_size, 32768);
    assert_eq!(loaded.cext.module_load_guard, 0x20_0000);

    let mut settings = config::KernelConfig::default();
    config::apply(&mut settings, "ipc.mailbox_cap", "128");
    config::apply(&mut settings, "exec.stack_aslr_max_pages", "0x80");
    config::apply(&mut settings, "scheduler.low_priority_threshold", "255");
    config::apply(&mut settings, "scheduler.low_priority_threshold", "256");
    config::apply(&mut settings, "ipc.mailbox_cap", "-1");
    config::apply(&mut settings, "unknown.setting", "999");
    assert_eq!(settings.ipc.mailbox_cap, 128);
    assert_eq!(settings.exec.stack_aslr_max_pages, 128);
    assert_eq!(settings.scheduler.low_priority_threshold, 255);
}

#[test]
fn boot_configuration_is_selected_by_range_without_any_filesystem_lookup() {
    let source = include_str!("../../../core/src/config.rs");
    for removed in [
        "kernel_read_initfs",
        "read_initfs",
        "/config/",
        "String::from_utf8",
    ] {
        assert!(
            !source.contains(removed),
            "configuration retained {removed}"
        );
    }
    let bytes = module(b"ipc.mailbox_cap=128\nexec.stack_aslr_max_pages=0x20\n");
    let loaded = config::load(&bytes);
    assert_eq!(loaded.ipc.mailbox_cap, 128);
    assert_eq!(loaded.exec.stack_aslr_max_pages, 32);

    // Even a plausible path or setting in the opaque resource prefix cannot
    // replace the descriptor-selected native configuration.
    let mut decoy = bytes;
    decoy.splice(64..64, [0u8; 128]);
    decoy[64..64 + b"/config/kernel.conf\nipc.mailbox_cap=999\n".len()]
        .copy_from_slice(b"/config/kernel.conf\nipc.mailbox_cap=999\n");
    decoy[16..24].copy_from_slice(&192u64.to_le_bytes());
    let image_offset = decoy.len() as u64 - 8;
    decoy[24..32].copy_from_slice(&image_offset.to_le_bytes());
    assert_eq!(config::load(&decoy).ipc.mailbox_cap, 128);
}

#[test]
fn absent_invalid_or_unrecognized_configuration_keeps_native_defaults() {
    let expected = config::KernelConfig::default();
    for bytes in [
        vec![],
        vec![0; 4096],
        module(b""),
        module(b"ipc.mailbox_cap=128\n\xff"),
        module(b"capability.path=/home;fs.read.user;fs.write.user;none\n"),
    ] {
        let loaded = config::load(&bytes);
        assert_eq!(loaded.ipc.mailbox_cap, expected.ipc.mailbox_cap);
        assert_eq!(loaded.ipc.max_msg_size, expected.ipc.max_msg_size);
    }
    let mut invalid = module(b"ipc.mailbox_cap=128\n");
    invalid[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        config::load(&invalid).ipc.mailbox_cap,
        expected.ipc.mailbox_cap
    );
}
