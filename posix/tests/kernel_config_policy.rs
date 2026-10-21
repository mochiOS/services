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
    pub mod fs {
        pub fn kernel_read_initfs(_: &str) -> Option<Vec<u8>> {
            Some(include_bytes!("../../../core/examples/fs/rootfs/config/kernel.conf").to_vec())
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
