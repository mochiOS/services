use std::sync::atomic::{AtomicU64, Ordering};

static CURRENT: AtomicU64 = AtomicU64::new(7);
static COPIES: AtomicU64 = AtomicU64::new(0);
static BYTES: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

pub mod task {
    #[derive(Clone, Copy)]
    pub struct Id(u64);
    impl Id {
        pub fn as_u64(self) -> u64 {
            self.0
        }
    }
    pub struct Thread(Id);
    impl Thread {
        pub fn process_id(&self) -> Id {
            self.0
        }
    }
    pub fn current_thread_id() -> Option<Id> {
        match super::CURRENT.load(super::Ordering::Relaxed) {
            0 => None,
            id => Some(Id(id)),
        }
    }
    pub fn with_thread<T>(id: Id, operation: impl FnOnce(&Thread) -> T) -> Option<T> {
        match id.0 {
            7 => Some(operation(&Thread(Id(70)))),
            9 => Some(operation(&Thread(Id(90)))),
            _ => None,
        }
    }
}
pub const EINVAL: u64 = mnu_abi::EINVAL;
pub const ESRCH: u64 = mnu_abi::ESRCH;
pub fn copy_to_user(address: u64, bytes: &[u8]) -> Result<(), u64> {
    COPIES.fetch_add(1, Ordering::Relaxed);
    if address == 0 {
        return Err(mnu_abi::EFAULT);
    }
    *BYTES.lock().unwrap() = bytes.to_vec();
    Ok(())
}
// Compile the real kernel implementation, not a model of its checks.
#[path = "../../../core/src/syscall/execution.rs"]
mod production;

#[test]
fn execution_identity_is_exact_caller_only_and_has_no_policy_fields() {
    use production::identity_read;
    assert_eq!(std::mem::size_of::<mnu_abi::ExecutionIdentity>(), 16);
    assert_eq!(
        std::mem::offset_of!(mnu_abi::ExecutionIdentity, thread_id),
        8
    );
    for length in [0, 15, 17, u64::MAX] {
        assert_eq!(identity_read(1, length), mnu_abi::EINVAL);
    }
    assert_eq!(COPIES.load(Ordering::Relaxed), 0);
    assert_eq!(identity_read(0, 16), mnu_abi::EFAULT);
    for (thread, process) in [(7u64, 70u64), (9, 90)] {
        CURRENT.store(thread, Ordering::Relaxed);
        assert_eq!(identity_read(1, 16), mnu_abi::SUCCESS);
        let bytes = BYTES.lock().unwrap();
        assert_eq!(&bytes[..8], &process.to_ne_bytes());
        assert_eq!(&bytes[8..], &thread.to_ne_bytes());
    }
    for missing in [0, 8] {
        CURRENT.store(missing, Ordering::Relaxed);
        assert_eq!(identity_read(1, 16), mnu_abi::ESRCH);
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(!runtime.contains("SyscallNumber::GetThreadSecurityContext"));
    let source = include_str!("native_dictionary_read.c");
    assert!(source.contains(&format!(
        "EXECUTION_IDENTITY_READ = {}",
        mnu_abi::SyscallNumber::ExecutionIdentityRead as u64
    )));
}
