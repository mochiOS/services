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
pub mod ipc {
    pub fn endpoint_execution_identity(endpoint: u64) -> Result<mnu_abi::ExecutionIdentity, u64> {
        match endpoint {
            0x4000_0005 => Ok(mnu_abi::ExecutionIdentity {
                process_id: 90,
                thread_id: 9,
            }),
            8 => Err(mnu_abi::EACCES),
            9 => Err(mnu_abi::ESRCH),
            _ => Err(mnu_abi::EINVAL),
        }
    }
}
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
fn execution_identity_reads_only_caller_or_authenticated_endpoint_and_has_no_policy_fields() {
    use production::identity_read;
    assert_eq!(std::mem::size_of::<mnu_abi::ExecutionIdentity>(), 16);
    assert_eq!(
        std::mem::offset_of!(mnu_abi::ExecutionIdentity, thread_id),
        8
    );
    for length in [0, 15, 17, u64::MAX] {
        assert_eq!(identity_read(1, length, 0), mnu_abi::EINVAL);
    }
    assert_eq!(COPIES.load(Ordering::Relaxed), 0);
    assert_eq!(identity_read(0, 16, 0), mnu_abi::EFAULT);
    for (thread, process) in [(7u64, 70u64), (9, 90)] {
        CURRENT.store(thread, Ordering::Relaxed);
        assert_eq!(identity_read(1, 16, 0), mnu_abi::SUCCESS);
        let bytes = BYTES.lock().unwrap();
        assert_eq!(&bytes[..8], &process.to_ne_bytes());
        assert_eq!(&bytes[8..], &thread.to_ne_bytes());
    }
    for missing in [0, 8] {
        CURRENT.store(missing, Ordering::Relaxed);
        assert_eq!(identity_read(1, 16, 0), mnu_abi::ESRCH);
    }
    assert_eq!(identity_read(1, 15, 0x4000_0005), mnu_abi::EINVAL);
    for (endpoint, error) in [
        (7, mnu_abi::EINVAL),
        (8, mnu_abi::EACCES),
        (9, mnu_abi::ESRCH),
    ] {
        let copies = COPIES.load(Ordering::Relaxed);
        assert_eq!(identity_read(1, 16, endpoint), error);
        assert_eq!(COPIES.load(Ordering::Relaxed), copies);
    }
    assert_eq!(identity_read(0, 16, 0x4000_0005), mnu_abi::EFAULT);
    assert_eq!(identity_read(1, 16, 0x4000_0005), mnu_abi::SUCCESS);
    assert_eq!(
        *BYTES.lock().unwrap(),
        [90u64.to_ne_bytes(), 9u64.to_ne_bytes()].concat()
    );
    let ipc = include_str!("../../../core/src/syscall/ipc.rs");
    let resolver = ipc
        .split("pub fn endpoint_execution_identity(")
        .nth(1)
        .unwrap()
        .split("pub fn endpoint_is_owned_by(")
        .next()
        .unwrap();
    assert!(resolver.contains("Capability::ProcessInspect"));
    assert!(resolver.contains("endpoint_record_from_handle(handle).ok_or(EINVAL)?"));
    assert!(!resolver.contains("security_context"));
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(!runtime.contains("SyscallNumber::GetThreadSecurityContext"));
    let source = include_str!("native_dictionary_read.c");
    assert!(source.contains(&format!(
        "EXECUTION_IDENTITY_READ = {}",
        mnu_abi::SyscallNumber::ExecutionIdentityRead as u64
    )));
}
