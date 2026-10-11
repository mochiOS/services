// Hardware double for native_user_return.rs; not a standalone Cargo test.
extern crate self as x86_64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
static INTERRUPTS: AtomicBool = AtomicBool::new(true);
static ACTIVE_TABLE: AtomicU64 = AtomicU64::new(0);
const EXPECTED_TABLE: u64 = 0x1000;

pub mod instructions {
    pub mod interrupts {
        pub fn disable() {
            crate::INTERRUPTS.store(false, crate::Ordering::SeqCst);
        }
    }
}
pub mod mem {
    pub mod gdt {
        pub fn user_code_selector() -> u16 {
            0x23
        }
        pub fn user_data_selector() -> u16 {
            0x1b
        }
    }
    pub mod paging {
        pub fn switch_page_table(table: u64) {
            crate::ACTIVE_TABLE.store(table, crate::Ordering::SeqCst);
            // A ring-0 timer IRQ returns without KPTI's user-CR3 restoration.
            if crate::INTERRUPTS.load(crate::Ordering::SeqCst) {
                crate::ACTIVE_TABLE.store(0x2000, crate::Ordering::SeqCst);
            }
        }
    }
}
pub mod cpu {
    pub fn write_fs_base(_: u64) {}
}
pub mod task {
    pub mod thread {
        #[derive(Default, Copy, Clone)]
        pub struct SyscallUserContext {
            pub rip: u64,
            pub rsp: u64,
            pub rflags: u64,
            pub rcx: u64,
            pub r11: u64,
            pub rbx: u64,
            pub rbp: u64,
            pub r12: u64,
            pub r13: u64,
            pub r14: u64,
            pub r15: u64,
            pub rdi: u64,
            pub rsi: u64,
            pub rdx: u64,
            pub r8: u64,
            pub r9: u64,
            pub r10: u64,
        }
    }
    pub struct Thread;
    impl Thread {
        pub fn process_id(&self) -> u64 {
            7
        }
        pub fn fs_base(&self) -> u64 {
            0
        }
    }
    pub struct Process;
    impl Process {
        pub fn page_table(&self) -> Option<u64> {
            Some(crate::EXPECTED_TABLE)
        }
    }
    pub fn current_thread_id() -> Option<u64> {
        Some(1)
    }
    pub fn with_thread<T>(_: u64, f: impl FnOnce(&Thread) -> T) -> Option<T> {
        Some(f(&Thread))
    }
    pub fn with_process<T>(_: u64, f: impl FnOnce(&Process) -> T) -> Option<T> {
        Some(f(&Process))
    }
}
macro_rules! asm {
    ($($tokens:tt)*) => {{
        // Model the late CLI in the original final assembly, then trap iret.
        crate::instructions::interrupts::disable();
        std::panic::panic_any("iret");
    }};
}
macro_rules! debug {
    ($($tokens:tt)*) => {};
}
pub(crate) use debug;
mod usermode { /* PRODUCTION */
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(|| unsafe {
        usermode::resume_usermode(task::thread::SyscallUserContext::default(), 0, 0)
    });
    assert_eq!(result.unwrap_err().downcast_ref::<&str>(), Some(&"iret"));
    assert_eq!(ACTIVE_TABLE.load(Ordering::SeqCst), EXPECTED_TABLE);
    assert!(!INTERRUPTS.load(Ordering::SeqCst));
}
