//! Production syscall admission with controlled copy, stack and scheduler
//! boundaries. This does not execute a new thread or emulate context switching.
#![allow(dead_code)]
use mnu_abi::status::Error;
use std::cell::{Cell, RefCell};

mod types {
    pub use mnu_abi::{EFAULT, EINVAL, EPERM};
}
mod capability {
    pub enum Capability {
        ProcessInspect,
    }
}
thread_local! {
    static COPY_ERROR: Cell<Option<Error>> = const { Cell::new(None) };
    static BAD_ADDRESS: Cell<u64> = const { Cell::new(0) };
    static CURRENT: Cell<bool> = const { Cell::new(true) };
    static PRESENT: Cell<bool> = const { Cell::new(true) };
    static TRANSITION: Cell<bool> = const { Cell::new(false) };
    static STACK_FAILURE: Cell<bool> = const { Cell::new(false) };
    static QUEUE_FAILURE: Cell<bool> = const { Cell::new(false) };
    static EVENTS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    static CREATED: Cell<Option<(task::thread::SyscallUserContext,u64,u64)>> =
        const { Cell::new(None) };
}
fn event(value: &'static str) {
    EVENTS.with_borrow_mut(|events| events.push(value));
}
mod config {
    pub struct Exec {
        pub kernel_thread_stack_size: usize,
    }
    pub struct Config {
        pub exec: Exec,
    }
    pub fn kernel() -> Config {
        Config {
            exec: Exec {
                kernel_thread_stack_size: 8192,
            },
        }
    }
}
mod task {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct ThreadId(pub u64);
    impl ThreadId {
        pub fn as_u64(self) -> u64 {
            self.0
        }
    }
    pub type ProcessId = u64;
    pub enum PrivilegeLevel {
        Core,
        Service,
        User,
    }
    pub struct Process;
    impl Process {
        pub fn privilege(&self) -> PrivilegeLevel {
            PrivilegeLevel::User
        }
        pub fn page_table(&self) -> Option<u64> {
            Some(0x9000)
        }
    }
    pub mod thread {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct SyscallUserContext {
            pub rip: u64,
            pub rsp: u64,
            pub rflags: u64,
            pub rdi: u64,
            pub rsi: u64,
            pub rdx: u64,
            pub r8: u64,
            pub r9: u64,
            pub r10: u64,
            pub rbp: u64,
            pub rbx: u64,
            pub r12: u64,
            pub r13: u64,
            pub r14: u64,
            pub r15: u64,
            pub rcx: u64,
            pub r11: u64,
        }
    }
    pub struct Thread;
    impl Thread {
        pub fn id(&self) -> ThreadId {
            ThreadId(7)
        }
        pub fn process_id(&self) -> ProcessId {
            3
        }
        pub fn name(&self) -> &str {
            "test"
        }
        pub fn new_user_resume(
            pid: ProcessId,
            context: thread::SyscallUserContext,
            rax: u64,
            tls: u64,
            stack: u64,
            size: usize,
        ) -> Self {
            assert_eq!((pid, stack, size), (3, 0xa000, 8192));
            assert!(super::TRANSITION.get());
            super::event("construct");
            super::CREATED.set(Some((context, rax, tls)));
            Self
        }
    }
    pub fn yield_now() {}
    pub fn current_thread_id() -> Option<ThreadId> {
        super::CURRENT.get().then_some(ThreadId(7))
    }
    pub fn with_thread<T>(tid: ThreadId, operation: impl FnOnce(&Thread) -> T) -> Option<T> {
        assert_eq!(tid.0, 7);
        super::PRESENT.get().then(|| operation(&Thread))
    }
    pub fn for_each_thread(mut operation: impl FnMut(&Thread)) {
        operation(&Thread);
    }
    pub fn with_process<T>(pid: ProcessId, operation: impl FnOnce(&Process) -> T) -> Option<T> {
        assert_eq!(pid, 3);
        Some(operation(&Process))
    }
    pub mod image_transition {
        pub struct Creation;
        impl Drop for Creation {
            fn drop(&mut self) {
                assert!(crate::TRANSITION.replace(false));
                crate::event("release gate");
            }
        }
        pub fn begin_thread_creation(pid: super::ProcessId) -> Option<Creation> {
            assert_eq!(pid, 3);
            crate::event("admit");
            if crate::TRANSITION.replace(true) {
                None
            } else {
                Some(Creation)
            }
        }
    }
    pub fn allocate_kernel_stack_in_table(size: usize, table: u64) -> Option<u64> {
        assert_eq!((size, table), (8192, 0x9000));
        super::event("allocate");
        (!super::STACK_FAILURE.get()).then_some(0xa000)
    }
    pub fn free_kernel_stack(stack: u64) {
        assert_eq!(stack, 0xa000);
        super::event("free");
    }
    pub fn add_thread(_: Thread) -> Option<ThreadId> {
        super::event("publish");
        (!super::QUEUE_FAILURE.get()).then_some(ThreadId(19))
    }
}
mod syscall {
    pub use mnu_abi::ENOENT;
    pub mod security {
        pub fn caller_has_any_capability(_: &[crate::capability::Capability]) -> bool {
            true
        }
        pub fn caller_is_core() -> bool {
            false
        }
    }
    pub fn validate_user_ptr(pointer: u64, length: u64) -> bool {
        pointer != 0 && pointer != crate::BAD_ADDRESS.get() && pointer.checked_add(length).is_some()
    }
    pub fn copy_from_user_native(pointer: u64, bytes: &mut [u8]) -> Result<(), crate::Error> {
        crate::event("copy");
        if let Some(error) = crate::COPY_ERROR.get() {
            return Err(error);
        }
        // Tests pass a live ThreadCreateContext; bad pointers use injected errors.
        unsafe {
            std::ptr::copy_nonoverlapping(pointer as *const u8, bytes.as_mut_ptr(), bytes.len());
        }
        Ok(())
    }
    pub fn copy_from_user(_: u64, _: &mut [u8]) -> Result<(), u64> {
        unreachable!()
    }
}
#[path = "../../../core/src/syscall/task.rs"]
mod native;

fn reset() {
    COPY_ERROR.set(None);
    BAD_ADDRESS.set(0);
    CURRENT.set(true);
    PRESENT.set(true);
    TRANSITION.set(false);
    STACK_FAILURE.set(false);
    QUEUE_FAILURE.set(false);
    EVENTS.with_borrow_mut(Vec::clear);
    CREATED.set(None);
}
fn context() -> mnu_abi::ThreadCreateContext {
    mnu_abi::ThreadCreateContext {
        entry: 0x1000,
        stack_pointer: 0x8000,
        argument: 0xdead,
        thread_local_base: 0x2000,
        ..Default::default()
    }
}
fn create(context: &mnu_abi::ThreadCreateContext) -> u64 {
    native::thread_create(
        context as *const _ as u64,
        std::mem::size_of_val(context) as u64,
    )
}
#[test]
fn invalid_input_and_copy_failures_do_not_reach_scheduler_admission() {
    reset();
    assert_eq!(
        native::thread_create(0, 176),
        Error::InvalidAddress.into_raw()
    );
    for length in [0, 64, 175, 177, u64::MAX] {
        assert_eq!(
            native::thread_create(0, length),
            Error::InvalidArgument.into_raw()
        );
    }
    EVENTS.with_borrow(|events| assert!(events.is_empty()));
    for error in [
        Error::InvalidAddress,
        Error::ResourceUnavailable,
        Error::BackingFailure,
    ] {
        reset();
        COPY_ERROR.set(Some(error));
        assert_eq!(create(&context()), error.into_raw());
        EVENTS.with_borrow(|events| assert_eq!(events, &["copy"]));
    }
    for index in 0..6 {
        reset();
        let mut context = context();
        match index {
            0 => context.entry = 0,
            1 => context.stack_pointer = 15,
            2 => context.flags = 1,
            index => context.reserved[index - 3] = 1,
        }
        assert_eq!(create(&context), Error::InvalidArgument.into_raw());
        EVENTS.with_borrow(|events| assert_eq!(events, &["copy"]));
    }
    for address in [0x1000, 0x7ff0, 0x2000] {
        reset();
        BAD_ADDRESS.set(address);
        assert_eq!(create(&context()), Error::InvalidAddress.into_raw());
        EVENTS.with_borrow(|events| assert_eq!(events, &["copy"]));
    }
}
#[test]
fn failed_admission_releases_only_resources_actually_acquired() {
    for missing in [0, 1] {
        reset();
        if missing == 0 {
            CURRENT.set(false)
        } else {
            PRESENT.set(false)
        }
        assert_eq!(create(&context()), Error::NotReady.into_raw());
        EVENTS.with_borrow(|events| assert_eq!(events, &["copy"]));
    }
    reset();
    TRANSITION.set(true);
    assert_eq!(create(&context()), Error::NotReady.into_raw());
    assert!(TRANSITION.get());
    EVENTS.with_borrow(|events| assert_eq!(events, &["copy", "admit"]));
    reset();
    STACK_FAILURE.set(true);
    assert_eq!(create(&context()), Error::ResourceUnavailable.into_raw());
    assert!(!TRANSITION.get());
    EVENTS.with_borrow(|events| assert_eq!(events, &["copy", "admit", "allocate", "release gate"]));
    reset();
    QUEUE_FAILURE.set(true);
    assert_eq!(create(&context()), Error::ResourceUnavailable.into_raw());
    assert!(!TRANSITION.get());
    EVENTS.with_borrow(|events| {
        assert_eq!(
            events,
            &[
                "copy",
                "admit",
                "allocate",
                "construct",
                "publish",
                "free",
                "release gate"
            ]
        )
    });
}
#[test]
fn success_transfers_stack_and_preserves_explicit_registers_with_fixed_flags() {
    reset();
    let mut context = context();
    context.registers = mnu_abi::ThreadInitialRegisters {
        rax: 1,
        rbx: 2,
        rcx: 3,
        rdx: 4,
        rsi: 5,
        rbp: 6,
        r8: 7,
        r9: 8,
        r10: 9,
        r11: 10,
        r12: 11,
        r13: 12,
        r14: 13,
        r15: 14,
    };
    assert_eq!(create(&context), 19);
    assert!(!TRANSITION.get());
    EVENTS.with_borrow(|events| {
        assert_eq!(
            events,
            &[
                "copy",
                "admit",
                "allocate",
                "construct",
                "publish",
                "release gate"
            ]
        )
    });
    let (actual, rax, tls) = CREATED.get().unwrap();
    assert_eq!(
        (actual.rip, actual.rsp, actual.rdi, rax, tls),
        (
            context.entry,
            context.stack_pointer,
            context.argument,
            1,
            context.thread_local_base
        )
    );
    assert_eq!(actual.rflags, 0x202);
    assert_eq!(
        [
            actual.rbx, actual.rcx, actual.rdx, actual.rsi, actual.rbp, actual.r8, actual.r9,
            actual.r10, actual.r11, actual.r12, actual.r13, actual.r14, actual.r15
        ],
        [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
    );
}
