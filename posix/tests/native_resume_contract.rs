// Structural regression checks complement the native_clone_cow.c KVM probe;
// they do not execute the privilege-changing assembly on the host.
#[test]
fn resumed_register_value_flows_from_the_native_caller() {
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    assert!(dispatch.contains("process::clone_process(arg0)"));
    let process = include_str!("../../../core/src/syscall/process.rs");
    assert!(process.contains("fn clone_current_process(resume_rax: u64)"));
    assert!(process.contains("user_context,\n        resume_rax,\n        parent_fs,"));
    let thread = include_str!("../../../core/src/task/thread.rs");
    assert!(thread.contains("pub fn new_user_resume("));
    assert!(thread.contains("resume_usermode(user_context, rax, fs_base)"));
    assert!(!thread.contains("new_fork_child"));
    let usermode = include_str!("../../../core/src/task/usermode.rs");
    let resume = &usermode[usermode.find("pub unsafe fn resume_usermode(").unwrap()..];
    assert!(resume.contains("\"mov rax, [rax + {rax_offset}]\""));
    assert!(!resume.contains("xor eax, eax"));
    assert!(resume.find("mov rsi, [rax").unwrap() < resume.find("mov rax, [rax").unwrap());
}

#[test]
fn posix_zero_return_policy_is_explicit_in_userspace() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("raw_syscall1(syscall::SyscallNumber::ProcessClone, 0)"));
    assert!(!runtime.contains("raw_syscall0(syscall::SyscallNumber::ProcessClone)"));
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    assert!(platform.contains("clone_process(resume_rax: u64) -> syscall::RawSyscallResult"));
    assert!(platform.contains("raw_syscall1(syscall::SyscallNumber::ProcessClone, resume_rax)"));
}
