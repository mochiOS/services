// Structural regression checks complement the native_clone_cow.c KVM probe;
// they do not execute the privilege-changing assembly on the host.
#[test]
fn resumed_register_value_flows_from_the_native_caller() {
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    assert!(dispatch.contains("exec::process_create_syscall(arg0, arg1, arg2)"));
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    assert!(exec.contains("Thread::new_user_resume("));
    assert!(exec.contains("let r = context.registers;"));
    assert!(exec.contains("        r.rax,"));
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
    assert!(runtime.contains("snapshot::capture_native("));
    assert!(runtime.contains("syscall::SyscallNumber::ProcessCreate"));
    assert!(runtime.contains("if image == 0"));
    assert!(!runtime.contains("syscall::SyscallNumber::ProcessClone"));
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    assert!(platform.contains("pub fn clone_address_space() -> SysResult<u32>"));
    assert!(!platform.contains("pub fn clone_process("));
}

#[test]
fn combined_clone_abi_and_implicit_authority_copy_are_removed() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let process = include_str!("../../../core/src/syscall/process.rs");
    let container = include_str!("../../../core/src/task/process.rs");
    let example = include_str!("../../../core/examples/user/src/lib.rs");
    for source in [abi, dispatch, process, example] {
        assert!(!source.contains("ProcessClone"));
        assert!(!source.contains("clone_current_process"));
    }
    for method in [
        "clone_object_handles",
        "clone_launch_context",
        "set_object_handles",
        "set_launch_context",
    ] {
        assert!(!container.contains(method));
    }
    assert!(!include_str!("native_clone_cow.c").contains("PROCESS_CLONE"));
}
