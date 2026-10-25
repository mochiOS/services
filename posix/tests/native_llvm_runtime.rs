//! Run the C++ target executable only after normal userspace bootstrap.
#[cfg(target_os = "mochios")]
pub fn run() {
    unsafe extern "C" {
        fn fork() -> i32;
        fn execve(path: *const u8, argv: *const *const u8, env: *const *const u8) -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(status: i32) -> !;
        fn __errno() -> *mut i32;
    }
    unsafe {
        let child = fork();
        assert!(child >= 0, "C++ probe fork errno={}", *__errno());
        if child == 0 {
            let arguments = [c"llvm-runtime-probe".as_ptr().cast(), core::ptr::null()];
            let environment = [core::ptr::null()];
            execve(
                c"/system/bin/llvm-runtime-probe".as_ptr().cast(),
                arguments.as_ptr(),
                environment.as_ptr(),
            );
            _exit(126);
        }
        let mut status = 0;
        assert_eq!(waitpid(child, &mut status, 0), child);
        assert_eq!(status, 0, "C++ probe child wait status={status}");
        mochi_user_platform::io::stdout(b"llvm-runtime: PASS child exec and wait\n").unwrap();
    }
}
