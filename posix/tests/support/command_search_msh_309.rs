//! Real std/POSIX search from the actual Terminal-launched msh. No grants.
use mochi_user_platform as p;
use std::process::Command;
unsafe extern "C" {
    fn confstr(selector: i32, output: *mut i8, length: usize) -> usize;
}
fn trace(text: &str) {
    p::syscall::call2(
        p::syscall::SyscallNumber::DebugWrite,
        text.as_ptr() as u64,
        text.len() as u64,
    )
    .unwrap();
}
fn success(command: &mut Command) {
    let result = command.output().unwrap();
    assert!(result.status.success(), "command failed: {:?}", result);
    assert!(!result.stdout.is_empty());
}
pub fn run() {
    // Existing POSIX alarm bounds hangs in real pipe/exec/wait, then is disarmed.
    unsafe {
        libc::alarm(60);
    }
    // _CS_PATH is SDK selector zero, not a native syscall selector.
    let length = unsafe { confstr(0, std::ptr::null_mut(), 0) };
    assert!(length > 1 && length < 4096);
    let mut bytes = vec![0; length];
    assert_eq!(
        unsafe { confstr(0, bytes.as_mut_ptr().cast(), bytes.len()) },
        length
    );
    assert_eq!(bytes.pop(), Some(0));
    let expected = String::from_utf8(bytes).unwrap();
    assert_eq!(
        std::env::var("PATH").unwrap(),
        expected,
        "session policy and POSIX default must agree"
    );
    trace("command-search-309: inherited PATH matches native confstr; testing bare spawn\n");
    success(Command::new("ls").arg("/home"));
    trace("command-search-309: bare command passed; testing child PATH override\n");
    let error = Command::new("ls")
        .env("PATH", "/missing-command-search-309")
        .output()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    trace("command-search-309: override denied; testing ENOTDIR continuation\n");
    success(
        Command::new("ls")
            .env("PATH", "/system/bin/ls:/system/bin")
            .arg("/home"),
    );
    trace("command-search-309: ENOTDIR passed; testing unset PATH and slash path\n");
    success(Command::new("ls").env_remove("PATH").arg("/home"));
    success(
        Command::new("/system/bin/ls")
            .env("PATH", "/missing-command-search-309")
            .arg("/home"),
    );
    unsafe {
        libc::alarm(0);
    }
    trace(
        "command-search-309: PASS real confstr/session PATH, bare exec, override, ENOTDIR, unset default, slash path, output and wait; no grant\n",
    );
}
