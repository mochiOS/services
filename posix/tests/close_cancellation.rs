use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn public_close_cancels_without_abandoning_internal_ownership_or_hiding_completion() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime.find("pub extern \"C\" fn close(").unwrap();
    let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
type c_int = i32;
static CASE: AtomicU32 = AtomicU32::new(0);
static PENDING: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(true);
static OWNED: AtomicBool = AtomicBool::new(false);
static CLOSES: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);
fn pthread_testcancel() {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if ENABLED.load(Ordering::Acquire) && PENDING.load(Ordering::Acquire) {
        assert!(!OWNED.load(Ordering::Acquire), "close still owns runtime state");
        assert_eq!(CLOSES.load(Ordering::Acquire), u32::from(CASE.load(Ordering::Acquire) == 1));
        std::process::exit(73);
    }
}
fn _close(fd: c_int) -> c_int {
    assert_eq!(fd, if CASE.load(Ordering::Acquire) == 5 { 0 } else { 7 });
    CLOSES.fetch_add(1, Ordering::Relaxed);
    OWNED.store(true, Ordering::Release);
    if CASE.load(Ordering::Acquire) != 4 { PENDING.store(true, Ordering::Release); }
    OWNED.store(false, Ordering::Release);
    match CASE.load(Ordering::Acquire) { 1 | 4 => -1, _ => 0 }
}
"#,
    );
    program.push_str(&runtime[start..end]);
    program.push_str(
        r#"
fn main() {
    let case: u32 = std::env::args().nth(1).unwrap().parse().unwrap();
    CASE.store(case, Ordering::Release);
    if case == 0 || case == 3 { PENDING.store(true, Ordering::Release); }
    if case == 3 { ENABLED.store(false, Ordering::Release); }
    let result = close(if case == 5 { 0 } else { 7 });
    assert!(!matches!(case, 0 | 1), "cancellation point returned");
    assert_eq!(result, if case == 4 { -1 } else { 0 });
    assert_eq!(CLOSES.load(Ordering::Acquire), 1);
    assert_eq!(CHECKS.load(Ordering::Acquire), if case == 4 { 2 } else { 1 });
    assert_eq!(PENDING.load(Ordering::Acquire), case != 4);
}
"#,
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-close-cancel-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Cdebuginfo=0", "-Cstrip=symbols", "-o"])
        .arg(&executable)
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let built = compiler.wait_with_output().unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    for case in 0..6 {
        let run = Command::new(&executable)
            .arg(case.to_string())
            .output()
            .unwrap();
        assert_eq!(
            run.status.code(),
            Some(if case <= 1 { 73 } else { 0 }),
            "case={case}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn internal_close_returns_without_cancelling_under_libc_locks() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let internal = runtime
        .split("pub extern \"C\" fn _close(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(!internal.contains("pthread_testcancel()"));
    assert!(internal.contains("close_fd_entry(&mut state.fds, fd)?"));
    assert!(internal.find("})();").unwrap() < internal.find("result_with_errno").unwrap());
}
