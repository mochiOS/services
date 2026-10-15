use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn public_open_preserves_committed_descriptors_and_cancels_only_after_internal_retirement() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime.find("pub extern \"C\" fn open(").unwrap();
    let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
type c_int = i32;
type c_char = i8;
static CASE: AtomicU32 = AtomicU32::new(0);
static PENDING: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(true);
static OWNED: AtomicBool = AtomicBool::new(false);
static OPENS: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);
fn pthread_testcancel() {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if ENABLED.load(Ordering::Acquire) && PENDING.load(Ordering::Acquire) {
        assert!(!OWNED.load(Ordering::Acquire), "internal ownership not retired");
        assert_eq!(OPENS.load(Ordering::Acquire), u32::from(CASE.load(Ordering::Acquire) == 1));
        std::process::exit(73);
    }
}
fn _open(_: *const c_char, _: c_int, _: c_int) -> c_int {
    OPENS.fetch_add(1, Ordering::Relaxed);
    OWNED.store(true, Ordering::Release);
    if CASE.load(Ordering::Acquire) != 5 { PENDING.store(true, Ordering::Release); }
    OWNED.store(false, Ordering::Release);
    match CASE.load(Ordering::Acquire) { 1 | 5 => -1, 3 => 0, _ => 7 }
}
"#,
    );
    program.push_str(&runtime[start..end]);
    program.push_str(
        r#"
fn main() {
    let case: u32 = std::env::args().nth(1).unwrap().parse().unwrap();
    CASE.store(case, Ordering::Release);
    if case == 0 || case == 4 { PENDING.store(true, Ordering::Release); }
    if case == 4 { ENABLED.store(false, Ordering::Release); }
    let result = open(std::ptr::null(), 0, 0);
    assert!(!matches!(case, 0 | 1), "cancellation point returned");
    assert_eq!(result, match case { 3 => 0, 5 => -1, _ => 7 });
    assert_eq!(OPENS.load(Ordering::Acquire), 1);
    assert_eq!(CHECKS.load(Ordering::Acquire), if case == 5 { 2 } else { 1 });
    assert_eq!(PENDING.load(Ordering::Acquire), case != 5);
}
"#,
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-open-cancel-{}", std::process::id()));
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
fn internal_open_returns_through_libc_and_checks_cancellation_before_fd_publication() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let internal = runtime
        .split("pub extern \"C\" fn _open(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(!internal.contains("pthread_testcancel()"));
    assert!(internal.contains("stdio_scope.note_interruption()"));
    let mutation = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    let slot = mutation.split("fn open_in_slot(").nth(1).unwrap();
    let cancelled = "target.is_none() && io_cancellation_requested(control)";
    assert_eq!(slot.matches(cancelled).count(), 2);
    assert!(slot.find(cancelled).unwrap() < slot.find("prepare_open_at(").unwrap());
    assert!(slot.find("source.opened = Some(opened)").unwrap() < slot.rfind(cancelled).unwrap());
    assert!(slot.rfind(cancelled).unwrap() < slot.find("commit_reservation(").unwrap());
    let retry = runtime
        .split("fn retry_open_with_prompt(")
        .nth(1)
        .unwrap()
        .split("struct RuntimeLaunchContext")
        .next()
        .unwrap();
    assert!(retry.contains("let result = file_mutation::open(path, flags, mode);"));
    assert!(retry.contains("drop_capability(capability)"));
    assert!(!retry.contains("file_mutation::open(path, flags, mode)?"));
}
