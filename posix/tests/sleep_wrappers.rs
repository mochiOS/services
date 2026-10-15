use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_sleep_wrappers_preserve_width_round_remaining_seconds_and_propagate_errors() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        r#"
use std::ptr;
type c_int = i32;
const EINTR: i32 = 4;
struct Timespec { tv_sec: i64, tv_nsec: i64 }
static mut ERRNO: i32 = 91;
static mut REQUEST: (i64, i64) = (0, 0);
static mut REMAINING: (i64, i64) = (0, 0);
static mut ERROR: i32 = 0;
unsafe fn __errno() -> *mut i32 { &raw mut ERRNO }
fn set_errno(value: i32) { unsafe { ERRNO = value; } }
unsafe fn nanosleep(request: *const Timespec, remaining: *mut Timespec) -> c_int {
    unsafe {
        REQUEST = ((*request).tv_sec, (*request).tv_nsec);
        if !remaining.is_null() && ERROR == EINTR {
            (*remaining).tv_sec = REMAINING.0;
            (*remaining).tv_nsec = REMAINING.1;
        }
        if ERROR == 0 { 0 } else { ERRNO = ERROR; -1 }
    }
}
"#,
    );
    for entry in ["pub extern \"C\" fn sleep(", "pub extern \"C\" fn usleep("] {
        let start = runtime.find(entry).unwrap();
        let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&runtime[start..end]);
    }
    program.push_str(
        r#"
fn main() {
    let _: extern "C" fn(u32) -> u32 = sleep;
    let _: extern "C" fn(u64) -> i32 = usleep;
    for seconds in [0, 1, u32::MAX] {
        assert_eq!(sleep(seconds), 0);
        unsafe { assert_eq!({ REQUEST }, (i64::from(seconds), 0)); assert_eq!({ ERRNO }, 91); }
    }
    for (seconds, nanos, expected) in [(0, 0, 0), (0, 1, 1), (1, 0, 1),
        (1, 999_999_999, 2), (4, 1, 5), (5, 0, 5)] {
        unsafe { ERROR = EINTR; REMAINING = (seconds, nanos); }
        assert_eq!(sleep(5), expected);
        unsafe { assert_eq!({ ERRNO }, 91); }
    }
    unsafe { REMAINING = (i64::from(u32::MAX) - 1, 999_999_999); }
    assert_eq!(sleep(u32::MAX), u32::MAX);
    unsafe { ERROR = 75; }
    assert_eq!(sleep(5), 5);
    unsafe { assert_eq!({ ERRNO }, 91); ERROR = 0; }
    for microseconds in [0, 1, 999_999, 1_000_000, 1_500_001, u64::MAX] {
        assert_eq!(usleep(microseconds), 0);
        unsafe {
            assert_eq!({ REQUEST }, ((microseconds / 1_000_000) as i64,
                ((microseconds % 1_000_000) * 1_000) as i64));
        }
    }
    for error in [EINTR, 22, 75] {
        unsafe { ERROR = error; }
        assert_eq!(usleep(1), -1);
        unsafe { assert_eq!({ ERRNO }, error); }
    }
}
"#,
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-sleep-wrappers-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args([
            "--edition=2024",
            "-Awarnings",
            "-Cdebuginfo=0",
            "-Cstrip=symbols",
            "-o",
        ])
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
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let run = Command::new(&executable).output().unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
