use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_sleeps_check_cancellation_and_close_the_check_to_wait_race() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = format!(
        r#"
use std::ffi::c_void;
use std::sync::atomic::{{AtomicU32, AtomicU64, Ordering}};
type c_int = i32;
type Pthread = usize;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const EAGAIN: i32 = 11;
const EOVERFLOW: i32 = 75;
const EIO: i32 = 5;
const EINTR: i32 = 4;
const ESRCH: i32 = 3;
const PTHREAD_CANCEL_ENABLE: u32 = 0;
struct Timespec {{ tv_sec: i64, tv_nsec: i64 }}
struct ThreadControl {{
    state: AtomicU32, cancel_state: AtomicU32, cancel_pending: AtomicU32,
    wait_generation: AtomicU32, caught_signal_generation: AtomicU64,
    multiplex_generation: AtomicU64,
}}
static CONTROL: ThreadControl = ThreadControl {{
    state: AtomicU32::new(2), cancel_state: AtomicU32::new(0), cancel_pending: AtomicU32::new(0),
    wait_generation: AtomicU32::new(0), caught_signal_generation: AtomicU64::new(0),
    multiplex_generation: AtomicU64::new(0),
}};
static CASE: AtomicU32 = AtomicU32::new(0);
static WAITS: AtomicU32 = AtomicU32::new(0);
static NOW: AtomicU64 = AtomicU64::new(0);
static READS: AtomicU32 = AtomicU32::new(0);
static mut ERRNO: i32 = 123;
unsafe fn __errno() -> *mut i32 {{ &raw mut ERRNO }}
fn set_errno(value: i32) {{ unsafe {{ ERRNO = value; }} }}
fn register_current_thread() -> Option<(usize, &'static ThreadControl)> {{ Some((1, &CONTROL)) }}
fn current_thread_control() -> Option<(usize, &'static ThreadControl)> {{ register_current_thread() }}
fn thread_control(thread: usize) -> Option<&'static ThreadControl> {{ (thread == 1).then_some(&CONTROL) }}
fn native_mutex_wake_all(address: &AtomicU32) {{
    assert!(std::ptr::eq(address, &CONTROL.state) || std::ptr::eq(address, &CONTROL.wait_generation));
}}
fn native_counter_wake_all(address: &AtomicU64) {{ assert!(std::ptr::eq(address, &CONTROL.multiplex_generation)); }}
fn finish_thread(_: &ThreadControl, result: *mut c_void) -> ! {{
    assert_eq!(result as usize, usize::MAX);
    let case = CASE.load(Ordering::Acquire);
    let expected = if case == 0 {{ 0 }} else {{ 1 }};
    assert_eq!(WAITS.load(Ordering::Acquire), expected);
    std::process::exit(73)
}}
fn monotonic_nanoseconds() -> Result<u64, i32> {{
    let read = READS.fetch_add(1, Ordering::AcqRel);
    // Inject after the sleep's generation snapshot but before native admission.
    if read == 1 && CASE.load(Ordering::Acquire) == 1 {{ assert_eq!(pthread_cancel(1), 0); }}
    if read == 1 && CASE.load(Ordering::Acquire) == 4 {{
        CONTROL.caught_signal_generation.fetch_add(1, Ordering::Release);
        notify_thread_waiter(&CONTROL);
    }}
    Ok(NOW.load(Ordering::Acquire))
}}
fn map_kernel_errno(raw: u64) -> i32 {{ raw as i32 }}
fn syscall_errno(_: u64) -> Result<u64, i32> {{ unreachable!() }}
mod mnu_abi {{
    #[derive(Default)] pub struct ClockInstant {{ pub seconds: u64, pub nanoseconds: u32, pub reserved: u32 }}
    pub enum ClockId {{ Realtime }}
}}
mod syscall {{
    pub enum SyscallNumber {{ ClockRead }}
    pub fn raw_syscall2(_: SyscallNumber, _: u64, _: u64) -> u64 {{ unreachable!() }}
}}
mod newlib_errno {{ pub const EINVAL: i32 = 22; pub const ENOTSUP: i32 = 95; }}
mod mochios_posix_client {{
    #[path = "{}"] pub mod time;
    pub mod synchronization {{
        use super::super::*;
        pub struct Error;
        impl Error {{ pub fn raw(&self) -> u64 {{ unreachable!() }} }}
        pub fn wait_u32(address: &AtomicU32, expected: u32, deadline: u64) -> Result<(), Error> {{
            assert!(std::ptr::eq(address, &CONTROL.wait_generation));
            let count = WAITS.fetch_add(1, Ordering::AcqRel);
            match CASE.load(Ordering::Acquire) {{
                1 => assert_ne!(address.load(Ordering::Acquire), expected),
                2 => {{ assert_eq!(address.load(Ordering::Acquire), expected); pthread_cancel(1); }},
                3 if count == 0 => {{ pthread_cancel(1); }},
                3 => {{ assert_eq!(expected, 1); NOW.store(deadline, Ordering::Release); }},
                5 if count == 0 => {{}}, // Harmless spurious native wake.
                5 => {{ NOW.store(deadline, Ordering::Release); }},
                6 => {{ NOW.store(deadline, Ordering::Release); pthread_cancel(1); }},
                _ => panic!("unexpected wait"),
            }}
            Ok(())
        }}
    }}
}}
"#,
        root.join("user/crates/posix-client/src/time.rs")
            .canonicalize()
            .unwrap()
            .display()
    );
    for entry in [
        "pub unsafe extern \"C\" fn nanosleep(",
        "pub unsafe extern \"C\" fn clock_nanosleep(",
        "pub extern \"C\" fn pthread_cancel(",
        "pub extern \"C\" fn pthread_testcancel(",
        "fn notify_thread_waiter(",
    ] {
        let start = runtime.find(entry).unwrap();
        let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&runtime[start..end]);
    }
    program.push_str(
        r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let case: u32 = args[1].parse().unwrap();
    CASE.store(case, Ordering::Release);
    if case == 0 { pthread_cancel(1); }
    if case == 3 { CONTROL.cancel_state.store(1, Ordering::Release); }
    let request = Timespec { tv_sec: if case == 0 { 0 } else { 1 }, tv_nsec: 0 };
    let mut remaining = Timespec { tv_sec: 99, tv_nsec: 99 };
    let result = unsafe {
        if args[2] == "clock" { clock_nanosleep(4, 0, &request, &mut remaining) }
        else { nanosleep(&request, &mut remaining) }
    };
    assert!(case == 3 || case == 4 || case == 5, "enabled cancellation returned");
    if case == 4 {
        assert_eq!(result, if args[2] == "clock" { EINTR } else { -1 });
        assert_eq!(remaining.tv_sec, 1);
        assert_eq!(remaining.tv_nsec, 0);
        assert_eq!(WAITS.load(Ordering::Acquire), 0);
    } else {
        assert_eq!(result, 0);
        assert_eq!(WAITS.load(Ordering::Acquire), 2);
    }
    if args[2] == "clock" { assert_eq!(unsafe { ERRNO }, 123); }
    if case == 3 { assert_eq!(CONTROL.cancel_pending.load(Ordering::Acquire), 1); }
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-sleep-cancel-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings", "-"])
        .arg("-o")
        .arg(&executable)
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
    for kind in ["nano", "clock"] {
        for case in 0..7 {
            let executed = Command::new(&executable)
                .args([&case.to_string(), kind])
                .output()
                .unwrap();
            let expected = if matches!(case, 0 | 1 | 2 | 6) { 73 } else { 0 };
            assert_eq!(
                executed.status.code(),
                Some(expected),
                "{kind}/{case}: {}",
                String::from_utf8_lossy(&executed.stderr)
            );
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn caught_handlers_notify_sleepers_and_recycled_controls_reset_the_generation() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let dispatch = runtime
        .split("fn dispatch_signal(")
        .nth(1)
        .unwrap()
        .split("fn apply_default_signal_action")
        .next()
        .unwrap();
    assert!(
        dispatch.find("notify_thread_waiter(control)").unwrap()
            < dispatch.find("function(signal)").unwrap()
    );
    assert_eq!(
        runtime
            .matches("wait_generation.store(0, Ordering::Relaxed)")
            .count(),
        2
    );
    assert!(!runtime.contains("NANOSLEEP_WORD"));
}
