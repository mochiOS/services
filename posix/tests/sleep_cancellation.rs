use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_sleeps_check_cancellation_and_close_the_check_to_wait_race() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = format!(
        r#"
use std::ffi::c_void;
use std::ptr;
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
    let expected = if case == 0 || case == 11 {{ 0 }} else {{ 1 }};
    assert_eq!(WAITS.load(Ordering::Acquire), expected);
    std::process::exit(73)
}}
fn monotonic_nanoseconds() -> Result<u64, i32> {{
    let read = READS.fetch_add(1, Ordering::AcqRel);
    if read == 1 && (CASE.load(Ordering::Acquire) == 11 || CASE.load(Ordering::Acquire) == 12) {{
        if CASE.load(Ordering::Acquire) == 11 {{ pthread_cancel(1); }}
        return Err(EIO);
    }}
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
mod newlib_errno {{ pub const EIO: i32 = 5; pub const EINVAL: i32 = 22; pub const ENOTSUP: i32 = 95; }}
mod mochios_posix_client {{
    #[path = "{}"] pub mod time;
    pub mod synchronization {{
        use super::super::*;
        pub struct Error(u64);
        impl Error {{ pub fn raw(&self) -> u64 {{ self.0 }} }}
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
                // A native failure may race with cancellation after admission.
                8 | 10 => {{ pthread_cancel(1); return Err(Error(EIO as u64)); }},
                9 => {{ return Err(Error(EIO as u64)); }},
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
    // Exercise the runtime's byte-format conversion too. All pointers in this
    // probe refer to live local request/remaining values; real fault handling
    // is covered separately by time_memory_runtime.
    program.push_str(r#"
#[repr(C)]
struct Tms { tms_utime:u64,tms_stime:u64,tms_cutime:u64,tms_cstime:u64 }
mod user_copy {
    pub fn read(source:*const u8,bytes:&mut [u8])->Result<(),i32>{
        if source.is_null(){return Err(crate::EFAULT);}
        unsafe{std::ptr::copy_nonoverlapping(source,bytes.as_mut_ptr(),bytes.len());}
        Ok(())
    }
    pub fn write(destination:*mut u8,bytes:&[u8])->Result<(),i32>{
        if destination.is_null(){return Err(crate::EFAULT);}
        unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),destination,bytes.len());}
        Ok(())
    }
}
mod time_memory {
"#);
    program.push_str(
        &include_str!("../../../user/crates/newlib-runtime/src/time_memory.rs")
            .replace("//!", "//"),
    );
    program.push_str("}\n");
    for entry in [
        "pub extern \"C\" fn sleep(",
        "pub extern \"C\" fn usleep(",
        "pub unsafe extern \"C\" fn nanosleep(",
        "fn sleep_failure(",
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
    if case == 3 || case == 10 { CONTROL.cancel_state.store(1, Ordering::Release); }
    let request = Timespec { tv_sec: if case == 0 { 0 } else { 1 }, tv_nsec: 0 };
    let mut remaining = Timespec { tv_sec: 99, tv_nsec: 99 };
    if case == 7 {
        let _: unsafe extern "C" fn(u64, c_int, *const Timespec, *mut Timespec) -> c_int = clock_nanosleep;
        for id in [u64::MAX, 1u64 << 32 | 1, 1u64 << 32 | 4, 1u64 << 32 | 2, 1u64 << 32 | 3] {
            assert_eq!(unsafe { clock_nanosleep(id, 0, &request, &mut remaining) }, EINVAL);
            assert_eq!(unsafe { ERRNO }, 123);
            assert_eq!((remaining.tv_sec, remaining.tv_nsec), (99, 99));
            assert_eq!(WAITS.load(Ordering::Acquire), 0);
            assert_eq!(READS.load(Ordering::Acquire), 0);
        }
        return;
    }
    let result = unsafe {
        match args[2].as_str() {
            "clock" => clock_nanosleep(4, 0, &request, &mut remaining),
            "sleep" => sleep(request.tv_sec as u32) as i32,
            "usleep" => usleep(request.tv_sec as u64 * 1_000_000),
            _ => nanosleep(&request, &mut remaining),
        }
    };
    assert!(matches!(case,3|4|5|9|10|12), "enabled cancellation returned");
    if matches!(case,9|10|12) {
        assert_eq!(result, match args[2].as_str() { "clock" => EIO, "sleep" => 1, _ => -1 });
        assert_eq!(unsafe { ERRNO }, if args[2] == "clock" || args[2] == "sleep" {123} else {EIO});
        if case == 10 { assert_eq!(CONTROL.cancel_pending.load(Ordering::Acquire),1); }
        return;
    }
    if case == 4 {
        assert_eq!(result, match args[2].as_str() {
            "clock" => EINTR, "sleep" => 1, _ => -1,
        });
        if args[2] == "clock" || args[2] == "nano" {
            assert_eq!(remaining.tv_sec, 1);
            assert_eq!(remaining.tv_nsec, 0);
        }
        assert_eq!(WAITS.load(Ordering::Acquire), 0);
    } else {
        assert_eq!(result, 0);
        assert_eq!(WAITS.load(Ordering::Acquire), 2);
    }
    if args[2] == "clock" || args[2] == "sleep" { assert_eq!(unsafe { ERRNO }, 123); }
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
        .args([
            "--edition=2021",
            "-Awarnings",
            "-Cdebuginfo=0",
            "-Cstrip=symbols",
            "-",
        ])
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
    for kind in ["nano", "clock", "sleep", "usleep"] {
        for case in (0..7).chain(8..=12) {
            let executed = Command::new(&executable)
                .args([&case.to_string(), kind])
                .output()
                .unwrap();
            let expected = if matches!(case, 0 | 1 | 2 | 6 | 8 | 11) { 73 } else { 0 };
            assert_eq!(
                executed.status.code(),
                Some(expected),
                "{kind}/{case}: {}",
                String::from_utf8_lossy(&executed.stderr)
            );
        }
    }
    let invalid_ids = Command::new(&executable)
        .args(["7", "clock"])
        .output()
        .unwrap();
    assert!(
        invalid_ids.status.success(),
        "{}",
        String::from_utf8_lossy(&invalid_ids.stderr)
    );
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
            < dispatch.find("signal_stack::invoke").unwrap()
    );
    assert_eq!(
        runtime
            .matches("wait_generation.store(0, Ordering::Relaxed)")
            .count(),
        2
    );
    assert!(!runtime.contains("NANOSLEEP_WORD"));
}
