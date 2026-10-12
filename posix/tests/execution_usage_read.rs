use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn native_accounting_layout_has_only_execution_domains_and_sampling_rate() {
    assert_eq!(mnu_abi::SyscallNumber::ProcessExecutionRead as u64, 683);
    assert_eq!(std::mem::size_of::<mnu_abi::ProcessExecutionUsage>(), 32);
    assert_eq!(std::mem::align_of::<mnu_abi::ProcessExecutionUsage>(), 8);
    assert_eq!(mnu_abi::ProcessExecutionUsage::default().reserved, 0);
}

#[test]
fn production_reader_requires_an_observable_process_object_and_validates_output() {
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let start = source.find("fn process_execution_usage_for(").unwrap();
    let end = source[start..]
        .find("/// Waits until the process exits.")
        .unwrap()
        + start;
    let mut program = String::from(
        r#"
use std::sync::Arc;
const SUCCESS: u64 = 0;
const EBADF: u64 = (-9i64) as u64;
const EACCES: u64 = (-13i64) as u64;
const EINVAL: u64 = (-22i64) as u64;
const ESRCH: u64 = (-3i64) as u64;
const EAGAIN: u64 = (-11i64) as u64;
const EFAULT: u64 = (-14i64) as u64;
mod mnu_abi {
    #[repr(C)] #[derive(Default, Debug, PartialEq)]
    pub struct ProcessExecutionUsage {
        pub user_ticks: u64, pub kernel_ticks: u64, pub ticks_per_second: u64, pub reserved: u64,
    }
}
struct Counter { user: u64, kernel: u64 }
struct Process { object: Arc<Counter> }
impl Process { fn process_object(&self) -> Arc<Counter> { Arc::clone(&self.object) } }
enum KernelObject { Process(Arc<Counter>), File }
#[derive(PartialEq, Debug)] struct HandleRights;
impl HandleRights { const WAIT: Self = Self; }
fn current_process() -> Result<u64, u64> { Ok(1) }
fn object(raw: u64, right: HandleRights) -> Result<KernelObject, u64> {
    assert_eq!(right, HandleRights::WAIT);
    match raw {
        42 => Ok(KernelObject::Process(Arc::new(Counter { user: 13, kernel: 17 }))),
        43 => Err(EACCES), // Explicit handle exists but does not grant WAIT.
        9 => Ok(KernelObject::File),
        _ => Err(EBADF),
    }
}
mod task {
    use super::*;
    pub fn with_process<R>(id: u64, read: impl FnOnce(&Process) -> R) -> Option<R> {
        // The remote process has already left the process table. Its retained
        // native object is still observable through the explicit handle.
        (id == 1).then(|| read(&Process { object: Arc::new(Counter { user: 7, kernel: 11 }) }))
    }
    pub mod thread {
        use super::*;
        pub fn process_execution_ticks(counter: &Counter) -> (u64, u64) { (counter.user, counter.kernel) }
    }
}
mod interrupt { pub mod timer { pub fn ticks_per_second() -> u64 { 500 } } }
mod syscall {
    use super::*;
    pub fn copy_to_user(output: u64, bytes: &[u8]) -> Result<(), u64> {
        if output < 4096 { return Err(EFAULT); }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output as *mut u8, bytes.len()); }
        Ok(())
    }
}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() {
    let mut usage = mnu_abi::ProcessExecutionUsage::default();
    let output = (&mut usage as *mut mnu_abi::ProcessExecutionUsage) as u64;
    assert_eq!(process_execution_read(0, output, 32), SUCCESS);
    assert_eq!((usage.user_ticks, usage.kernel_ticks, usage.ticks_per_second, usage.reserved), (7, 11, 500, 0));
    assert_eq!(process_execution_read(42, output, 32), SUCCESS);
    assert_eq!((usage.user_ticks, usage.kernel_ticks), (13, 17));
    for (handle, expected) in [(43, EACCES), (9, EBADF), (99, EBADF)] {
        assert_eq!(process_execution_read(handle, output, 32), expected);
        assert_eq!((usage.user_ticks, usage.kernel_ticks), (13, 17));
    }
    for length in [0, 31, 33, u64::MAX] {
        assert_eq!(process_execution_read(0, output, length), EINVAL);
    }
    assert_eq!(process_execution_read(0, 0, 32), EFAULT);
    assert_eq!(process_execution_read(0, 1, 32), EFAULT);
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-execution-read-{}-{}",
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
    let executed = Command::new(&executable).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}

#[test]
fn snapshot_is_coherent_and_platform_wrapper_rejects_invalid_optional_handles() {
    let thread = include_str!("../../../core/src/task/thread.rs");
    let snapshot = thread
        .split("fn process_execution_ticks(")
        .nth(1)
        .unwrap()
        .split("fn mark_thread_terminated(")
        .next()
        .unwrap();
    assert!(
        snapshot.find("THREAD_QUEUE.lock()").unwrap()
            < snapshot.find("process.user_cpu_ticks()").unwrap()
    );
    assert!(snapshot.contains("process.kernel_cpu_ticks()"));
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    let wrapper = platform
        .split("fn execution_usage(")
        .nth(1)
        .unwrap()
        .split("fn wait_handle(")
        .next()
        .unwrap();
    assert!(wrapper.contains("syscall::execution::usage(handle)"));
    let low = include_str!("../../../user/crates/syscall/src/execution.rs");
    assert!(low.contains("Some(0) => return Err"));
    assert!(low.contains("ProcessExecutionRead"));
    assert!(low.contains("usage.ticks_per_second == 0 || usage.reserved != 0"));
    assert!(!wrapper.contains("process_id"));
}
