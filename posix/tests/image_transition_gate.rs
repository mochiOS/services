use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_gate_excludes_creators_and_image_operations_and_releases_on_failure() {
    let implementation = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/src/task/image_transition.rs")
        .canonicalize()
        .unwrap();
    let capture = include_str!("../../../core/src/syscall/process.rs")
        .split("pub fn clone_address_space() -> u64 {")
        .nth(1)
        .unwrap()
        .split("// CONTROL authorizes")
        .next()
        .unwrap();
    let program = format!(
        r#"
extern crate alloc;
use std::sync::atomic::{{AtomicBool, AtomicU8, Ordering}};
const EPERM:u64=1; const ENOSYS:u64=38; const EAGAIN:u64=11;
static MODE:AtomicU8=AtomicU8::new(0);
static CPU_REFERENCED:AtomicBool=AtomicBool::new(false);
fn caller_has_process_spawn_capability()->bool {{ true }}
mod syscall {{ pub mod security {{ pub fn current_process_id()->Option<u64> {{ Some(7) }} }} }}
mod mem {{ pub mod address_space {{ pub enum CloneError {{}} pub struct CloneSource; }} }}
mod percpu {{
    pub fn thread_is_cpu_referenced(id:u64)->bool {{
        id == 2 && super::CPU_REFERENCED.load(super::Ordering::Relaxed)
    }}
}}
mod interrupt {{ pub mod spinlock {{
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T> {{
        pub const fn new(value:T)->Self {{ Self(std::sync::Mutex::new(value)) }}
        pub fn lock(&self)->std::sync::MutexGuard<'_,T> {{ self.0.lock().unwrap() }}
    }}
}} }}
mod task {{
    pub type ProcessId = u64;
    #[derive(PartialEq, Eq)]
    pub enum ThreadState {{ Running, Ready, Terminated }}
    pub struct Thread {{ id:u64, process:u64, state:ThreadState }}
    pub struct ThreadId(u64);
    impl ThreadId {{ pub fn as_u64(&self)->u64 {{ self.0 }} }}
    impl Thread {{
        pub fn process_id(&self)->u64 {{ self.process }}
        pub fn state(&self)->ThreadState {{ match self.state {{
            ThreadState::Running=>ThreadState::Running,
            ThreadState::Ready=>ThreadState::Ready,
            ThreadState::Terminated=>ThreadState::Terminated,
        }} }}
        pub fn id(&self)->ThreadId {{ ThreadId(self.id) }}
    }}
    pub fn for_each_thread(mut visit:impl FnMut(&Thread)) {{
        visit(&Thread {{ id:1, process:7, state:ThreadState::Running }});
        match super::MODE.load(super::Ordering::Relaxed) {{
            1=>visit(&Thread {{ id:2, process:7, state:ThreadState::Ready }}),
            2=>visit(&Thread {{ id:2, process:7, state:ThreadState::Terminated }}),
            3=>visit(&Thread {{ id:2, process:9, state:ThreadState::Ready }}),
            _=>{{}}
        }}
    }}
    #[path={path:?}] pub mod image_transition;
}}
use task::image_transition::*;
fn clone_admission()->u64 {{
    {capture}
    // This point models image capture, while the actual admission guard lives.
    assert!(begin_thread_creation(7).is_none());
    assert!(begin_image_transition(7).is_none());
    0
}}
fn main() {{
    assert_eq!(clone_admission(),0);
    let creating=begin_thread_creation(7).unwrap();
    assert_eq!(clone_admission(),EAGAIN);
    drop(creating);
    let image=begin_image_transition(7).unwrap();
    assert_eq!(clone_admission(),EAGAIN);
    drop(image);
    MODE.store(1,Ordering::Relaxed);
    assert_eq!(clone_admission(),EAGAIN);
    assert!(begin_thread_creation(7).is_some());
    MODE.store(2,Ordering::Relaxed);
    assert_eq!(clone_admission(),0);
    CPU_REFERENCED.store(true,Ordering::Relaxed);
    assert_eq!(clone_admission(),EAGAIN);
    assert!(begin_thread_creation(7).is_some());
    MODE.store(3,Ordering::Relaxed);
    assert_eq!(clone_admission(),0);
    MODE.store(0,Ordering::Relaxed);
    let first = begin_thread_creation(7).unwrap();
    let second = begin_thread_creation(7).unwrap();
    assert!(begin_image_transition(7).is_none());
    drop(first);
    assert!(begin_image_transition(7).is_none());
    let unrelated = begin_image_transition(9).unwrap();
    drop(second);
    let image = begin_image_transition(7).unwrap();
    assert!(begin_image_transition(7).is_none());
    assert!(begin_thread_creation(7).is_none());
    assert!(begin_thread_creation(9).is_none());
    assert!(std::thread::spawn(|| begin_thread_creation(7).is_none()).join().unwrap());
    drop(image);
    assert!(begin_thread_creation(7).is_some());
    let failure:Result<(),()> = (|| {{
        let _image = begin_image_transition(7).unwrap();
        Err(())
    }})();
    assert_eq!(failure, Err(()));
    assert!(begin_image_transition(7).is_some());
    drop(unrelated);
    assert!(begin_thread_creation(9).is_some());
    for _ in 0..100 {{
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let other = barrier.clone();
        let thread = std::thread::spawn(move || {{
            let creator = begin_thread_creation(7).unwrap();
            other.wait(); other.wait(); drop(creator);
        }});
        barrier.wait();
        assert!(begin_image_transition(7).is_none());
        barrier.wait(); thread.join().unwrap();
        assert!(begin_image_transition(7).is_some());
    }}
}}
"#,
        path = implementation,
        capture = capture,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-image-gate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings", "-"])
        .arg("-o")
        .arg(&binary)
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
    let executed = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}

#[test]
fn old_image_is_retired_only_after_preparation_and_before_page_table_commit() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let replacement = source
        .split("fn replace_current_process_image(")
        .nth(1)
        .unwrap()
        .split("pub fn process_image_replace_syscall(")
        .next()
        .unwrap();
    let gate = replacement
        .find("begin_image_transition(process_id)")
        .unwrap();
    let prepare = replacement.find("remap_kernel_stack_user_table(").unwrap();
    let retire = replacement
        .find("retire_image_siblings(pid, current_tid)")
        .unwrap();
    let commit = replacement
        .find("process.set_page_table(new_pt_phys)")
        .unwrap();
    let release = replacement.find("drop(transition)").unwrap();
    assert!(gate < prepare && prepare < retire && retire < commit && commit < release);
}
