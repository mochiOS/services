use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_gate_excludes_creators_and_replacers_and_releases_on_failure() {
    let implementation = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/src/task/image_transition.rs")
        .canonicalize()
        .unwrap();
    let program = format!(
        r#"
extern crate alloc;
mod interrupt {{ pub mod spinlock {{
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T> {{
        pub const fn new(value:T)->Self {{ Self(std::sync::Mutex::new(value)) }}
        pub fn lock(&self)->std::sync::MutexGuard<'_,T> {{ self.0.lock().unwrap() }}
    }}
}} }}
mod task {{
    pub type ProcessId = u64;
    #[path={path:?}] pub mod image_transition;
}}
use task::image_transition::*;
fn main() {{
    let first = begin_thread_creation(7).unwrap();
    let second = begin_thread_creation(7).unwrap();
    assert!(begin_image_replace(7).is_none());
    drop(first);
    assert!(begin_image_replace(7).is_none());
    let unrelated = begin_image_replace(9).unwrap();
    drop(second);
    let image = begin_image_replace(7).unwrap();
    assert!(begin_image_replace(7).is_none());
    assert!(begin_thread_creation(7).is_none());
    assert!(begin_thread_creation(9).is_none());
    assert!(std::thread::spawn(|| begin_thread_creation(7).is_none()).join().unwrap());
    drop(image);
    assert!(begin_thread_creation(7).is_some());
    let failure:Result<(),()> = (|| {{
        let _image = begin_image_replace(7).unwrap();
        Err(())
    }})();
    assert_eq!(failure, Err(()));
    assert!(begin_image_replace(7).is_some());
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
        assert!(begin_image_replace(7).is_none());
        barrier.wait(); thread.join().unwrap();
        assert!(begin_image_replace(7).is_some());
    }}
}}
"#,
        path = implementation
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
    let gate = replacement.find("begin_image_replace(process_id)").unwrap();
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
