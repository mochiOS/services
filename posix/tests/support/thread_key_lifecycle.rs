//! Production lifecycle gate for the standalone pthread-key probes. Tests
//! supply delivery deferral and control only native address waits.
pub fn append(program: &mut String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    program.push_str(&format!(
        r#"
#[path={gate:?}]pub mod lifecycle_gate;
#[path={runtime:?}]mod lifecycle_runtime;
pub mod thread_lifecycle {{
 pub use crate::lifecycle_gate::*;
 pub(super) use crate::lifecycle_runtime::mutate;
}}
const EOVERFLOW:c_int=139;
fn process_exit(error:c_int)->!{{panic!("unexpected lifecycle failure {{error}}")}}
fn native_mutex_wait(word:&std::sync::atomic::AtomicU32,expected:u32){{
 let deadline=std::time::Instant::now()+std::time::Duration::from_secs(5);
 while word.load(Ordering::Acquire)==expected{{
  assert!(std::time::Instant::now()<deadline,"key operation stranded behind capture");
  std::thread::yield_now();
 }}
}}
fn native_mutex_wake_all(_:&std::sync::atomic::AtomicU32){{}}
"#,
        gate = root.join("user/crates/posix-client/src/thread_lifecycle.rs"),
        runtime = root.join("user/crates/newlib-runtime/src/thread_lifecycle.rs")
    ));
}
