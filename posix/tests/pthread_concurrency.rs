#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_concurrency_hint_is_atomic_process_local_and_errno_independent() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../user/crates/newlib-runtime/src/pthread_concurrency.rs")
        .canonicalize()
        .unwrap();
    let program = format!(
        r#"
use std::ffi::c_int;
const EINVAL:c_int=22;
#[path={path:?}] mod actual;
unsafe extern "C" {{ fn __errno_location()->*mut c_int; }}
use actual::{{pthread_getconcurrency as get, pthread_setconcurrency as set}};
fn main(){{
 assert_eq!(get(),0);
 unsafe{{__errno_location().write(123)}};
 for level in [1,7,128,i32::MAX,0]{{
  assert_eq!(set(level),0);assert_eq!(get(),level);
  for invalid in [-1,-7,i32::MIN]{{assert_eq!(set(invalid),EINVAL);assert_eq!(get(),level)}}
  assert_eq!(unsafe{{__errno_location().read()}},123);
 }}
 let workers:Vec<_>=(1..=8).map(|level|std::thread::spawn(move||{{
  unsafe{{__errno_location().write(100+level)}};
  for _ in 0..10000{{assert_eq!(set(level),0);assert!((0..=8).contains(&get()));assert_eq!(set(-1),EINVAL)}}
  assert_eq!(unsafe{{__errno_location().read()}},100+level);
 }})).collect();
 for worker in workers{{worker.join().unwrap()}}
 assert!((1..=8).contains(&get()));
 assert_eq!(set(37),0);assert_eq!(get(),37);
 assert_eq!(set(0),0);assert_eq!(get(),0);
}}
"#
    );
    // The actual module has no kernel, endpoint, allocator or TCB imports;
    // this executable supplies none. Calls cannot become cancellation points.
    probe::run(&program);
}

#[test]
fn c_pthread_header_calls_the_production_exports_and_shares_the_hint() {
    use std::{
        fs,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };
    struct Temporary(std::path::PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn run(command: &mut Command) {
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../user/crates/newlib-runtime/src/pthread_concurrency.rs")
        .canonicalize()
        .unwrap();
    let temporary = Temporary(std::env::temp_dir().join(format!(
            "mochios-concurrency-abi-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    fs::create_dir(&temporary.0).unwrap();
    let bridge = temporary.0.join("bridge.rs");
    fs::write(
        &bridge,
        format!("use std::ffi::c_int;const EINVAL:c_int=22;#[path={path:?}]mod actual;\n"),
    )
    .unwrap();
    let archive = temporary.0.join("libbridge.a");
    run(Command::new("rustc")
        .args(["--edition=2024", "--crate-type=staticlib"])
        .arg(&bridge)
        .arg("-o")
        .arg(&archive));
    let caller = temporary.0.join("caller.c");
    fs::write(&caller, include_str!("pthread_concurrency_abi.c")).unwrap();
    let binary = temporary.0.join("caller");
    run(Command::new("cc")
        .args([
            "-std=c11",
            "-D_GNU_SOURCE=1",
            "-Werror",
            "-Wall",
            "-Wextra",
            "-pthread",
        ])
        .arg(&caller)
        .arg(&archive)
        .args(["-ldl", "-lm", "-o"])
        .arg(&binary));
    // Host libc also exports these names. Require definitions in our executable
    // so a missing no_mangle/export cannot silently test the host implementation.
    let symbols = Command::new("nm")
        .arg("--defined-only")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8(symbols.stdout).unwrap();
    for name in ["pthread_getconcurrency", "pthread_setconcurrency"] {
        assert!(
            symbols.lines().any(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.len() == 3 && fields[1] == "T" && fields[2] == name
            }),
            "C caller did not link the production export {name}"
        );
    }
    run(&mut Command::new(binary));
}
