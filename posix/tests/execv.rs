use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_execv_forwards_exact_arguments_current_environment_and_execve_result() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source.find("pub extern \"C\" fn execv(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
use std::ffi::{c_char, c_int};
static mut environ: *mut *mut c_char = std::ptr::null_mut();
static mut EXPECT_PATH: *const c_char = std::ptr::null();
static mut EXPECT_ARGV: *const *const c_char = std::ptr::null();
static mut RESULT: i32 = -1;
fn _execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    unsafe {
        let expected_path = EXPECT_PATH; let expected_argv = EXPECT_ARGV;
        assert_eq!(path, expected_path); assert_eq!(argv, expected_argv);
        assert_eq!(envp, environ.cast_const().cast::<*const c_char>());
        RESULT
    }
}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() { unsafe {
    let path = c"/application";
    let arguments = [c"custom-argv0".as_ptr(), std::ptr::null()];
    let mut environment = [c"VALUE=inherited".as_ptr().cast_mut(), std::ptr::null_mut()];
    EXPECT_PATH = path.as_ptr(); EXPECT_ARGV = arguments.as_ptr(); environ = environment.as_mut_ptr();
    assert_eq!(execv(EXPECT_PATH, EXPECT_ARGV), -1);
    environ = std::ptr::null_mut(); RESULT = -7;
    assert_eq!(execv(EXPECT_PATH, EXPECT_ARGV), -7);
    EXPECT_PATH = std::ptr::null(); EXPECT_ARGV = std::ptr::null();
    assert_eq!(execv(EXPECT_PATH, EXPECT_ARGV), -7);
} }
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-execv-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
