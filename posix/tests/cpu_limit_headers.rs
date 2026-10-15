use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn mochios_clock_selectors_are_visible_without_claiming_the_entire_cpu_timer_option() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut compiler = Command::new("cc")
        .args([
            "-std=c11",
            "-D__mochios__",
            "-D_POSIX_C_SOURCE=200809L",
            "-Werror=implicit-function-declaration",
            "-I",
        ])
        .arg(root.join("out/newlib-port/sdk/sysroot/include"))
        .arg("-include")
        .arg(root.join("libraries/newlib/newlib/libc/include/time.h"))
        .args(["-x", "c", "-fsyntax-only", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler.stdin.take().unwrap().write_all(b"_Static_assert(CLOCK_PROCESS_CPUTIME_ID == 2, \"process clock SDK ABI\");\n_Static_assert(CLOCK_THREAD_CPUTIME_ID == 3, \"thread clock SDK ABI\");\nint (*read_clock)(clockid_t, struct timespec *) = clock_gettime;\n").unwrap();
    let built = compiler.wait_with_output().unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}
