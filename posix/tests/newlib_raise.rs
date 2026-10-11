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

#[test]
fn reentrant_raise_calls_the_thread_directed_runtime_and_copies_errno() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp = Temporary(
        std::env::temp_dir().join(format!("mochios-raise-{}-{nonce}", std::process::id())),
    );
    fs::create_dir_all(&temp.0).unwrap();
    fs::write(
        temp.0.join("reent.h"),
        r#"
#ifndef TEST_REENT_H
#define TEST_REENT_H
struct _reent { int _errno; };
#define _REENT_ERRNO(r) ((r)->_errno)
#define _REENT_INIT_PTR(r) ((r)->_errno = 0)
void _reclaim_reent(struct _reent *);
#endif
"#,
    )
    .unwrap();
    fs::write(
        temp.0.join("main.c"),
        r#"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <reent.h>
static int result, delivered;
int raise(int signal) { delivered = signal; errno = EINVAL; return result; }
void __sinit(struct _reent *r) { (void)r; }
void _reclaim_reent(struct _reent *r) { (void)r; }
int _raise_r(struct _reent *, int);
int main(void) {
    struct _reent r = {71};
    assert(_raise_r(&r, SIGPIPE) == 0 && delivered == SIGPIPE && r._errno == 71);
    result = -1;
    assert(_raise_r(&r, SIGPIPE) == -1 && r._errno == EINVAL);
    result = 1; r._errno = 71;
    assert(_raise_r(&r, SIGPIPE) == 1 && r._errno == EINVAL);
    return 0;
}
"#,
    )
    .unwrap();
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../user/runtime/newlib_reent.c");
    let binary = temp.0.join("raise-test");
    let output = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(&temp.0)
        .arg(source)
        .arg(temp.0.join("main.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(binary).status().unwrap().success());
}

#[test]
fn pipe_signal_generation_occurs_before_partial_progress_hides_the_error() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let write = runtime
        .split("fn syscall_write(")
        .nth(1)
        .unwrap()
        .split("fn syscall_read(")
        .next()
        .unwrap();
    let signal = write
        .find("generate_thread_signal(posix_protocol::SIGNAL_PIPE)")
        .unwrap();
    assert!(write[..signal].contains("if matches!(result, Err(EPIPE))"));
    assert!(signal < write.find(".map_err(|error| match error").unwrap());
    let sdk = include_str!("../../../user/scripts/build-newlib.sh");
    assert!(sdk.contains("x86_64-elf-ar d \"$SDK/sysroot/lib/libc.a\" libc_a-raise.o"));
    assert!(!sdk.contains("x86_64-elf-ar d \"$SYSROOT/lib/libc.a\""));
}
