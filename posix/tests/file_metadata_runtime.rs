//! Header wiring; the production metadata and path owners are exercised
//! together in path_io_resources.rs rather than duplicating their lifetime model.

#[test]
fn newlib_stat_header_declares_the_mochios_metadata_entry_points() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut compiler = Command::new("cc")
        .args([
            "-std=c11",
            "-D__mochios__",
            "-D_POSIX_C_SOURCE=200809L",
            "-Werror=implicit-function-declaration",
            "-Werror=incompatible-pointer-types",
            "-I",
        ])
        .arg(root.join("out/newlib-port/sdk/sysroot/include"))
        .arg("-include")
        .arg(root.join("libraries/newlib/newlib/libc/include/sys/stat.h"))
        .args(["-x", "c", "-fsyntax-only", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler.stdin.take().unwrap().write_all(br#"
#include <stddef.h>
int (*stat_link)(const char *, struct stat *) = lstat;
int (*stat_relative)(int, const char *, struct stat *, int) = fstatat;
int (*set_times)(int, const struct timespec *) = futimens;
int (*set_times_at)(int, const char *, const struct timespec *, int) = utimensat;
_Static_assert(UTIME_NOW == -2L && UTIME_OMIT == -1L, "mochiOS newlib sentinels");
_Static_assert(sizeof(struct timespec) == 16 && offsetof(struct timespec, tv_nsec) == 8, "mochiOS timespec layout");
"#).unwrap();
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
