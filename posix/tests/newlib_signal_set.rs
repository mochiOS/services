use std::fs;
use std::process::Command;

#[test]
fn runtime_set_bits_match_the_newlib_signal_range_without_undefined_shifts() {
    use mochios_posix_client::signal::{NEWLIB_SIGNAL_COUNT, newlib_set_bit};
    assert_eq!(NEWLIB_SIGNAL_COUNT, 32);
    for signal in 1..NEWLIB_SIGNAL_COUNT {
        assert_eq!(newlib_set_bit(signal), Some(1u64 << (signal - 1)));
    }
    for signal in [i32::MIN, -1, 0, 32, 64, i32::MAX] {
        assert_eq!(newlib_set_bit(signal), None);
    }
}

#[test]
fn sdk_signal_set_calls_match_real_newlib_functions_and_validate_arguments() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temporary = std::env::temp_dir().join(format!(
        "mochios-sigset-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&temporary).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(temporary.clone());
    let header = temporary.join("signal.h");
    let script = root.join("user/scripts/fix-newlib-signal-header.pl");
    fs::write(
        &header,
        include_str!("../../../libraries/newlib/newlib/libc/include/sys/signal.h"),
    )
    .unwrap();
    for _ in 0..2 {
        let output = Command::new("perl")
            .arg(&script)
            .arg(&header)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let header = fs::read_to_string(&header).unwrap();
    assert_eq!(header.matches("#define SA_NOCLDWAIT 0x2").count(), 1);
    let start = header
        .find("#if !defined(__CYGWIN__) && !defined(__rtems__)")
        .unwrap();
    let end = start
        + header[start..]
            .find("#endif /* !__CYGWIN__ && !__rtems__ */")
            .unwrap()
        + "#endif /* !__CYGWIN__ && !__rtems__ */".len();
    let declarations = "typedef unsigned long sigset_t;\n#define NSIG 32\n#define SIG_SETMASK 0\n#define EINVAL 22\nextern int errno;\n";
    let library = include_str!("../../../libraries/newlib/newlib/libc/unix/sigset.c")
        .replace("#include <signal.h>", "")
        .replace("#include <errno.h>", "");
    let implementation = temporary.join("implementation.c");
    fs::write(
        &implementation,
        format!("{declarations}\nint errno;\n{library}"),
    )
    .unwrap();
    let consumer = temporary.join("consumer.c");
    fs::write(
        &consumer,
        format!(
            r#"{declarations}
int sigemptyset(sigset_t *);
int sigfillset(sigset_t *);
int sigaddset(sigset_t *, int);
int sigdelset(sigset_t *, int);
int sigismember(const sigset_t *, int);
{}
int main(void) {{
    sigset_t set, function_set;
    if (sigemptyset(&set) || set != 0) return 1;
    for (int signal = 1; signal < NSIG; ++signal) {{
        if (sigemptyset(&set) || (sigemptyset)(&function_set)) return 2;
        if (sigaddset(&set, signal) || (sigaddset)(&function_set, signal)) return 3;
        if (set != (1UL << (signal - 1)) || set != function_set) return 4;
        if (sigismember(&set, signal) != 1 || (sigismember)(&set, signal) != 1) return 5;
        if (sigdelset(&set, signal) || set != 0 || sigismember(&set, signal) != 0) return 6;
    }}
    int evaluated = 30;
    if (sigaddset(&set, evaluated++) || evaluated != 31 || set != (1UL << 29)) return 7;
    sigset_t previous = set;
    int invalid[] = {{-1, 0, 32, 64}};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {{
        errno = 0;
        if (sigaddset(&set, invalid[i]) != -1 || errno != EINVAL || set != previous) return 8;
        if (sigdelset(&set, invalid[i]) != -1 || set != previous) return 9;
        if (sigismember(&set, invalid[i]) != -1) return 10;
    }}
    if (sigfillset(&set) || set != ~0UL) return 11;
    return 0;
}}
"#,
            &header[start..end]
        ),
    )
    .unwrap();
    let binary = temporary.join("probe");
    let output = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-D__mochios__"])
        .arg(&implementation)
        .arg(&consumer)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status = Command::new(&binary).status().unwrap();
    assert!(status.success(), "sigset probe exited {status}");
    let invalid = temporary.join("unsupported.h");
    fs::write(&invalid, "not a newlib header\n").unwrap();
    let output = Command::new("perl")
        .arg(script)
        .arg(&invalid)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(&invalid).unwrap(),
        "not a newlib header\n"
    );
}
