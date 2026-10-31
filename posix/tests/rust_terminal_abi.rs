#![allow(non_camel_case_types, dead_code)]
type c_int = i32;
const NCCS: usize = 32;
macro_rules! s { ($($item:item)*) => { $(#[repr(C)] #[derive(Clone,Copy)] $item)* }; }
#[path = "../../../libraries/libc/newlib/termios_type.rs"]
mod layout;
#[path = "../../../libraries/libc/newlib/signal_numbers.rs"]
mod signal;
#[path = "../../../libraries/libc/newlib/termios.rs"]
mod terminal;
#[path = "../../../libraries/libc/newlib/wait_status.rs"]
mod wait;
#[test]
fn rust_status_macros_do_not_confuse_exited_or_stopped_children_with_continued_children() {
    for code in 0..=255 {
        let status = code << 8;
        assert!(wait::WIFEXITED(status));
        assert_eq!(wait::WEXITSTATUS(status), code);
        assert!(!wait::WIFCONTINUED(status));
        assert!(!wait::WIFSTOPPED(status));
        assert!(!wait::WIFSIGNALED(status));
    }
    for number in 1..32 {
        for core in [0, 128] {
            let status = number | core;
            assert!(wait::WIFSIGNALED(status));
            assert_eq!(wait::WTERMSIG(status), number);
            assert_eq!(wait::WCOREDUMP(status), core != 0);
            assert!(!wait::WIFCONTINUED(status));
        }
        let status = (number << 8) | 127;
        assert!(wait::WIFSTOPPED(status));
        assert_eq!(wait::WSTOPSIG(status), number);
        assert!(!wait::WIFCONTINUED(status));
    }
    assert!(wait::WIFCONTINUED(65535));
    assert!(!wait::WIFSTOPPED(65535));
    assert!(!wait::WIFSIGNALED(65535));
    assert!(!wait::WIFEXITED(65535));
}
#[test]
fn rust_terminal_and_wait_bindings_match_the_actual_sdk_c_headers() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut constants = vec![
        ("ICANON", terminal::ICANON as u64),
        ("ECHO", terminal::ECHO as u64),
        ("ISIG", terminal::ISIG as u64),
        ("ICRNL", terminal::ICRNL as u64),
        ("OPOST", terminal::OPOST as u64),
        ("ONLCR", terminal::ONLCR as u64),
        ("TCSANOW", terminal::TCSANOW as u64),
        ("TCSADRAIN", terminal::TCSADRAIN as u64),
        ("TCSAFLUSH", terminal::TCSAFLUSH as u64),
        ("VMIN", terminal::VMIN as u64),
        ("VTIME", terminal::VTIME as u64),
        ("VERASE", terminal::VERASE as u64),
        ("WUNTRACED", wait::WUNTRACED as u64),
        ("WCONTINUED", wait::WCONTINUED as u64),
        ("WEXITED", wait::WEXITED as u64),
        ("WNOWAIT", wait::WNOWAIT as u64),
    ];
    constants.extend([
        ("SIGHUP", signal::SIGHUP as u64),
        ("SIGINT", signal::SIGINT as u64),
        ("SIGQUIT", signal::SIGQUIT as u64),
        ("SIGILL", signal::SIGILL as u64),
        ("SIGTRAP", signal::SIGTRAP as u64),
        ("SIGABRT", signal::SIGABRT as u64),
        ("SIGBUS", signal::SIGBUS as u64),
        ("SIGFPE", signal::SIGFPE as u64),
        ("SIGKILL", signal::SIGKILL as u64),
        ("SIGSEGV", signal::SIGSEGV as u64),
        ("SIGSYS", signal::SIGSYS as u64),
        ("SIGPIPE", signal::SIGPIPE as u64),
        ("SIGALRM", signal::SIGALRM as u64),
        ("SIGTERM", signal::SIGTERM as u64),
        ("SIGURG", signal::SIGURG as u64),
        ("SIGSTOP", signal::SIGSTOP as u64),
        ("SIGTSTP", signal::SIGTSTP as u64),
        ("SIGCONT", signal::SIGCONT as u64),
        ("SIGCHLD", signal::SIGCHLD as u64),
        ("SIGTTIN", signal::SIGTTIN as u64),
        ("SIGTTOU", signal::SIGTTOU as u64),
        ("SIGIO", signal::SIGIO as u64),
        ("SIGXCPU", signal::SIGXCPU as u64),
        ("SIGXFSZ", signal::SIGXFSZ as u64),
        ("SIGVTALRM", signal::SIGVTALRM as u64),
        ("SIGPROF", signal::SIGPROF as u64),
        ("SIGWINCH", signal::SIGWINCH as u64),
        ("SIGUSR1", signal::SIGUSR1 as u64),
        ("SIGUSR2", signal::SIGUSR2 as u64),
    ]);
    let mut source = String::from(
        "#include <sys/termios.h>\n#include <sys/wait.h>\n#include <signal.h>\n#include <stddef.h>\n",
    );
    source.push_str(&format!("_Static_assert(sizeof(struct termios) == {}, \"termios size\");\n_Static_assert(_Alignof(struct termios) == {}, \"termios align\");\n",core::mem::size_of::<layout::termios>(),core::mem::align_of::<layout::termios>()));
    for (name, offset) in [
        ("c_cc", core::mem::offset_of!(layout::termios, c_cc)),
        ("c_ispeed", core::mem::offset_of!(layout::termios, c_ispeed)),
        ("c_ospeed", core::mem::offset_of!(layout::termios, c_ospeed)),
    ] {
        source.push_str(&format!(
            "_Static_assert(offsetof(struct termios, {name}) == {offset}, \"{name} offset\");\n"
        ));
    }
    for (name, value) in constants {
        source.push_str(&format!("_Static_assert({name} == {value}, \"{name}\");\n"));
    }
    for status in [0, 23 << 8, 9, 11 | 128, (19 << 8) | 127, 65535] {
        for (name, value) in [
            ("WIFEXITED", wait::WIFEXITED(status)),
            ("WIFSIGNALED", wait::WIFSIGNALED(status)),
            ("WIFSTOPPED", wait::WIFSTOPPED(status)),
            ("WIFCONTINUED", wait::WIFCONTINUED(status)),
        ] {
            source.push_str(&format!(
                "_Static_assert(!!{name}({status}) == {}, \"{name}\");\n",
                i32::from(value)
            ));
        }
    }
    let mut child = Command::new("clang")
        .args([
            "--target=x86_64-unknown-none-elf",
            "-D__mochios__=1",
            "-D_GNU_SOURCE=1",
            "-fsyntax-only",
            "-Werror",
        ])
        .arg(format!(
            "--sysroot={}",
            root.join("out/newlib-port/sdk/sysroot").display()
        ))
        .arg("-isystem")
        .arg(root.join("out/newlib-port/sdk/sysroot/include"))
        .args(["-x", "c", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
