use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn wait_headers_work_installed_and_with_a_source_overlay_in_c_and_cpp() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let installed =
        std::env::temp_dir().join(format!("mochios-wait-headers-{}", std::process::id()));
    std::fs::create_dir_all(installed.join("sys")).unwrap();
    for name in ["wait.h", "syslimits.h"] {
        std::fs::copy(
            root.join("user/libc-port/include/sys").join(name),
            installed.join("sys").join(name),
        )
        .unwrap();
    }
    for (compiler, language) in [("clang", "c"), ("clang++", "c++")] {
        for source_overlay in [false, true] {
            let mut command = Command::new(compiler);
            command.args([
                "--target=x86_64-unknown-none-elf",
                "-D__mochios__=1",
                "-D_GNU_SOURCE=1",
                "-Werror",
                "-fsyntax-only",
            ]);
            command.arg(format!(
                "--sysroot={}",
                root.join("out/newlib-port/sdk/sysroot").display()
            ));
            if source_overlay {
                command
                    .arg("-isystem")
                    .arg(root.join("user/libc-port/include"));
            }
            command
                .arg("-isystem")
                .arg(&installed)
                .arg("-isystem")
                .arg(root.join("out/newlib-port/sdk/sysroot/include"))
                .args(["-x", language, "-"])
                .stdin(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(
                    br#"
#include <sys/wait.h>
#include <sys/wait.h>
#include <limits.h>
#if _POSIX_ARG_MAX != 4096
#error missing POSIX argument minimum
#endif
typedef char exited[WIFEXITED(23 << 8) && WEXITSTATUS(23 << 8) == 23 ? 1 : -1];
typedef char killed[WIFSIGNALED(9) && WTERMSIG(9) == 9 ? 1 : -1];
typedef char stopped[WIFSTOPPED((19 << 8) | 0x7f) && WSTOPSIG((19 << 8) | 0x7f) == 19 ? 1 : -1];
typedef char continued[WIFCONTINUED(0xffff) && !WIFSIGNALED(0xffff) ? 1 : -1];
pid_t (*wait_fn)(int *) = wait;
pid_t (*waitpid_fn)(pid_t, int *, int) = waitpid;
int (*waitid_fn)(idtype_t, id_t, siginfo_t *, int) = waitid;
int options = WNOHANG | WUNTRACED | WCONTINUED | WEXITED | WNOWAIT;
"#,
                )
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{language}, overlay={source_overlay}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    std::fs::remove_dir_all(installed).unwrap();
}
