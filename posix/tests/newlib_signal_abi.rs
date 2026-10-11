use std::fs;
use std::process::Command;

#[test]
fn runtime_signal_action_matches_newlib_not_rtems() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime.find("pub struct SignalAction {").unwrap();
    let end = start + runtime[start..].find("\n}").unwrap() + 2;
    let declaration = &runtime[start..end];
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/signal.h");
    let branch = header
        .split("#else /* defined(__rtems__) */")
        .nth(1)
        .unwrap();
    let start = branch.find("struct sigaction").unwrap();
    let end = start + branch[start..].find("};").unwrap() + 2;
    let c_declaration = &branch[start..end];
    let temporary = std::env::temp_dir().join(format!(
        "mochios-signal-abi-{}-{}",
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
    // Compile the actual runtime declaration, not a duplicate test structure.
    let rust = format!(
        "#[allow(non_camel_case_types)] type c_int = i32;\n#[repr(C)]\n{declaration}\n\
         fn main() {{ println!(\"{{}} {{}} {{}} {{}}\", \
         std::mem::size_of::<SignalAction>(), std::mem::offset_of!(SignalAction, handler), \
         std::mem::offset_of!(SignalAction, sa_mask), std::mem::offset_of!(SignalAction, sa_flags)); }}"
    );
    let c = format!(
        "#include <stddef.h>\n#include <stdio.h>\n\
         typedef unsigned long sigset_t; typedef void (*_sig_func_ptr)(int);\n{c_declaration}\n\
         int main(void) {{ printf(\"%zu %zu %zu %zu\\n\", sizeof(struct sigaction), \
         offsetof(struct sigaction, sa_handler), offsetof(struct sigaction, sa_mask), \
         offsetof(struct sigaction, sa_flags)); }}"
    );
    let mut layouts = Vec::new();
    for (compiler, extension, source) in [("rustc", "rs", rust), ("cc", "c", c)] {
        let source_path = temporary.join(format!("probe.{extension}"));
        let binary = temporary.join(extension);
        fs::write(&source_path, source).unwrap();
        let output = Command::new(compiler)
            .arg(&source_path)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(binary).output().unwrap();
        assert!(output.status.success());
        layouts.push(output.stdout);
    }
    assert_eq!(
        layouts[0], layouts[1],
        "runtime/newlib sigaction ABI mismatch"
    );
}
