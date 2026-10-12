use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_c_exports_share_the_file_lock_and_invert_the_native_try_result() {
    let source = include_str!("../../../user/runtime/newlib_reent.c");
    let mut program = String::from(
        r#"
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#define __SSTR 0x0200
struct lock { unsigned owner, depth; };
typedef struct { int _flags; struct lock *_lock; } FILE;
static unsigned caller = 1;
static void acquire(struct lock *lock) { assert(lock); assert(!lock->owner || lock->owner == caller); lock->owner = caller; ++lock->depth; }
static void release(struct lock *lock) { assert(lock && lock->owner == caller && lock->depth); if (--lock->depth == 0) lock->owner = 0; }
static int __lock_try_acquire_recursive(struct lock *lock) {
    assert(lock); if (lock->owner && lock->owner != caller) return 0; acquire(lock); return 1;
}
#define _flockfile(fp) do { if (!((fp)->_flags & __SSTR)) acquire((fp)->_lock); } while (0)
#define _funlockfile(fp) do { if (!((fp)->_flags & __SSTR)) release((fp)->_lock); } while (0)
"#,
    );
    for entry in ["void flockfile(", "int ftrylockfile(", "void funlockfile("] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&source[start..end]);
    }
    program.push_str(r#"
int main(void) {
    struct lock lock = {0, 0}; FILE file = {0, &lock};
    errno = 123;
    flockfile(&file); flockfile(&file);
    assert(lock.depth == 2 && lock.owner == 1);
    assert(ftrylockfile(&file) == 0 && lock.depth == 3);
    funlockfile(&file);
    caller = 2;
    assert(ftrylockfile(&file) != 0 && lock.depth == 2 && lock.owner == 1);
    caller = 1;
    funlockfile(&file); funlockfile(&file);
    assert(lock.depth == 0 && lock.owner == 0);
    caller = 2;
    assert(ftrylockfile(&file) == 0 && lock.owner == 2);
    funlockfile(&file);
    assert(errno == 123);
    FILE private_string = {__SSTR, NULL};
    flockfile(&private_string); assert(ftrylockfile(&private_string) == 0); funlockfile(&private_string);
    return 0;
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-stdio-locks-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-x", "c", "-"])
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
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed = Command::new(&executable).output().unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn c_runtime_sources_are_part_of_the_runtime_build_input() {
    let inputs = include_str!("../../../build/mmake/inputs.mk");
    let runtime = inputs.split("runtime-inputs:").nth(1).unwrap();
    assert!(runtime.contains("@watch user/runtime/**"));
}
