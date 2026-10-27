use std::process::Command;

#[test]
fn remove_handles_files_directories_links_and_reentrant_errors() {
    let source = include_str!("../../../user/runtime/newlib_reent.c");
    let mut program = String::from(
        r#"
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
struct _reent { int error; };
static struct _reent current;
#define _REENT (&current)
#define _REENT_ERRNO(r) ((r)->error)
static unsigned directory_attempts;
static int injected_error;
static int test_unlink(const char *path) {
    if (injected_error) { errno = injected_error; return -1; }
    return unlink(path);
}
static int test_rmdir(const char *path) { ++directory_attempts; return rmdir(path); }
#define unlink test_unlink
#define rmdir test_rmdir
#define remove port_remove
"#,
    );
    for entry in ["int _remove_r(", "int remove("] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&source[start..end]);
    }
    program.push_str(
        r#"
#undef unlink
#undef rmdir
int main(void) {
    char directory[] = "/tmp/mochios-remove-XXXXXX";
    assert(mkdtemp(directory) && chdir(directory) == 0);
    int fd = open("file", O_CREAT | O_RDWR, 0600);
    assert(fd >= 0 && write(fd, "x", 1) == 1);
    assert(remove("file") == 0 && directory_attempts == 0);
    char byte;
    assert(pread(fd, &byte, 1, 0) == 1 && byte == 'x' && close(fd) == 0);
    assert(mkdir("empty", 0700) == 0 && remove("empty") == 0);
    assert(directory_attempts == 1);
    assert(mkdir("target", 0700) == 0 && symlink("target", "link") == 0);
    assert(remove("link") == 0 && directory_attempts == 1);
    struct stat st;
    assert(stat("target", &st) == 0 && S_ISDIR(st.st_mode));
    fd = open("target/child", O_CREAT | O_WRONLY, 0600);
    assert(fd >= 0 && close(fd) == 0);
    struct _reent separate = {71};
    assert(_remove_r(&separate, "target") == -1 && separate.error == ENOTEMPTY);
    assert(directory_attempts == 2);
    assert(remove("missing") == -1 && current.error == ENOENT);
    assert(directory_attempts == 2);
    injected_error = EACCES;
    assert(_remove_r(&separate, "target") == -1 && separate.error == EACCES);
    assert(directory_attempts == 2);
    injected_error = EIO;
    assert(remove("target") == -1 && current.error == EIO && directory_attempts == 2);
    injected_error = 0;
    assert(remove("target/child") == 0 && remove("target") == 0);
    assert(chdir("/") == 0 && rmdir(directory) == 0);
    return 0;
}
"#,
    );
    let temp = std::env::temp_dir().join(format!("mochios-remove-test-{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();
    let input = temp.join("remove.c");
    let binary = temp.join("remove-test");
    std::fs::write(&input, program).unwrap();
    let output = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(input)
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
    std::fs::remove_dir_all(temp).unwrap();
}
