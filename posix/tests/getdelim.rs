use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_line_reader_handles_growth_binary_delimiters_eof_and_allocation_failures() {
    let backend = include_str!("../../../libraries/newlib/newlib/libc/stdio/getdelim.c");
    let start = backend.find("ssize_t\n__getdelim (").unwrap();
    let body = &backend[start..];
    let port = include_str!("../../../user/runtime/newlib_reent.c");
    let mut program = String::from(
        r#"
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define __SERR 1
#define __SEOF 2
#define EOF (-1)
#define MIN_LINE_SIZE 4
#define DEFAULT_LINE_SIZE 128
typedef struct { int _flags, locked; const unsigned char *bytes; size_t length, pos, error_at; } FILE;
static unsigned allocations, fail_at;
static void *injected_realloc(void *pointer, size_t length) {
    if (++allocations == fail_at) { errno = ENOMEM; return NULL; }
    return realloc(pointer, length);
}
static int getc_unlocked(FILE *fp) {
    assert(fp->locked == 1);
    if (fp->pos == fp->error_at) { fp->_flags |= __SERR; errno = EIO; return EOF; }
    if (fp->pos == fp->length) { fp->_flags |= __SEOF; return EOF; }
    return fp->bytes[fp->pos++];
}
#define CHECK_INIT(reent, fp) ((void)(fp))
#define _REENT 0
#define __sfeof(fp) ((fp)->_flags & __SEOF)
#define __sferror(fp) ((fp)->_flags & __SERR)
#define _newlib_flockfile_start(fp) { ++(fp)->locked;
#define _newlib_flockfile_end(fp) --(fp)->locked; }
#define realloc injected_realloc
"#,
    );
    program.push_str(body);
    program.push_str("\n#undef realloc\n");
    for entry in ["ssize_t getdelim(", "ssize_t getline("] {
        let start = port.find(entry).unwrap();
        let end = start + port[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&port[start..end]);
    }
    program.push_str(r#"
static FILE file(const unsigned char *bytes, size_t length) {
    FILE fp = {0, 0, bytes, length, 0, (size_t)-1}; return fp;
}
int main(void) {
    char *line = NULL; size_t capacity = 0;
    FILE fp = file((const unsigned char *)"abc\nlast", 8);
    assert(getline(&line, &capacity, &fp) == 4 && !memcmp(line, "abc\n\0", 5));
    assert(getline(&line, &capacity, &fp) == 4 && !memcmp(line, "last\0", 5));
    errno = 123;
    assert(getline(&line, &capacity, &fp) == -1 && errno == 123 && fp.locked == 0 && (fp._flags & __SEOF));
    free(line); line = NULL; capacity = 0;
    unsigned char binary[] = {'a', 0, 'b', 255, 'c'};
    fp = file(binary, sizeof(binary));
    assert(getdelim(&line, &capacity, 255, &fp) == 4);
    assert(!memcmp(line, binary, 4) && line[4] == 0 && fp.pos == 4 && fp.locked == 0);
    free(line); line = NULL; capacity = 0;
    unsigned char long_line[600]; memset(long_line, 'x', sizeof(long_line)); long_line[599] = '\n';
    fp = file(long_line, sizeof(long_line));
    assert(getline(&line, &capacity, &fp) == 600 && capacity >= 601 && line[600] == 0);
    free(line); line = NULL; capacity = 0;
    fp = file(long_line, sizeof(long_line)); allocations = 0; fail_at = 1;
    assert(getline(&line, &capacity, &fp) == -1 && errno == ENOMEM);
    assert(line == NULL && capacity == 0 && fp.locked == 0 && (fp._flags & __SERR));
    line = malloc(4); capacity = 4; char *original = line;
    fp = file(long_line, sizeof(long_line)); allocations = 0; fail_at = 1;
    assert(getline(&line, &capacity, &fp) == -1 && errno == ENOMEM);
    assert(line == original && capacity == 4 && !memcmp(line, "xxx\0", 4));
    assert(fp.locked == 0 && (fp._flags & __SERR)); free(line);
    line = NULL; capacity = 0; fail_at = 0;
    fp = file(long_line, sizeof(long_line)); fp.error_at = 5;
    assert(getline(&line, &capacity, &fp) == -1 && errno == EIO && fp.locked == 0);
    assert(!memcmp(line, "xxxxx\0", 6) && (fp._flags & __SERR)); free(line);
    fp = file(binary, sizeof(binary));
    assert(getline(NULL, &capacity, &fp) == -1 && errno == EINVAL && fp.locked == 0);
    return 0;
}
"#);
    compile_and_run(&program, "normal");
    let overflow = program.replace(
        "const size_t max_line_size = (size_t)-1 >> 1;",
        "const size_t max_line_size = 7;",
    );
    let start = overflow.find("int main(void) {").unwrap();
    let overflow = format!(
        "{}{}",
        &overflow[..start],
        r#"
int main(void) {
    unsigned char bytes[12]; memset(bytes, 'x', sizeof(bytes));
    FILE fp = file(bytes, sizeof(bytes)); char *line = NULL; size_t capacity = 0;
    assert(getline(&line, &capacity, &fp) == -1 && errno == EOVERFLOW);
    assert(fp.locked == 0 && (fp._flags & __SERR));
    assert(!memcmp(line, "xxxxxxx\0", 8)); free(line); return 0;
}
"#
    );
    compile_and_run(&overflow, "overflow");
}

fn compile_and_run(program: &str, suffix: &str) {
    let directory = std::env::temp_dir().join(format!(
        "mochios-getdelim-{}-{suffix}-{}",
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
fn public_headers_expose_the_posix_2008_names() {
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/stdio.h");
    assert!(header
        .split("#if __POSIX_VISIBLE >= 200809")
        .skip(1)
        .any(|section| section.contains("ssize_t getdelim (")
            && section.contains("ssize_t getline (")));
    let bindings = include_str!("../../../libraries/libc/newlib/mochios.rs");
    assert!(bindings.contains("pub fn getdelim("));
    assert!(bindings.contains("pub fn getline("));
}
