use std::io::Write;
use std::process::{Command, Stdio};

fn c_function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("void {name}(")).unwrap();
    let body = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (offset, byte) in source.as_bytes()[body..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=body + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated C function");
}

#[test]
fn actual_reent_shims_separate_cache_reclamation_from_callback_dispatch() {
    let source = include_str!("../../../user/runtime/newlib_reent.c");
    let destroy = c_function(source, "__mochios_reent_destroy");
    let discard = c_function(source, "__mochios_reent_discard");
    let program = format!(
        r#"
#include <stddef.h>
#include <assert.h>
struct _reent {{ void (*cleanup)(struct _reent *); unsigned cache; }};
#define _REENT_CLEANUP(r) ((r)->cleanup)
static unsigned calls, freed;
static void callback(struct _reent *r) {{ assert(r->cache == 0); ++calls; }}
static void _reclaim_reent(struct _reent *r) {{
    freed += r->cache; r->cache = 0;
    if (r->cleanup) r->cleanup(r);
}}
{destroy}
{discard}
int main(void) {{
    struct _reent parent = {{callback, 1}}, child = parent;
    __mochios_reent_discard(&child);
    assert(freed == 1 && calls == 0 && child.cleanup == NULL);
    assert(parent.cleanup == callback && parent.cache == 1);
    __mochios_reent_destroy(&parent);
    assert(freed == 2 && calls == 1);
    struct _reent empty = {{NULL, 0}};
    __mochios_reent_discard(&empty);
    assert(freed == 2 && calls == 1);
}}
"#
    );
    let directory = std::env::temp_dir().join(format!("mochios-fork-reent-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("cc")
        .args([
            "-x", "c", "-", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o",
        ])
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn child_reclamation_separates_quiescent_cache_cleanup_from_live_memory_retention() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let discard = source
        .split("fn discard_fork_thread_control(")
        .nth(1)
        .unwrap()
        .split("fn reclaim_thread_control(")
        .next()
        .unwrap();
    assert!(discard.contains("THREAD_EXITED | THREAD_REAPING => ThreadReclamation::ForkChild"));
    assert!(discard.contains("THREAD_RUNNING => ThreadReclamation::ForkLive"));
    assert!(discard.contains("reclaim_thread_control(control, reason)"));
    assert!(discard.contains("process_exit(127)"));
    let child = source
        .split("fn clone_registered_process()")
        .nth(1)
        .unwrap()
        .split("return Ok((0,")
        .next()
        .unwrap();
    assert!(child.contains("discard_fork_thread_control(other)"));
    assert!(!child.contains("release_thread_control(other)"));
    assert!(source.contains("ThreadReclamation::ThreadExit => __mochios_reent_destroy"));
    assert!(source.contains("ThreadReclamation::ForkChild => __mochios_reent_discard"));
}
