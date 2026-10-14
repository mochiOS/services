use std::process::Command;

#[test]
fn c_message_layout_and_control_iteration_match_the_runtime_abi() {
    run("socket_message_abi.c");
}

#[test]
fn host_stream_ancillary_boundaries_match_the_queue_contract() {
    run("socket_stream_ancillary_abi.c");
}

fn run(source: &str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = std::env::temp_dir().join(format!(
        "mochios-socket-message-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let compiled = Command::new("cc")
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=undefined",
        ])
        .arg("-I")
        .arg(root.join("user/libc-port/include"))
        .arg(root.join("services/posix/tests").join(source))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}
