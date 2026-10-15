#[path = "../../tty/src/shell_launch.rs"]
mod shell_launch;

#[test]
fn missing_shell_reports_the_original_posix_error() {
    let missing = format!("/tmp/mochios-no-such-shell-{}", std::process::id());
    let error = shell_launch::spawn_shell(&missing, 19, 7).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn tty_has_no_private_capability_or_path_launch_fallback() {
    let source = include_str!("../../tty/src/main.rs");
    for old in [
        "spawn_manifest(",
        "encode_spawn_args(",
        "resolve_execution_security(",
        "CAPABILITY_REPLY_BUF",
    ] {
        assert!(!source.contains(old));
    }
    assert!(source.contains("let _shell = match shell_launch::spawn_shell"));
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("authorize_exec_path("));
    assert!(runtime.contains("syscall::image::replace_bounded("));
}
