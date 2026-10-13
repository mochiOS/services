/// Launches through the standard POSIX process implementation. Authorization
/// is performed by the runtime, and all inherited FD/CLOEXEC state follows the
/// same path as an ordinary Rust application. No capability strings are argv.
pub(crate) fn spawn_shell(
    program: &str,
    tty_endpoint: u64,
    logger_endpoint: u64,
) -> std::io::Result<std::process::Child> {
    std::process::Command::new(program)
        .arg(tty_endpoint.to_string())
        .arg(logger_endpoint.to_string())
        .spawn()
}
