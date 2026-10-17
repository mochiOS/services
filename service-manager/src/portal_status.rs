pub(crate) fn failure_status(error: u64) -> i32 {
    // Prompt/session protocols expose POSIX wire failures, not native tags or
    // newlib C errno numbers. Invalid/unknown failures must never become zero.
    mochios_posix_protocol::status::normalize_failure(error as i64)
}
