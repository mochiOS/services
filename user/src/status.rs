/// Accepts either a native encoded failure or an internal positive errno.
/// Account protocol failures must always carry a negative signed status.
pub fn wire_status(raw: u64) -> i32 {
    if raw == 0 {
        return 0;
    }
    mochios_posix_protocol::status::normalize_failure(raw as i64)
}
