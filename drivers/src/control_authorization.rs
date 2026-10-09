/// Verify authority on the IPC-authenticated sender, never a request field.
/// The controller separately checks its launch-bound token.
pub(crate) fn manager_request(
    sender_endpoint: u64,
    check_authority: impl FnOnce(u64) -> bool,
) -> bool {
    sender_endpoint != 0 && check_authority(sender_endpoint)
}
