//! Only owner-scoped native observations enter the userspace collector. No
//! client metadata/PID/FD is treated as a root or as an object identifier.
use mochi_user_platform as platform;
use posix_service::socket::Streams;

pub const INTERVAL_NS: u64 = 1_000_000_000;
pub fn collect(streams: &mut Streams) -> Result<Vec<u64>, i32> {
    streams.collect_record_cycles(
        |handle| match platform::handle::identify_provider_object(handle) {
            Ok(id) => Ok(Some(id)),
            Err(error) => identify_status(error.raw()),
        },
        |id| {
            platform::handle::provider_object_reference_count(id)
                .map_err(|error| reference_count_status(error.raw()))
        },
    )
}

fn identify_status(raw: i64) -> Result<Option<u64>, i32> {
    use mnu_abi::status::Error;
    match Error::from_raw(raw as u64) {
        // Non-provider objects and foreign Providers are not our namespace.
        // Their indirect/native references remain conservative roots.
        Some(Error::InvalidArgument | Error::AccessDenied) => Ok(None),
        _ => Err(mochios_posix_protocol::status::normalize_failure(raw)),
    }
}

fn reference_count_status(raw: i64) -> i32 {
    if mnu_abi::status::Error::from_raw(raw as u64) == Some(mnu_abi::status::Error::InvalidArgument)
    {
        // These IDs came from our own stream table. A missing Provider means
        // its release may still be queued: retry the entire observation,
        // never infer zero references or discard queues from a partial graph.
        return -11;
    }
    mochios_posix_protocol::status::normalize_failure(raw)
}
