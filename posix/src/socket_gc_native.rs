//! Only owner-scoped native observations enter the userspace collector. No
//! client metadata/PID/FD is treated as a root or as an object identifier.
use mochi_user_platform as platform;
use posix_service::socket::Streams;

pub const INTERVAL_NS: u64 = 1_000_000_000;
pub fn collect(streams: &mut Streams) -> Result<Vec<u64>, i32> {
    streams.collect_record_cycles(
        |handle| match platform::handle::identify_provider_object(handle) {
            Ok(id) => Ok(Some(id)),
            // RAM/streams and foreign Providers are not this socket namespace.
            // Any indirect/native references they keep are conservative roots.
            Err(error) if matches!(error.raw(), -9 | -13) => Ok(None),
            Err(error) => Err(error.raw() as i32),
        },
        |id| {
            platform::handle::provider_object_reference_count(id)
                .map_err(|error| reference_count_status(error.raw()))
        },
    )
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
