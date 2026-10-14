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
                .map_err(|error| error.raw() as i32)
        },
    )
}
