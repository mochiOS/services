//! Query a delegated account endpoint without paths, names of services or hashes.
use mochios_posix_client::Transport;
use mochios_posix_protocol::{self as protocol, account as wire};
use std::vec::Vec;

pub fn lookup<T: Transport>(
    transport: &T,
    id: u64,
    query: &[u8],
    error: impl Fn(T::Error) -> i32,
) -> Result<Vec<u8>, i32> {
    let query = wire::decode_query(query).map_err(|_| -22)?;
    let mut request = [0; wire::MAX_MESSAGE];
    let n = wire::encode_request(id, query, &mut request).map_err(|_| -22)?;
    let mut response = [0; wire::MAX_MESSAGE];
    let n = transport
        .call(&request[..n], &mut response)
        .map_err(error)?;
    let bytes = response.get(..n).ok_or(-5)?;
    let record = wire::decode_response(id, bytes).map_err(|_| -5)??;
    let mut output = Vec::new();
    output.try_reserve(wire::MAX_RECORD).map_err(|_| -12)?;
    output.resize(wire::MAX_RECORD, 0);
    let length = protocol::account::encode_record(record, &mut output).map_err(|_| -5)?;
    output.truncate(length);
    Ok(output)
}
