//! Borrow the scoped factory grant for one read-only metadata exchange.
use mnu_abi::{HANDLE_RIGHT_TRANSFER, IpcObjectHandle, IpcObjectHandles};
use mochios_filesystem_protocol::device_observation as wire;

pub fn observe_with(
    endpoint: u32,
    factory: u32,
    request: wire::Request,
    invoke: impl FnOnce(u32, &[u8], &mut [u8], &mut IpcObjectHandles) -> Result<u64, i32>,
    mut close: impl FnMut(u32),
) -> Result<Vec<u8>, i32> {
    if endpoint == 0 || factory == 0 || endpoint == factory {
        return Err(13);
    }
    wire::Request::decode(&request.encode()).map_err(|status| -status)?;
    let mut exchanged = IpcObjectHandles::default();
    exchanged.count = 1;
    exchanged.handles[0] = IpcObjectHandle {
        handle: factory,
        reserved: 0,
        rights: HANDLE_RIGHT_TRANSFER,
    };
    let mut reply = vec![0; 8 + request.capacity as usize];
    // Failure leaves the request's borrowed attachment in `exchanged`.
    // No reply references have been installed, so do not close that grant.
    let delivered = invoke(endpoint, &request.encode(), &mut reply, &mut exchanged)?;
    let length = delivered as u32 as usize;
    let result = (|| {
        if exchanged.delivery_flags != 0
            || exchanged.count != 0
            || length < 8
            || length > reply.len()
        {
            return Err(5);
        }
        let status = i64::from_le_bytes(reply[..8].try_into().unwrap());
        if status != 0 {
            return Err(
                if length == 8 && status < 0 && status >= -i64::from(i32::MAX) {
                    -status as i32
                } else {
                    5
                },
            );
        }
        Ok(reply[8..length].to_vec())
    })();
    // Every native-success response attachment is newly owned and unexpected,
    // including malformed responses; reclaim each installed handle once.
    for (index, object) in exchanged
        .handles
        .iter()
        .take(exchanged.count as usize)
        .enumerate()
    {
        if object.handle != 0
            && !exchanged.handles[..index]
                .iter()
                .any(|old| old.handle == object.handle)
        {
            close(object.handle);
        }
    }
    result
}
