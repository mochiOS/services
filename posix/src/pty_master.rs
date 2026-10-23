//! Master-only allocation. No native slave object exists during publication.
use crate::{
    ObjectResponse, OpenedObject,
    pty::{PtyManager, PtyPair},
};
use mochios_posix_protocol as protocol;
use std::sync::Mutex;

/// Native create/close operate on local references. Synchronization and name
/// registration may make peer RPC, so neither may run under the manager lock.
/// Callback failures use negative POSIX wire status, never native status bits.
pub fn open(
    manager: &Mutex<PtyManager>,
    request_id: u64,
    create: impl FnOnce(u64, u64) -> Result<u32, i32>,
    synchronize: impl FnOnce(PtyPair) -> Result<(), i32>,
    publish: impl FnOnce(PtyPair) -> Result<(), i32>,
    mut close: impl FnMut(u32),
) -> ObjectResponse<u32> {
    let pair = {
        let mut manager = manager.lock().unwrap();
        match manager.open_with_slave_lock(true) {
            Ok(pair) => {
                // Drop the internal preparation-only slave before any native
                // reference, factory or name can escape. No provider release
                // callback is needed because no native slave was ever made.
                if let Err(error) = manager.release(pair.slave_object_id) {
                    manager.discard(pair);
                    return failure(request_id, -error);
                }
                pair
            }
            Err(error) => return failure(request_id, -error),
        }
    };
    let rights = crate::pty_factory::MASTER_RIGHTS;
    let mut master = None;
    let result = (|| {
        let handle = create(pair.master_object_id, rights)?;
        if handle == 0 {
            return Err(protocol::STATUS_EIO);
        }
        master = Some(handle);
        synchronize(pair)?;
        publish(pair)?;
        Ok(handle)
    })();
    match result {
        Ok(handle) => ObjectResponse {
            response: crate::status_response(request_id, 0),
            handles: vec![OpenedObject { handle, rights }],
        },
        Err(status) => {
            if let Some(handle) = master {
                close(handle);
            }
            manager.lock().unwrap().discard(pair);
            failure(request_id, status)
        }
    }
}

fn failure(request_id: u64, status: i32) -> ObjectResponse<u32> {
    ObjectResponse {
        response: crate::status_response(request_id, status),
        handles: Vec::new(),
    }
}
