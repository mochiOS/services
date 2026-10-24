//! Compiled into a diagnostic POSIX binary only. Its already inherited FS
//! endpoint is used directly; no service lookup or extra production RPC exists.
use super::RuntimeFilesystem;
use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
use mochi_user_platform as platform;
use mochios_filesystem_protocol as wire;
use posix_service::fifo_inode::{METADATA_RIGHTS, validate_reply};

fn payload(path: &[u8], uid: u32) -> Vec<u8> {
    let mut payload = vec![0; wire::CREDENTIALS_MAX_LEN + path.len()];
    let length = wire::encode_credentials_payload(uid, uid, &[], path, &mut payload).unwrap();
    payload.truncate(length);
    payload
}

fn open(
    fs: &RuntimeFilesystem,
    path: &[u8],
    uid: u32,
) -> Result<(wire::NodeStatus, IpcObjectHandle), i32> {
    let payload = payload(path, uid);
    let mut request = vec![0; wire::HEADER_LEN + payload.len()];
    let header = wire::Header {
        opcode: wire::OP_OPEN_AT,
        request_id: 71,
        length: payload.len() as u32,
        flags: wire::OPEN_AT_READ | wire::OPEN_AT_RETAIN_FIFO,
        ..Default::default()
    };
    let length = wire::encode(header, &payload, &mut request).unwrap();
    let mut reply = vec![0; wire::HEADER_LEN + wire::NODE_STATUS_LEN];
    let mut objects = IpcObjectHandles::default();
    let native = fs
        .call(&request[..length], &mut reply, &mut objects)
        .map_err(|_| -5)?;
    let result = posix_service::filesystem_transport::reply_frame(&reply, native, 71)
        .and_then(|(header, payload)| validate_reply(header, 71, payload, &objects));
    match result {
        Ok(status) => Ok((status, objects.handles[0])),
        Err(error) => {
            super::close_runtime_handles(&objects);
            Err(error)
        }
    }
}

fn stat(fs: &RuntimeFilesystem, handle: u32) -> wire::NodeStatus {
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle,
        rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
        reserved: 0,
    };
    fs.status_call(
        wire::Header {
            opcode: wire::OP_STAT_HANDLE,
            request_id: 72,
            ..Default::default()
        },
        &[],
        objects,
    )
    .unwrap()
}

pub fn run(fs: &RuntimeFilesystem) {
    let identity = platform::process::current_execution_identity().unwrap();
    let path = format!("/tmp/fifo-inode-187-{}", identity.process_id);
    let encoded_path = payload(path.as_bytes(), 0);
    let create = || {
        fs.empty_call(
            wire::Header {
                opcode: wire::OP_CREATE_FIFO_AT,
                request_id: 70,
                length: encoded_path.len() as u32,
                mode: 0o600,
                ..Default::default()
            },
            &encoded_path,
            IpcObjectHandles::default(),
        )
        .unwrap()
    };
    create();
    let (before, metadata) = open(fs, path.as_bytes(), 0).unwrap();
    assert_eq!(
        platform::handle::rights(metadata.handle).unwrap(),
        METADATA_RIGHTS
    );
    assert!(platform::handle::read(metadata.handle, &mut [0; 1]).is_err());
    assert!(
        platform::handle::duplicate(
            metadata.handle,
            METADATA_RIGHTS | mnu_abi::HANDLE_RIGHT_READ
        )
        .is_err()
    );
    assert_eq!(stat(fs, metadata.handle), before);
    platform::io::stdout(b"fifo-inode: PASS authorized open and metadata-only native authority\n")
        .unwrap();
    assert_eq!(open(fs, path.as_bytes(), 501).err(), Some(-13));
    platform::io::stdout(b"fifo-inode: PASS denied credentials return no Handle\n").unwrap();
    let alias = platform::handle::duplicate(metadata.handle, METADATA_RIGHTS).unwrap();
    platform::handle::close(metadata.handle).unwrap();
    fs.empty_call(
        wire::Header {
            opcode: wire::OP_UNLINK_AT,
            request_id: 73,
            length: encoded_path.len() as u32,
            ..Default::default()
        },
        &encoded_path,
        IpcObjectHandles::default(),
    )
    .unwrap();
    create();
    let (replacement, new_metadata) = open(fs, path.as_bytes(), 0).unwrap();
    assert_ne!(replacement.node_id, before.node_id);
    let retained = stat(fs, alias);
    assert_eq!(retained.node_id, before.node_id);
    assert_eq!(
        (retained.kind, retained.link_count),
        (wire::NODE_TYPE_FIFO, 0)
    );
    platform::handle::close(alias).unwrap();
    platform::handle::close(new_metadata.handle).unwrap();
    fs.empty_call(
        wire::Header {
            opcode: wire::OP_UNLINK_AT,
            request_id: 74,
            length: encoded_path.len() as u32,
            ..Default::default()
        },
        &encoded_path,
        IpcObjectHandles::default(),
    )
    .unwrap();
    platform::io::stdout(
        b"fifo-inode: PASS retained Handle survives unlink, replacement and original close\n",
    )
    .unwrap();
}
