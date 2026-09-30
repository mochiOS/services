use std::collections::HashMap;

use ext4plus::error::Ext4Error;
use ext4plus::file::File;
use ext4plus::{Ext4, FileType, Metadata};
use mochios_filesystem_protocol as protocol;

const EIO: i32 = 5;
const ENOENT: i32 = 2;
const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const EISDIR: i32 = 21;
const ENOTDIR: i32 = 20;
const ENOSYS: i32 = 38;
const EFBIG: i32 = 27;

pub struct Response {
    pub header: protocol::Header,
    pub payload: Vec<u8>,
}

pub struct FilesystemService {
    fs: Ext4,
    nodes: HashMap<u64, String>,
    node_ids: HashMap<String, u64>,
    opens: HashMap<u64, File>,
    next_node_id: u64,
    next_open_id: u64,
}

impl FilesystemService {
    pub fn new(fs: Ext4) -> Self {
        let mut nodes = HashMap::new();
        let mut node_ids = HashMap::new();
        nodes.insert(1, "/".to_owned());
        node_ids.insert("/".to_owned(), 1);
        Self {
            fs,
            nodes,
            node_ids,
            opens: HashMap::new(),
            next_node_id: 2,
            next_open_id: 1,
        }
    }

    pub fn handle(&mut self, request: protocol::Header, payload: &[u8]) -> Response {
        let result = match request.opcode {
            protocol::OP_MOUNT => self.mount(request),
            protocol::OP_LOOKUP => self.lookup(request, payload),
            protocol::OP_OPEN => self.open(request),
            protocol::OP_CLOSE => self.close(request),
            protocol::OP_READ => self.read(request),
            protocol::OP_WRITE => self.write(request, payload),
            protocol::OP_STAT => self.stat(request),
            protocol::OP_TRUNCATE => self.truncate(request),
            protocol::OP_READLINK => self.read_link(request),
            protocol::OP_SYNC => Ok(self.success(request)),
            _ => Err(ENOSYS),
        };
        result.unwrap_or_else(|errno| self.error(request, errno))
    }

    fn mount(&self, request: protocol::Header) -> Result<Response, i32> {
        let metadata = self.fs.metadata("/").map_err(errno)?;
        Ok(self.metadata_response(request, 1, metadata))
    }

    fn lookup(&mut self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        let path = decode_path(payload)?;
        let metadata = self.fs.symlink_metadata(path).map_err(errno)?;
        let node_id = if let Some(node_id) = self.node_ids.get(path) {
            *node_id
        } else {
            let node_id = self.next_node_id;
            self.next_node_id = self.next_node_id.checked_add(1).ok_or(EIO)?;
            self.nodes.insert(node_id, path.to_owned());
            self.node_ids.insert(path.to_owned(), node_id);
            node_id
        };
        Ok(self.metadata_response(request, node_id, metadata))
    }

    fn open(&mut self, request: protocol::Header) -> Result<Response, i32> {
        let path = self.nodes.get(&request.node_id).ok_or(ENOENT)?;
        let file = self.fs.open(path.as_str()).map_err(errno)?;
        let open_id = self.next_open_id;
        self.next_open_id = self.next_open_id.checked_add(1).ok_or(EIO)?;
        self.opens.insert(open_id, file);
        let mut response = self.success(request);
        response.header.open_id = open_id;
        Ok(response)
    }

    fn close(&mut self, request: protocol::Header) -> Result<Response, i32> {
        self.opens.remove(&request.open_id).ok_or(EBADF)?;
        Ok(self.success(request))
    }

    fn read(&mut self, request: protocol::Header) -> Result<Response, i32> {
        let length = (request.flags as usize).min(protocol::MAX_IO_LEN);
        let file = self.opens.get_mut(&request.open_id).ok_or(EBADF)?;
        let mut payload = vec![0u8; length];
        let mut done = 0;
        while done < payload.len() {
            let count = file
                .read_bytes_at(&mut payload[done..], request.offset + done as u64)
                .map_err(errno)?;
            if count == 0 {
                break;
            }
            done += count;
        }
        payload.truncate(done);
        let mut response = self.success(request);
        response.header.length = done as u32;
        response.payload = payload;
        Ok(response)
    }

    fn write(&mut self, request: protocol::Header, payload: &[u8]) -> Result<Response, i32> {
        if payload.len() > protocol::MAX_IO_LEN {
            return Err(EINVAL);
        }
        let file = self.opens.get_mut(&request.open_id).ok_or(EBADF)?;
        let mut done = 0;
        while done < payload.len() {
            let count = file
                .write_bytes_at(&payload[done..], request.offset + done as u64)
                .map_err(errno)?;
            if count == 0 {
                return Err(EIO);
            }
            done += count;
        }
        let mut response = self.success(request);
        response.header.offset = done as u64;
        Ok(response)
    }

    fn stat(&self, request: protocol::Header) -> Result<Response, i32> {
        let (node_id, metadata) = if request.open_id != 0 {
            let file = self.opens.get(&request.open_id).ok_or(EBADF)?;
            (request.node_id, file.inode().metadata())
        } else {
            let path = self.nodes.get(&request.node_id).ok_or(ENOENT)?;
            (
                request.node_id,
                self.fs.symlink_metadata(path.as_str()).map_err(errno)?,
            )
        };
        Ok(self.metadata_response(request, node_id, metadata))
    }

    fn truncate(&mut self, request: protocol::Header) -> Result<Response, i32> {
        self.opens
            .get_mut(&request.open_id)
            .ok_or(EBADF)?
            .truncate(request.offset)
            .map_err(errno)?;
        Ok(self.success(request))
    }

    fn read_link(&self, request: protocol::Header) -> Result<Response, i32> {
        let path = self.nodes.get(&request.node_id).ok_or(ENOENT)?;
        let target = self.fs.read_link(path.as_str()).map_err(errno)?;
        let payload = target.as_ref().to_vec();
        if payload.len() > protocol::MAX_IO_LEN {
            return Err(EFBIG);
        }
        let mut response = self.success(request);
        response.header.length = payload.len() as u32;
        response.payload = payload;
        Ok(response)
    }

    fn metadata_response(
        &self,
        request: protocol::Header,
        node_id: u64,
        metadata: Metadata,
    ) -> Response {
        let mut response = self.success(request);
        response.header.node_id = node_id;
        response.header.offset = metadata.len();
        response.header.mode = u32::from(metadata.mode());
        response.header.flags = node_type(metadata.file_type());
        response
    }

    fn success(&self, request: protocol::Header) -> Response {
        Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: request.request_id,
                mount_id: request.mount_id,
                status: 0,
                ..protocol::Header::default()
            },
            payload: Vec::new(),
        }
    }

    fn error(&self, request: protocol::Header, errno: i32) -> Response {
        let mut response = self.success(request);
        response.header.status = -errno;
        response
    }
}

fn decode_path(payload: &[u8]) -> Result<&str, i32> {
    if payload.is_empty() || payload.len() > protocol::MAX_PATH_LEN || payload.contains(&0) {
        return Err(EINVAL);
    }
    let path = std::str::from_utf8(payload).map_err(|_| EINVAL)?;
    if !path.starts_with('/') {
        return Err(EINVAL);
    }
    Ok(path)
}

fn node_type(file_type: FileType) -> u32 {
    if file_type.is_regular_file() {
        protocol::NODE_TYPE_REGULAR
    } else if file_type.is_dir() {
        protocol::NODE_TYPE_DIRECTORY
    } else if file_type.is_symlink() {
        protocol::NODE_TYPE_SYMLINK
    } else {
        protocol::NODE_TYPE_SPECIAL
    }
}

fn errno(error: Ext4Error) -> i32 {
    match error {
        Ext4Error::NotFound => ENOENT,
        Ext4Error::IsADirectory => EISDIR,
        Ext4Error::NotADirectory => ENOTDIR,
        Ext4Error::Readonly | Ext4Error::Encrypted => EACCES,
        Ext4Error::NoSpace => ENOSPC,
        Ext4Error::AlreadyExists => EEXIST,
        Ext4Error::FileTooLarge => EFBIG,
        Ext4Error::MalformedPath | Ext4Error::NotAbsolute | Ext4Error::NotASymlink => EINVAL,
        _ => EIO,
    }
}
