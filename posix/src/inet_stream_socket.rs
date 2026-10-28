//! TCP Provider descriptions and connect notifications. Neither identifier is
//! a process FD or authority; native delivery authenticates every operation.
use crate::inet_stream::{Backend, ConnectProgress, Stream};
use mnu_abi::provider;
use mochios_posix_protocol::{FileStatus, socket as wire};

const DESCRIPTION_TAG: u64 = 5 << 59;
const JOB_TAG: u64 = 6 << 59;
const MASK: u64 = (1 << 59) - 1;
const SIGNALS: u64 = mnu_abi::HANDLE_SIGNAL_READABLE
    | mnu_abi::HANDLE_SIGNAL_WRITABLE
    | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
pub fn is_stream(id: u64) -> bool {
    id & !MASK == DESCRIPTION_TAG && id & MASK != 0
}
pub fn is_job(id: u64) -> bool {
    id & !MASK == JOB_TAG && id & MASK != 0
}
fn native_signals(bits: u32) -> u64 {
    (if bits & wire::READY_READ != 0 {
        mnu_abi::HANDLE_SIGNAL_READABLE
    } else {
        0
    }) | (if bits & (wire::READY_WRITE | wire::WRITE_CLOSED) != 0 {
        mnu_abi::HANDLE_SIGNAL_WRITABLE
    } else {
        0
    }) | (if bits & wire::WRITE_ERROR != 0
        || bits & (wire::READ_CLOSED | wire::WRITE_CLOSED) == wire::READ_CLOSED | wire::WRITE_CLOSED
    {
        mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
    } else {
        0
    })
}
struct Row<B: Backend> {
    id: u64,
    socket: Stream<B>,
    forwarded: u64,
    credentials: (u32, u32),
}
struct Job<H> {
    id: u64,
    description: u64,
    attempt: u64,
    result: Option<Result<(), i32>>,
    signalled: bool,
    // An owned native reference keeps the description alive until the final
    // notification reference is released. Its Drop performs the actual close.
    _source: H,
}
pub struct Registry<B: Backend, H> {
    next: u64,
    next_job: u64,
    rows: Vec<Row<B>>,
    jobs: Vec<Job<H>>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Started {
    Connected,
    InProgress,
    Waiting(u64),
}
impl<B: Backend, H> Registry<B, H> {
    pub const fn new() -> Self {
        Self {
            next: 1,
            next_job: 1,
            rows: Vec::new(),
            jobs: Vec::new(),
        }
    }
    fn reserve(&mut self) -> Result<u64, i32> {
        if self.rows.len() >= crate::socket::MAX_ENDPOINTS || self.next > MASK {
            return Err(-23);
        }
        self.rows.try_reserve(1).map_err(|_| -12)?;
        let id = DESCRIPTION_TAG | self.next;
        self.next += 1;
        Ok(id)
    }
    pub fn insert(&mut self, socket: Stream<B>, credentials: (u32, u32)) -> Result<u64, i32> {
        let id = self.reserve()?;
        self.rows.push(Row {
            id,
            socket,
            forwarded: 0,
            credentials,
        });
        Ok(id)
    }
    fn row(&mut self, id: u64) -> Result<&mut Row<B>, i32> {
        self.rows.iter_mut().find(|r| r.id == id).ok_or(-9)
    }
    pub fn remove(&mut self, id: u64) -> Result<(), i32> {
        let index = self.rows.iter().position(|r| r.id == id).ok_or(-9)?;
        self.rows.swap_remove(index);
        Ok(())
    }
    /// Reserve all fallible local storage before starting an asynchronous open.
    /// The source reference is consumed on every path, retained only by a job.
    pub fn connect(
        &mut self,
        id: u64,
        address: wire::Address<'_>,
        source: H,
    ) -> Result<Started, i32> {
        let blocking = self.row(id)?.socket.options() & wire::NONBLOCKING == 0;
        if blocking {
            if self.jobs.len() >= crate::socket::MAX_ENDPOINTS || self.next_job > MASK {
                return Err(-23);
            }
            self.jobs.try_reserve(1).map_err(|_| -12)?;
        }
        let socket = &mut self.row(id)?.socket;
        match socket.connect(address)? {
            ConnectProgress::Connected => Ok(Started::Connected),
            ConnectProgress::Pending if !blocking => Ok(Started::InProgress),
            ConnectProgress::Pending => {
                let attempt = socket.attempt();
                let job = JOB_TAG | self.next_job;
                self.next_job += 1;
                self.jobs.push(Job {
                    id: job,
                    description: id,
                    attempt,
                    result: None,
                    signalled: false,
                    _source: source,
                });
                Ok(Started::Waiting(job))
            }
        }
    }
    fn result(&mut self, id: u64, expire: bool) -> Result<(), i32> {
        let index = self.jobs.iter().position(|j| j.id == id).ok_or(-9)?;
        if let Some(result) = self.jobs[index].result {
            return result;
        }
        let (description, attempt) = (self.jobs[index].description, self.jobs[index].attempt);
        let socket = &mut self.row(description)?.socket;
        let result = if expire {
            socket.cancel_connect(attempt, -110)
        } else {
            socket.connect_result(attempt)
        };
        let result = match result {
            Ok(ConnectProgress::Pending) => return Err(-11),
            Ok(ConnectProgress::Connected) => Ok(()),
            Err(e) => Err(e),
        };
        self.jobs[index].result = Some(result);
        result
    }
    pub fn release_job(&mut self, id: u64) -> Result<(), i32> {
        let index = self.jobs.iter().position(|j| j.id == id).ok_or(-9)?;
        let job = self.jobs.swap_remove(index);
        if job.result.is_none() {
            if let Ok(row) = self.row(job.description) {
                let _ = row.socket.cancel_connect(job.attempt, -125);
            }
        }
        // Only now drop the owned source reference. The subsequent native
        // OP_RELEASE for a retired job cannot target a new job (IDs never reuse).
        drop(job);
        Ok(())
    }
    /// The caller may allocate a native Provider for this reserved ID before
    /// consuming a transport accept. Failure closes that provisional reference.
    pub fn accept<R>(
        &mut self,
        listener: u64,
        request: wire::Accept,
        credentials: (u32, u32),
        prepare: impl FnOnce(u64) -> Result<R, i32>,
    ) -> Result<(u64, R), i32> {
        let id = self.reserve()?;
        let prepared = prepare(id)?;
        let socket = self.row(listener)?.socket.accept(request)?;
        self.rows.push(Row {
            id,
            socket,
            forwarded: 0,
            credentials,
        });
        Ok((id, prepared))
    }
    pub fn peer_address(&mut self, id: u64) -> Result<crate::inet_datagram::Endpoint, i32> {
        self.row(id)?.socket.peer_address()
    }
    pub fn pump(&mut self, mut signal: impl FnMut(u64, u64) -> Result<(), i32>) {
        for index in 0..self.jobs.len() {
            let id = self.jobs[index].id;
            let _ = self.result(id, false);
            let job = &mut self.jobs[index];
            if job.result.is_some() && !job.signalled {
                job.signalled = signal(id, mnu_abi::HANDLE_SIGNAL_READABLE).is_ok();
            }
        }
        for row in &mut self.rows {
            let ready = row
                .socket
                .readiness()
                .map(native_signals)
                .unwrap_or(SIGNALS);
            if ready != row.forwarded && signal(row.id, ready).is_ok() {
                row.forwarded = ready;
            }
        }
    }
    pub fn watches(&self, mut add: impl FnMut(B::Handle, u64)) {
        for row in &self.rows {
            let interests = SIGNALS & !row.forwarded;
            if interests != 0 {
                add(row.socket.binding_handle(), interests);
            }
        }
    }
    pub fn dispatch(
        &mut self,
        bytes: &[u8],
        delivery: u32,
        count: u32,
        response: &mut [u8],
    ) -> Result<Option<usize>, i32> {
        let (header, payload) = provider::RequestHeader::decode(bytes).map_err(|_| -22)?;
        let native = delivery == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT && count == 0;
        if native && header.opcode == provider::OP_RELEASE {
            if is_job(header.object_id) {
                self.release_job(header.object_id)?;
            } else {
                self.remove(header.object_id)?;
            }
            return Ok(None);
        }
        let capacity = if matches!(
            header.opcode,
            provider::OP_READ | provider::OP_READ_AT | provider::OP_CONTROL
        ) {
            header.length as usize
        } else {
            0
        };
        if response.len() < provider::RESPONSE_HEADER_LEN + capacity {
            return Err(-22);
        }
        let mut data = [0; provider::MAX_DATA_LEN];
        let result = (|| {
            if !native {
                return Err(-13);
            }
            if is_job(header.object_id) {
                if header.opcode != provider::OP_CONTROL {
                    return Err(-95);
                }
                if !payload.is_empty() || header.length != 0 {
                    return Err(-22);
                }
                match header.basis {
                    wire::CONTROL_CONNECT_RESULT => self.result(header.object_id, false)?,
                    wire::CONTROL_CONNECT_EXPIRE => self.result(header.object_id, true)?,
                    _ => return Err(-95),
                }
                return Ok((0, 0));
            }
            let row = self.row(header.object_id)?;
            let socket = &mut row.socket;
            match header.opcode {
                provider::OP_MEMORY_OBJECT => Ok((0, 0)),
                provider::OP_SEEK | provider::OP_WRITE_AT => Err(-29),
                provider::OP_WRITE => socket.send(payload).map(|n| (n as u64, 0)),
                provider::OP_READ | provider::OP_READ_AT => {
                    if header.basis != 0 {
                        return Err(-22);
                    }
                    socket
                        .receive(
                            header.opcode == provider::OP_READ_AT,
                            &mut data[..header.length as usize],
                        )
                        .map(|n| (n as u64, n))
                }
                provider::OP_CONTROL => match header.basis {
                    wire::CONTROL_KIND
                    | wire::CONTROL_ACCEPTING
                    | wire::CONTROL_GET_OPTIONS
                    | wire::CONTROL_TAKE_ERROR
                    | wire::CONTROL_READINESS
                        if payload.is_empty() && header.length == 4 =>
                    {
                        let value = match header.basis {
                            wire::CONTROL_KIND => wire::Kind::Stream as u32,
                            wire::CONTROL_ACCEPTING => u32::from(socket.accepting()),
                            wire::CONTROL_GET_OPTIONS => socket.options(),
                            wire::CONTROL_TAKE_ERROR => socket.take_error()?,
                            _ => socket.readiness()?,
                        };
                        data[..4].copy_from_slice(&value.to_le_bytes());
                        Ok((4, 4))
                    }
                    wire::CONTROL_SET_OPTIONS if payload.len() == 4 && header.length == 0 => {
                        socket.set_options(u32::from_le_bytes(payload.try_into().unwrap()))?;
                        Ok((0, 0))
                    }
                    wire::CONTROL_GET_RECEIVE_TIMEOUT | wire::CONTROL_GET_SEND_TIMEOUT
                        if payload.is_empty() && header.length == 8 =>
                    {
                        let value = if header.basis == wire::CONTROL_GET_RECEIVE_TIMEOUT {
                            socket.receive_timeout()
                        } else {
                            socket.send_timeout()
                        };
                        data[..8].copy_from_slice(&value.to_le_bytes());
                        Ok((8, 8))
                    }
                    wire::CONTROL_SET_RECEIVE_TIMEOUT | wire::CONTROL_SET_SEND_TIMEOUT
                        if payload.len() == 8 && header.length == 0 =>
                    {
                        let value = u64::from_le_bytes(payload.try_into().unwrap());
                        if header.basis == wire::CONTROL_SET_RECEIVE_TIMEOUT {
                            socket.set_receive_timeout(value);
                        } else {
                            socket.set_send_timeout(value);
                        }
                        Ok((0, 0))
                    }
                    wire::CONTROL_BIND if header.length == 0 => {
                        socket.bind(wire::Address::decode(payload).map_err(|_| -22)?)?;
                        Ok((0, 0))
                    }
                    wire::CONTROL_LISTEN if payload.len() == 4 && header.length == 0 => {
                        socket.listen(u32::from_le_bytes(payload.try_into().unwrap()) as usize)?;
                        Ok((0, 0))
                    }
                    wire::CONTROL_SHUTDOWN if payload.len() == 4 && header.length == 0 => {
                        socket.shutdown(u32::from_le_bytes(payload.try_into().unwrap()))?;
                        Ok((0, 0))
                    }
                    wire::CONTROL_LOCAL_ADDRESS | wire::CONTROL_PEER_ADDRESS
                        if payload.is_empty() =>
                    {
                        let endpoint = if header.basis == wire::CONTROL_LOCAL_ADDRESS {
                            socket.local_address()?
                        } else {
                            socket.peer_address()?
                        };
                        let n = endpoint
                            .as_address()
                            .encode(&mut data[..header.length as usize])
                            .map_err(|_| -22)?;
                        Ok((n as u64, n))
                    }
                    wire::CONTROL_STAT
                        if payload.is_empty()
                            && header.length as usize
                                == mochios_posix_protocol::FILE_STATUS_LEN =>
                    {
                        let status = FileStatus {
                            // A socket's virtual inode is independent of the
                            // native Provider type tag. Keep its device distinct
                            // from UNIX descriptions with the same low counter.
                            device: 0x5443,
                            inode: row.id & MASK,
                            mode: 0o140600,
                            uid: row.credentials.0,
                            gid: row.credentials.1,
                            block_size: provider::MAX_DATA_LEN as i64,
                            ..Default::default()
                        };
                        mochios_posix_protocol::encode_file_status(status, &mut data)
                            .map_err(|_| -5)?;
                        Ok((header.length as u64, header.length as usize))
                    }
                    _ => Err(-95),
                },
                _ => Err(-95),
            }
        })();
        let (status, value, n) = match result {
            Ok((value, n)) => (0, value, n),
            Err(error) => (error, 0, 0),
        };
        provider::ResponseHeader {
            opcode: header.opcode,
            object_id: header.object_id,
            status: i64::from(status),
            value,
            data_length: n as u32,
        }
        .encode(&data[..n], response)
        .map(Some)
        .map_err(|_| -22)
    }
}
