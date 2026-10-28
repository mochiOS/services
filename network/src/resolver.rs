//! Bounded DNS jobs. I/O operations never wait; all resources are private to
//! this engine and are released on completion, cancellation or context loss.
use alloc::vec::Vec;
use mochios_network_stack::{
    DNS_MAX_MESSAGE_LEN, DnsCache, DnsError, DnsName, DnsRecordName, DnsRecordSet, DnsRecordType,
    DnsResponseCode, Ipv4Config, decode_dns_records, encode_dns_record_query,
};

const JOB_LIMIT: usize = 16;
const STEP_BUDGET: usize = 4;
const RETRY_DELAY: u64 = 500;
const RETRY_LIMIT: u8 = 3;

pub(crate) trait Transport {
    type Datagram: Copy;
    type Stream: Copy;
    fn context(&self) -> Result<Ipv4Config, i32>;
    fn entropy(&mut self) -> Result<u64, i32>;
    fn open_datagram(&mut self, server: [u8; 4], entropy: u64) -> Result<Self::Datagram, i32>;
    fn send_datagram(&mut self, socket: Self::Datagram, data: &[u8], now: u64) -> Result<(), i32>;
    fn receive_datagram(&mut self, socket: Self::Datagram) -> Result<Option<Vec<u8>>, i32>;
    fn close_datagram(&mut self, socket: Self::Datagram);
    fn open_stream(&mut self, server: [u8; 4], entropy: u64) -> Result<Self::Stream, i32>;
    fn stream_connected(&mut self, socket: Self::Stream) -> Result<bool, i32>;
    fn send_stream(&mut self, socket: Self::Stream, data: &[u8]) -> Result<usize, i32>;
    fn receive_stream(&mut self, socket: Self::Stream, data: &mut [u8]) -> Result<usize, i32>;
    fn close_stream(&mut self, socket: Self::Stream, now: u64);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Query(u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Wire(DnsError),
    Transport(i32),
}
impl From<DnsError> for Failure {
    fn from(value: DnsError) -> Self {
        Self::Wire(value)
    }
}
impl From<i32> for Failure {
    fn from(value: i32) -> Self {
        Self::Transport(if value < 0 && value != i32::MIN {
            value
        } else {
            -5
        })
    }
}
impl Failure {
    pub(crate) fn status(&self) -> i32 {
        match self {
            Self::Transport(error) => *error,
            Self::Wire(DnsError::Response(DnsResponseCode::NameError)) => -2,
            Self::Wire(
                DnsError::Timeout
                | DnsError::RetryLimit
                | DnsError::TruncatedResponse
                | DnsError::Response(DnsResponseCode::ServerFailure),
            ) => -11,
            Self::Wire(DnsError::CacheCapacity) => -12,
            Self::Wire(DnsError::UnsupportedRecord) => -95,
            _ => -22,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Answer {
    pub records: DnsRecordSet,
    pub from_cache: bool,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Statistics {
    pub queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub failures: u64,
    pub timeouts: u64,
}

#[derive(Clone, Copy)]
enum Stage {
    Prepare,
    Datagram,
    Connecting,
    Sending,
    Length,
    Body,
}

struct Job<D, S> {
    id: Query,
    context: Ipv4Config,
    deadline: u64,
    name: DnsRecordName,
    kind: DnsRecordType,
    prefix: Option<(DnsRecordSet, u64)>,
    stage: Stage,
    datagram: Option<D>,
    stream: Option<S>,
    transaction: u16,
    query: Vec<u8>,
    sent: usize,
    attempts: u8,
    next_send: u64,
    length: [u8; 2],
    length_read: usize,
    body: Vec<u8>,
    body_read: usize,
    answer: Option<Result<Answer, Failure>>,
}

impl<D: Copy, S: Copy> Job<D, S> {
    fn close<T: Transport<Datagram = D, Stream = S>>(&mut self, io: &mut T, now: u64) {
        if let Some(socket) = self.datagram.take() {
            io.close_datagram(socket);
        }
        if let Some(socket) = self.stream.take() {
            io.close_stream(socket, now);
        }
    }

    fn response<T: Transport<Datagram = D, Stream = S>>(
        &mut self,
        io: &mut T,
        records: DnsRecordSet,
        now: u64,
    ) -> Result<Option<DnsRecordSet>, Failure> {
        let follow = records.values().is_empty() && records.canonical_name() != &self.name;
        let next_name = records.canonical_name().clone();
        let records = match self.prefix.take() {
            Some((prefix, started)) => {
                prefix.follow_answer(records, now.saturating_sub(started))?
            }
            None => records,
        };
        self.close(io, now);
        if !follow {
            return Ok(Some(records));
        }
        self.prefix = Some((records, now));
        self.name = next_name;
        self.stage = Stage::Prepare;
        Ok(None)
    }

    fn tcp<T: Transport<Datagram = D, Stream = S>>(&mut self, io: &mut T) -> Result<(), Failure> {
        if let Some(socket) = self.datagram.take() {
            io.close_datagram(socket);
        }
        let entropy = io.entropy()?;
        let length = u16::try_from(self.query.len()).map_err(|_| DnsError::MessageTooLarge)?;
        let mut query = Vec::new();
        query
            .try_reserve_exact(self.query.len() + 2)
            .map_err(|_| Failure::Transport(-12))?;
        query.extend_from_slice(&length.to_be_bytes());
        query.extend_from_slice(&self.query);
        self.stream = Some(io.open_stream(self.context.dns, entropy)?);
        self.query = query;
        self.sent = 0;
        self.length_read = 0;
        self.body.clear();
        self.body_read = 0;
        self.stage = Stage::Connecting;
        Ok(())
    }

    fn step<T: Transport<Datagram = D, Stream = S>>(
        &mut self,
        io: &mut T,
        now: u64,
        stats: &mut Statistics,
    ) -> Result<Option<DnsRecordSet>, Failure> {
        if now >= self.deadline {
            return Err(DnsError::Timeout.into());
        }
        for _ in 0..STEP_BUDGET {
            match self.stage {
                Stage::Prepare => {
                    let entropy = io.entropy()?;
                    let mut query = [0; DNS_MAX_MESSAGE_LEN];
                    self.transaction = (entropy >> 32) as u16;
                    let n = encode_dns_record_query(
                        self.transaction,
                        &self.name,
                        self.kind,
                        &mut query,
                    )?;
                    let socket = match io.open_datagram(self.context.dns, entropy) {
                        Ok(socket) => socket,
                        Err(-11) => return Ok(None),
                        Err(error) => return Err(error.into()),
                    };
                    self.datagram = Some(socket);
                    self.query.clear();
                    self.query
                        .try_reserve(n)
                        .map_err(|_| Failure::Transport(-12))?;
                    self.query.extend_from_slice(&query[..n]);
                    self.next_send = now;
                    self.attempts = 0;
                    self.stage = Stage::Datagram;
                }
                Stage::Datagram => {
                    let socket = self.datagram.ok_or(Failure::Transport(-5))?;
                    // Accept an already queued response before retransmission.
                    if self.attempts != 0
                        && let Some(packet) = io.receive_datagram(socket)?
                    {
                        match decode_dns_records(&packet, self.transaction, &self.name, self.kind) {
                            Ok(records) => return self.response(io, records, now),
                            Err(DnsError::TruncatedResponse) => {
                                self.tcp(io)?;
                                continue;
                            }
                            Err(
                                DnsError::TransactionMismatch
                                | DnsError::QuestionMismatch
                                | DnsError::Response(DnsResponseCode::ServerFailure),
                            ) => continue,
                            Err(error) => return Err(error.into()),
                        }
                    }
                    if now >= self.next_send {
                        if self.attempts >= RETRY_LIMIT {
                            self.tcp(io)?;
                            continue;
                        }
                        match io.send_datagram(socket, &self.query, now) {
                            Ok(()) => {
                                stats.queries = stats.queries.saturating_add(1);
                                self.next_send = now.saturating_add(RETRY_DELAY << self.attempts);
                                self.attempts += 1;
                                if self.attempts == 1 {
                                    continue;
                                }
                            }
                            Err(-11) => self.next_send = now.saturating_add(1),
                            Err(error) => return Err(error.into()),
                        }
                    }
                    return Ok(None);
                }
                Stage::Connecting => {
                    if !io.stream_connected(self.stream.ok_or(Failure::Transport(-5))?)? {
                        return Ok(None);
                    }
                    self.stage = Stage::Sending;
                }
                Stage::Sending => {
                    let socket = self.stream.ok_or(Failure::Transport(-5))?;
                    let remaining = &self.query[self.sent..];
                    let count = match io.send_stream(socket, remaining) {
                        Err(-11) => return Ok(None),
                        result => result?,
                    };
                    if count == 0 || count > remaining.len() {
                        return Err(Failure::Transport(-5));
                    }
                    self.sent += count;
                    if self.sent == self.query.len() {
                        stats.queries = stats.queries.saturating_add(1);
                        self.stage = Stage::Length;
                    }
                }
                Stage::Length => {
                    let socket = self.stream.ok_or(Failure::Transport(-5))?;
                    let out = &mut self.length[self.length_read..];
                    let count = match io.receive_stream(socket, out) {
                        Err(-11) => return Ok(None),
                        result => result?,
                    };
                    if count == 0 {
                        return Err(Failure::Transport(-104));
                    }
                    if count > out.len() {
                        return Err(Failure::Transport(-5));
                    }
                    self.length_read += count;
                    if self.length_read == 2 {
                        let length = usize::from(u16::from_be_bytes(self.length));
                        if length < 12 {
                            return Err(DnsError::InvalidHeader.into());
                        }
                        self.body.clear();
                        self.body
                            .try_reserve_exact(length)
                            .map_err(|_| Failure::Transport(-12))?;
                        self.body.resize(length, 0);
                        self.body_read = 0;
                        self.stage = Stage::Body;
                    }
                }
                Stage::Body => {
                    let socket = self.stream.ok_or(Failure::Transport(-5))?;
                    let end = (self.body_read + 4096).min(self.body.len());
                    let out = &mut self.body[self.body_read..end];
                    let count = match io.receive_stream(socket, out) {
                        Err(-11) => return Ok(None),
                        result => result?,
                    };
                    if count == 0 {
                        return Err(Failure::Transport(-104));
                    }
                    if count > out.len() {
                        return Err(Failure::Transport(-5));
                    }
                    self.body_read += count;
                    if self.body_read == self.body.len() {
                        match decode_dns_records(
                            &self.body,
                            self.transaction,
                            &self.name,
                            self.kind,
                        ) {
                            Ok(records) => return self.response(io, records, now),
                            Err(DnsError::TransactionMismatch | DnsError::QuestionMismatch) => {
                                self.length_read = 0;
                                self.stage = Stage::Length;
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

pub(crate) struct Resolver<D, S> {
    jobs: Vec<Job<D, S>>,
    next: u64,
    context: Option<Ipv4Config>,
    cache: DnsCache,
    pub statistics: Statistics,
}
impl<D: Copy, S: Copy> Resolver<D, S> {
    pub(crate) fn new() -> Self {
        Self {
            jobs: Vec::new(),
            next: 1,
            context: None,
            cache: DnsCache::new(32),
            statistics: Statistics::default(),
        }
    }

    fn sync<T: Transport<Datagram = D, Stream = S>>(
        &mut self,
        io: &mut T,
        now: u64,
    ) -> Result<Ipv4Config, i32> {
        let config = io.context();
        if self.context != config.as_ref().ok().copied() {
            self.context = config.as_ref().ok().copied();
            self.cache.clear();
            for job in &mut self.jobs {
                if job.answer.is_none() {
                    job.close(io, now);
                    job.answer = Some(Err(Failure::from(
                        config.as_ref().err().copied().unwrap_or(-99),
                    )));
                    self.statistics.failures = self.statistics.failures.saturating_add(1);
                }
            }
        }
        config
    }

    pub(crate) fn start<T: Transport<Datagram = D, Stream = S>>(
        &mut self,
        io: &mut T,
        name: DnsRecordName,
        kind: DnsRecordType,
        now: u64,
        timeout: u64,
    ) -> Result<Query, i32> {
        let context = self.sync(io, now)?;
        if self.jobs.len() >= JOB_LIMIT || self.next == u64::MAX {
            return Err(-11);
        }
        self.jobs.try_reserve(1).map_err(|_| -12)?;
        let id = Query(self.next);
        self.next += 1;
        let answer = self.cache.lookup_records(&name, kind, now).map(|records| {
            Ok(Answer {
                records,
                from_cache: true,
            })
        });
        if answer.is_some() {
            self.statistics.cache_hits = self.statistics.cache_hits.saturating_add(1);
        } else {
            self.statistics.cache_misses = self.statistics.cache_misses.saturating_add(1);
        }
        self.jobs.push(Job {
            id,
            context,
            deadline: now.saturating_add(timeout),
            name,
            kind,
            prefix: None,
            stage: Stage::Prepare,
            datagram: None,
            stream: None,
            transaction: 0,
            query: Vec::new(),
            sent: 0,
            attempts: 0,
            next_send: now,
            length: [0; 2],
            length_read: 0,
            body: Vec::new(),
            body_read: 0,
            answer,
        });
        Ok(id)
    }

    pub(crate) fn pump<T: Transport<Datagram = D, Stream = S>>(&mut self, io: &mut T, now: u64) {
        let _ = self.sync(io, now);
        for job in &mut self.jobs {
            if job.answer.is_some() {
                continue;
            }
            match job.step(io, now, &mut self.statistics) {
                Ok(None) => (),
                Ok(Some(records)) => {
                    job.close(io, now);
                    let _ = self.cache.insert_records(&records, now);
                    job.answer = Some(Ok(Answer {
                        records,
                        from_cache: false,
                    }));
                }
                Err(error) => {
                    job.close(io, now);
                    if matches!(
                        error,
                        Failure::Wire(DnsError::Timeout | DnsError::RetryLimit)
                            | Failure::Transport(-110)
                    ) {
                        self.statistics.timeouts = self.statistics.timeouts.saturating_add(1);
                    } else {
                        self.statistics.failures = self.statistics.failures.saturating_add(1);
                    }
                    job.answer = Some(Err(error));
                }
            }
        }
    }

    pub(crate) fn take(&mut self, id: Query) -> Result<Option<Result<Answer, Failure>>, i32> {
        let i = self.jobs.iter().position(|job| job.id == id).ok_or(-9)?;
        if self.jobs[i].answer.is_none() {
            return Ok(None);
        }
        Ok(self.jobs.swap_remove(i).answer)
    }

    pub(crate) fn cancel<T: Transport<Datagram = D, Stream = S>>(
        &mut self,
        io: &mut T,
        id: Query,
        now: u64,
    ) -> Result<(), i32> {
        let i = self.jobs.iter().position(|job| job.id == id).ok_or(-9)?;
        let mut job = self.jobs.swap_remove(i);
        job.close(io, now);
        Ok(())
    }
}

pub(crate) fn hostname(name: &str) -> Result<DnsRecordName, Failure> {
    Ok(DnsRecordName::from(&DnsName::parse(name)?))
}
