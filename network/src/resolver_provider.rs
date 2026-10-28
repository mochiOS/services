//! Explicit DNS authority and immutable result objects. Only the creating
//! endpoint's kernel metadata authenticates attachments and Provider requests.
use crate::resolver::Answer;
use alloc::vec::Vec;
use mnu_abi::provider;
use mochi_user_platform as platform;
use mochios_net_device_protocol::resolver as wire;
use mochios_network_stack::{DnsRecordName, DnsRecordType, DnsRecordValue};

// ProviderObjectIdentify returns IDs in the native nonnegative result domain.
const FACTORY_TAG: u64 = 3 << 60;
const JOB_TAG: u64 = 5 << 60;
const TAG_MASK: u64 = 15 << 60;
const ID_LIMIT: u64 = 1 << 60;
const FACTORY_LIMIT: usize = 64;
const JOB_LIMIT: usize = 16;
pub(crate) const FACTORY_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;
pub(crate) const JOB_RIGHTS: u64 =
    FACTORY_RIGHTS | mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WAIT;
const SIGNAL: u64 = mnu_abi::HANDLE_SIGNAL_READABLE;

use crate::resolver_backend::Backend;
struct Factory {
    id: u64,
    limits: wire::Limits,
}
struct Job<Q> {
    id: u64,
    query: Option<Q>,
    kind: wire::Kind,
    question: Vec<u8>,
    ready: bool,
    status: i32,
    result: Vec<u8>,
}
impl<Q: Copy> Job<Q> {
    fn fail(&mut self, status: i32) {
        self.status = if status < 0 && status != i32::MIN {
            status
        } else {
            -5
        };
        self.result
            .truncate(wire::RESULT_HEADER_LEN + self.question.len());
        // The failure buffer was allocated before the backend job started.
        let encoded = wire::Name::decode(&self.question)
            .and_then(|name| wire::encode_failure(self.kind, self.status, name, &mut self.result));
        debug_assert!(encoded.is_ok());
        self.ready = true;
    }
    fn finish(&mut self, answer: Answer) -> Result<(), i32> {
        let kind = match answer.records.record_type() {
            DnsRecordType::A => wire::Kind::A,
            DnsRecordType::Aaaa => wire::Kind::Aaaa,
            DnsRecordType::Ptr => wire::Kind::Ptr,
        };
        let question = wire::Name::decode(&self.question).map_err(|_| -5)?;
        if kind != self.kind
            || !question
                .matches(wire::Name::decode(answer.records.question().wire()).map_err(|_| -5)?)
        {
            return Err(-5);
        }
        let canonical =
            wire::Name::decode(answer.records.canonical_name().wire()).map_err(|_| -5)?;
        fn value(v: &DnsRecordValue) -> &[u8] {
            match v {
                DnsRecordValue::Ipv4(v) => v,
                DnsRecordValue::Ipv6(v) => v,
                DnsRecordValue::Name(v) => v.wire(),
            }
        }
        let mut size = wire::RESULT_HEADER_LEN + self.question.len() + canonical.bytes().len();
        for name in answer.records.aliases() {
            size = size.checked_add(2 + name.wire().len()).ok_or(-75)?;
        }
        for v in answer.records.values() {
            size = size.checked_add(2 + value(v).len()).ok_or(-75)?;
        }
        if size > wire::MAX_RESULT_LEN {
            return Err(-75);
        }
        self.result
            .try_reserve(size.saturating_sub(self.result.len()))
            .map_err(|_| -12)?;
        self.result.resize(size, 0);
        wire::encode_result(
            kind,
            0,
            question,
            Some(canonical),
            answer.from_cache,
            answer.records.aliases().iter().map(|n| n.wire()),
            answer.records.values().iter().map(value),
            &mut self.result,
        )
        .map_err(|_| -5)?;
        self.status = 0;
        self.ready = true;
        Ok(())
    }
}

pub(crate) struct Server<Q> {
    endpoint: Option<u32>,
    next: u64,
    factories: Vec<Factory>,
    jobs: Vec<Job<Q>>,
}
impl<Q: Copy> Server<Q> {
    pub(crate) fn new(endpoint: Option<u32>) -> Self {
        Self {
            endpoint,
            next: 1,
            factories: Vec::new(),
            jobs: Vec::new(),
        }
    }
    fn id(&mut self, tag: u64) -> Result<u64, i32> {
        if self.next >= ID_LIMIT {
            return Err(-24);
        }
        let id = tag | self.next;
        self.next += 1;
        Ok(id)
    }
    fn attached_limits(
        &self,
        handles: &platform::ipc::IpcObjectHandles,
    ) -> Result<wire::Limits, i32> {
        if handles.count != 1
            || !matches!(
                handles.delivery_flags,
                0 | mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
            )
        {
            return Err(-13);
        }
        let h = handles.handles[0];
        if h.handle == 0 || h.reserved != 0 || h.rights != mnu_abi::HANDLE_RIGHT_CONTROL {
            return Err(-13);
        }
        let id = platform::handle::identify_provider_object(h.handle).map_err(|_| -13)?;
        self.factories
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.limits)
            .ok_or(-13)
    }
    fn factory(&mut self, limits: wire::Limits) -> Result<(u64, u32), i32> {
        if self.factories.len() >= FACTORY_LIMIT {
            return Err(-24);
        }
        self.factories.try_reserve(1).map_err(|_| -12)?;
        let id = self.id(FACTORY_TAG)?;
        let h =
            platform::handle::create_provider_object(self.endpoint.ok_or(-5)?, id, FACTORY_RIGHTS)
                .map_err(|_| -5)?;
        self.factories.push(Factory { id, limits });
        Ok((id, h))
    }
    fn open<B: Backend<Query = Q>>(
        &mut self,
        request: wire::Request<'_>,
        backend: &mut B,
        now: u64,
    ) -> Result<(u64, u32), i32> {
        if self.jobs.len() >= JOB_LIMIT {
            return Err(-24);
        }
        self.jobs.try_reserve(1).map_err(|_| -12)?;
        let mut question = Vec::new();
        question
            .try_reserve_exact(request.name.bytes().len())
            .map_err(|_| -12)?;
        question.extend_from_slice(request.name.bytes());
        let mut result = Vec::new();
        result
            .try_reserve_exact(wire::RESULT_HEADER_LEN + question.len())
            .map_err(|_| -12)?;
        result.resize(wire::RESULT_HEADER_LEN + question.len(), 0);
        wire::encode_failure(request.kind, -125, request.name, &mut result).map_err(|_| -5)?;
        let id = self.id(JOB_TAG)?;
        let h = platform::handle::create_provider_object(self.endpoint.ok_or(-5)?, id, JOB_RIGHTS)
            .map_err(|_| -5)?;
        if platform::handle::signal_provider_object(id, 0, SIGNAL).is_err() {
            let _ = platform::handle::close(h);
            return Err(-5);
        }
        let kind = match request.kind {
            wire::Kind::A => DnsRecordType::A,
            wire::Kind::Aaaa => DnsRecordType::Aaaa,
            wire::Kind::Ptr => DnsRecordType::Ptr,
        };
        let mut job = Job {
            id,
            query: None,
            kind: request.kind,
            question,
            ready: false,
            status: 0,
            result,
        };
        match DnsRecordName::from_wire(&job.question)
            .map_err(|_| -22)
            .and_then(|name| backend.start(name, kind, now, u64::from(request.timeout)))
        {
            Ok(q) => job.query = Some(q),
            Err(error) => job.fail(error),
        }
        self.jobs.push(job);
        Ok((id, h))
    }
    fn remove<B: Backend<Query = Q>>(&mut self, id: u64, backend: &mut B, now: u64) {
        self.factories.retain(|f| f.id != id);
        if let Some(i) = self.jobs.iter().position(|j| j.id == id) {
            if let Some(q) = self.jobs.swap_remove(i).query {
                let _ = backend.cancel(q, now);
            }
        }
    }
    fn update<B: Backend<Query = Q>>(&mut self, i: usize, backend: &mut B, now: u64) {
        let row = &mut self.jobs[i];
        if row.ready {
            return;
        }
        let Some(q) = row.query else {
            row.fail(-5);
            return;
        };
        let result = match backend.take(q) {
            Ok(None) => return,
            Ok(Some(result)) => result.map_err(|e| e.status()),
            Err(e) => {
                let _ = backend.cancel(q, now);
                Err(e)
            }
        };
        row.query = None;
        match result {
            Ok(answer) => {
                if let Err(error) = row.finish(answer) {
                    row.fail(error)
                }
            }
            Err(error) => row.fail(error),
        }
    }
    pub(crate) fn pump<B: Backend<Query = Q>>(&mut self, backend: &mut B, now: u64) {
        let mut i = 0;
        while i < self.jobs.len() {
            self.update(i, backend, now);
            let row = &self.jobs[i];
            let set = if row.ready { SIGNAL } else { 0 };
            if platform::handle::signal_provider_object(row.id, set, SIGNAL & !set).is_err() {
                let id = row.id;
                self.remove(id, backend, now);
            } else {
                i += 1;
            }
        }
    }
    pub(crate) fn dispatch<B: Backend<Query = Q>>(
        &mut self,
        sender: u64,
        bytes: &[u8],
        handles: &platform::ipc::IpcObjectHandles,
        backend: &mut B,
        now: u64,
    ) -> bool {
        if bytes.starts_with(b"NDNS") {
            let op = bytes
                .get(6..8)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .unwrap_or(0);
            let result = (|| {
                let op = wire::operation(bytes).map_err(|_| -22)?;
                match op {
                    wire::ACQUIRE => {
                        let limits = wire::decode_scoped(bytes).map_err(|_| -22)?;
                        if handles.count != 0
                            || !matches!(
                                handles.delivery_flags,
                                0 | mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
                            )
                        {
                            return Err(-13);
                        }
                        if platform::capability::check_thread(sender, "net.connect") != Ok(1) {
                            return Err(-13);
                        }
                        self.factory(limits).map(Some)
                    }
                    wire::DERIVE => {
                        let limits = wire::decode_scoped(bytes).map_err(|_| -22)?;
                        if !self.attached_limits(handles)?.contains(limits) {
                            return Err(-13);
                        }
                        self.factory(limits).map(Some)
                    }
                    wire::VALIDATE => {
                        if bytes.len() != 8 {
                            return Err(-22);
                        }
                        self.attached_limits(handles)?;
                        Ok(None)
                    }
                    wire::OPEN => {
                        let request = wire::Request::decode(bytes).map_err(|_| -22)?;
                        let limits = self.attached_limits(handles)?;
                        if limits.scopes & request.kind.scope() == 0
                            || request.timeout > limits.maximum_timeout
                        {
                            return Err(-13);
                        }
                        self.open(request, backend, now).map(Some)
                    }
                    _ => Err(-38),
                }
            })();
            let mut response = [0; wire::REPLY_LEN];
            match result {
                Ok(Some((id, h))) => {
                    wire::reply(op, 0, &mut response).unwrap();
                    let mut attached = platform::ipc::IpcObjectHandles::default();
                    attached.count = 1;
                    attached.handles[0] = platform::ipc::IpcObjectHandle {
                        handle: h,
                        reserved: 0,
                        rights: if id & TAG_MASK == FACTORY_TAG {
                            FACTORY_RIGHTS
                        } else {
                            JOB_RIGHTS
                        },
                    };
                    self.pump(backend, now);
                    // pump may have found a dead/unsignallable object.
                    let live = self.factories.iter().any(|f| f.id == id)
                        || self.jobs.iter().any(|j| j.id == id);
                    if !live {
                        wire::reply(op, -5, &mut response).unwrap();
                        let _ = platform::ipc::reply(sender, &response);
                    } else if platform::ipc::reply_object_handles(sender, &response, &attached)
                        .is_err()
                    {
                        self.remove(id, backend, now);
                        // A receiver unable to accept another Handle may still
                        // accept an ordinary error reply. Do not strand its call.
                        wire::reply(op, -5, &mut response).unwrap();
                        let _ = platform::ipc::reply(sender, &response);
                    }
                    let _ = platform::handle::close(h);
                }
                result => {
                    wire::reply(op, result.err().unwrap_or(0), &mut response).unwrap();
                    let _ = platform::ipc::reply(sender, &response);
                }
            }
            return true;
        }
        let Ok((header, input)) = provider::RequestHeader::decode(bytes) else {
            return false;
        };
        if !matches!(header.object_id & TAG_MASK, FACTORY_TAG | JOB_TAG) {
            return false;
        }
        let native =
            handles.count == 0 && handles.delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
        if native && header.opcode == provider::OP_RELEASE {
            self.remove(header.object_id, backend, now);
            return true;
        }
        let mut data = [0; provider::MAX_DATA_LEN];
        let result = (|| {
            if !native {
                return Err(-13);
            }
            if header.object_id & TAG_MASK == FACTORY_TAG {
                let row = self
                    .factories
                    .iter()
                    .find(|f| f.id == header.object_id)
                    .ok_or(-9)?;
                if header.opcode != provider::OP_CONTROL || header.basis != wire::QUERY_LIMITS {
                    return Err(-95);
                }
                if !input.is_empty() || header.length != wire::LIMITS_LEN as u32 {
                    return Err(-22);
                }
                return row
                    .limits
                    .encode(&mut data)
                    .map(|n| (n as u64, n))
                    .map_err(|_| -5);
            }
            let i = self
                .jobs
                .iter()
                .position(|j| j.id == header.object_id)
                .ok_or(-9)?;
            self.update(i, backend, now);
            match header.opcode {
                // Positioned I/O asks whether this object participates in the
                // VM page cache first. DNS snapshots expose no pager identity.
                provider::OP_MEMORY_OBJECT => Ok((0, 0)),
                provider::OP_READ_AT => {
                    let row = &self.jobs[i];
                    if !row.ready {
                        return Err(-11);
                    }
                    let start = usize::try_from(header.basis).map_err(|_| -22)?;
                    if start >= row.result.len() {
                        return Ok((0, 0));
                    }
                    let n = (row.result.len() - start).min(header.length as usize);
                    data[..n].copy_from_slice(&row.result[start..start + n]);
                    Ok((n as u64, n))
                }
                provider::OP_QUERY if header.basis == wire::STATUS => {
                    if !input.is_empty() || header.length != wire::OBSERVATION_LEN as u32 {
                        return Err(-22);
                    }
                    let row = &self.jobs[i];
                    wire::Observation {
                        ready: row.ready,
                        kind: row.kind,
                        status: row.status,
                        length: if row.ready {
                            row.result.len() as u64
                        } else {
                            0
                        },
                    }
                    .encode(&mut data)
                    .map(|n| (n as u64, n))
                    .map_err(|_| -5)
                }
                provider::OP_CONTROL if header.basis == wire::CANCEL => {
                    if !input.is_empty() || header.length != 4 {
                        return Err(-22);
                    }
                    let row = &mut self.jobs[i];
                    let cancelled = if row.ready {
                        false
                    } else {
                        backend.cancel(row.query.ok_or(-5)?, now)?;
                        row.query = None;
                        row.fail(-125);
                        true
                    };
                    data[..4].copy_from_slice(&u32::from(cancelled).to_le_bytes());
                    Ok((4, 4))
                }
                _ => Err(-95),
            }
        })();
        self.pump(backend, now);
        let (status, value, n) = match result {
            Ok((value, n)) => (0, value, n),
            Err(error) => (error, 0, 0),
        };
        let mut response = [0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
        if let Ok(n) = (provider::ResponseHeader {
            opcode: header.opcode,
            status: status as i64,
            object_id: header.object_id,
            value,
            data_length: n as u32,
        })
        .encode(&data[..n], &mut response)
        {
            let _ = platform::ipc::reply(sender, &response[..n]);
        }
        true
    }
}
