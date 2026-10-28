//! Deferred replies for the existing ResolveIpv4 protocol. Sender values and
//! authorization are supplied by the native IPC receive boundary, never by wire.
use crate::resolver::{Answer, Failure, hostname};
use alloc::vec::Vec;
use mochios_net_device_protocol::{self as wire, Header, Opcode};
use mochios_network_stack::{DnsRecordName, DnsRecordValue, parse_ipv4_literal};

const LIMIT: usize = 16;
const PER_SENDER: usize = 2;
const MAX_TIMEOUT: u64 = 30_000;

pub(crate) trait Backend {
    type Query: Copy;
    fn start(&mut self, name: DnsRecordName, now: u64, timeout: u64) -> Result<Self::Query, i32>;
    fn take(&mut self, id: Self::Query) -> Result<Option<Result<Answer, Failure>>, i32>;
}
struct Pending<Q> {
    sender: u64,
    request: u64,
    query: Q,
}
pub(crate) struct Replies<Q> {
    pending: Vec<Pending<Q>>,
}
impl<Q: Copy> Replies<Q> {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }
    fn reply(
        sender: u64,
        request: u64,
        result: Result<([u8; 4], bool), i32>,
        send: &mut impl FnMut(u64, &[u8]),
    ) {
        let (status, address, cached) = match result {
            Ok((address, cached)) => (0, address, cached),
            Err(status) => (status, [0; 4], false),
        };
        let mut bytes = [0; wire::RESOLVE_RESULT_LEN];
        if let Ok(n) =
            wire::encode_resolve_ipv4_result(request, status, address, cached, &mut bytes)
        {
            send(sender, &bytes[..n]);
        }
    }
    pub(crate) fn dispatch<B: Backend<Query = Q>>(
        &mut self,
        backend: &mut B,
        sender: u64,
        bytes: &[u8],
        now: u64,
        authorized: impl FnOnce(u64) -> bool,
        mut send: impl FnMut(u64, &[u8]),
    ) -> bool {
        let Ok(header) = Header::decode(bytes) else {
            return false;
        };
        if header.opcode != Opcode::ResolveIpv4 {
            return false;
        }
        let result = (|| {
            if !authorized(sender) {
                return Err(-13);
            }
            let (request, timeout, name) = wire::decode_resolve_ipv4(bytes).map_err(|_| -22)?;
            if let Some(address) = parse_ipv4_literal(name) {
                return Ok(Some((address, false)));
            }
            let name = hostname(name).map_err(|error| error.status())?;
            if self.pending.len() >= LIMIT
                || self.pending.iter().filter(|p| p.sender == sender).count() >= PER_SENDER
            {
                return Err(-11);
            }
            self.pending.try_reserve(1).map_err(|_| -12)?;
            let query = backend.start(name, now, u64::from(timeout).min(MAX_TIMEOUT))?;
            self.pending.push(Pending {
                sender,
                request,
                query,
            });
            Ok(None)
        })();
        match result {
            Ok(None) => (),
            Ok(Some(answer)) => Self::reply(sender, header.request_id, Ok(answer), &mut send),
            Err(error) => Self::reply(sender, header.request_id, Err(error), &mut send),
        }
        true
    }
    pub(crate) fn pump<B: Backend<Query = Q>>(
        &mut self,
        backend: &mut B,
        mut send: impl FnMut(u64, &[u8]),
    ) {
        let mut i = 0;
        while i < self.pending.len() {
            let result = match backend.take(self.pending[i].query) {
                Ok(None) => {
                    i += 1;
                    continue;
                }
                Ok(Some(result)) => result.map_err(|error| error.status()).and_then(|answer| {
                    match answer.records.values().first() {
                        Some(DnsRecordValue::Ipv4(address)) => Ok((*address, answer.from_cache)),
                        _ => Err(wire::STATUS_UNSUPPORTED_RECORD),
                    }
                }),
                Err(error) => Err(error),
            };
            let pending = self.pending.swap_remove(i);
            Self::reply(pending.sender, pending.request, result, &mut send);
        }
    }
}
