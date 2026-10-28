//! Resolver job operations shared by native Provider and packet adapters.
use crate::resolver::{Answer, Failure};
use mochios_network_stack::{DnsRecordName, DnsRecordType};

pub(crate) trait Backend {
    type Query: Copy;
    fn start(
        &mut self,
        name: DnsRecordName,
        kind: DnsRecordType,
        now: u64,
        timeout: u64,
    ) -> Result<Self::Query, i32>;
    fn take(&mut self, id: Self::Query) -> Result<Option<Result<Answer, Failure>>, i32>;
    fn cancel(&mut self, id: Self::Query, now: u64) -> Result<(), i32>;
}
pub(crate) struct Unavailable;
impl Backend for Unavailable {
    type Query = crate::resolver::Query;
    fn start(
        &mut self,
        _: DnsRecordName,
        _: DnsRecordType,
        _: u64,
        _: u64,
    ) -> Result<Self::Query, i32> {
        Err(mochios_net_device_protocol::STATUS_NETWORK_UNAVAILABLE)
    }
    fn take(&mut self, _: Self::Query) -> Result<Option<Result<Answer, Failure>>, i32> {
        Err(-9)
    }
    fn cancel(&mut self, _: Self::Query, _: u64) -> Result<(), i32> {
        Err(-9)
    }
}
