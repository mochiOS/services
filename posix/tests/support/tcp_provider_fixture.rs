//! Test ownership of the production Provider metadata and its pure transport.
//! Delegates without adapting wire, authentication, connection or packet state.
pub(crate) struct Fixture {
    provider: crate::server::Server,
    transport: crate::stream::Transport,
}
impl Fixture {
    pub(crate) fn new(endpoint: Option<u32>) -> Self {
        Self {
            provider: crate::server::Server::new(endpoint),
            transport: crate::stream::Transport::new(),
        }
    }
    pub(crate) fn transport(&mut self) -> &mut crate::stream::Transport {
        &mut self.transport
    }
    pub(crate) fn pump(&mut self, now: u64) {
        self.provider.pump(now, &mut self.transport);
    }
    pub(crate) fn dispatch(
        &mut self,
        sender: u64,
        bytes: &[u8],
        handles: &crate::ipc::IpcObjectHandles,
        now: u64,
    ) -> bool {
        self.provider
            .dispatch(sender, bytes, handles, now, &mut self.transport)
    }
}
