//! The service owns the POSIX node name. It is not a native machine authority.
use mochios_posix_protocol::system_identity as wire;
mod build {
    include!(concat!(env!("OUT_DIR"), "/system_identity.rs"));
}

#[derive(Debug)]
pub(super) struct Identity {
    node: [u8; wire::HOST_NAME_MAX],
    length: usize,
}
impl Identity {
    pub const fn new() -> Self {
        let mut node = [0; wire::HOST_NAME_MAX];
        let name = b"localhost";
        let mut index = 0;
        while index < name.len() {
            node[index] = name[index];
            index += 1;
        }
        Self {
            node,
            length: name.len(),
        }
    }
    pub fn record(&self) -> wire::Record<'_> {
        wire::Record {
            system: b"mochiOS",
            node: &self.node[..self.length],
            release: build::RELEASE.as_bytes(),
            version: build::VERSION.as_bytes(),
            machine: build::MACHINE.as_bytes(),
        }
    }
    pub fn set_node(&mut self, name: &[u8]) -> Result<(), i32> {
        if !wire::valid_field(name) {
            return Err(-22);
        }
        self.node[..name.len()].copy_from_slice(name);
        self.node[name.len()..].fill(0);
        self.length = name.len();
        Ok(())
    }
}

impl<H: Copy> crate::PosixService<H> {
    pub(super) fn system_identity_payload(&self, pid: u64) -> Result<Vec<u8>, i32> {
        if self.registered_peer(pid).is_none() {
            return Err(-1);
        }
        let mut output = vec![0; wire::MAX_RECORD];
        let size = wire::encode(self.system_identity.record(), &mut output).map_err(|_| -5)?;
        output.truncate(size);
        Ok(output)
    }
    pub(super) fn set_hostname_payload(&mut self, pid: u64, name: &[u8]) -> Result<Vec<u8>, i32> {
        if !self
            .sessions
            .get(&pid)
            .is_some_and(|session| session.effective_uid == 0)
        {
            return Err(-1);
        }
        self.system_identity.set_node(name)?;
        Ok(Vec::new())
    }
}
