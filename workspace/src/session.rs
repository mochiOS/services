//! Session authority comes from a launcher-delegated domain and retained native
//! ProcessHandles. Environment names and request-supplied IDs are not authority.
use super::{OwnedObjectHandle, PosixClient, SyscallEndpointTransport, error, platform};
use mochios_posix_client::ObjectHandleAttachment;
use mochios_posix_protocol::process_domain;

pub(super) struct Session {
    domain: OwnedObjectHandle,
    uid: u32,
}

impl Session {
    pub fn capture(
        posix: &PosixClient<SyscallEndpointTransport>,
        endpoint: u64,
    ) -> Result<Self, u64> {
        let domain = OwnedObjectHandle(
            platform::handle::inherited(process_domain::LAUNCH_CONTEXT_KEY)
                .map_err(error::native_errno)?,
        );
        let credentials = posix.session_info().map_err(error::posix_errno)?;
        if credentials.real_uid != credentials.effective_uid {
            return Err(platform::syscall::EACCES);
        }
        let session = Self {
            domain,
            uid: credentials.effective_uid,
        };
        if !session.permits(posix, endpoint) {
            return Err(platform::syscall::EACCES);
        }
        Ok(session)
    }

    pub fn permits(&self, posix: &PosixClient<SyscallEndpointTransport>, sender: u64) -> bool {
        let Ok(process) = platform::process::open_handle_for_endpoint(
            sender,
            platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_TRANSFER,
        ) else {
            return false;
        };
        let process = OwnedObjectHandle(process);
        let attachment = ObjectHandleAttachment {
            handle: process.raw(),
            rights: platform::handle::HANDLE_RIGHT_WAIT,
        };
        let Ok(credentials) = posix.process_session_info(attachment) else {
            return false;
        };
        if credentials.real_uid != self.uid || credentials.effective_uid != self.uid {
            return false;
        }
        posix
            .process_domain_contains(
                ObjectHandleAttachment {
                    handle: self.domain.raw(),
                    rights: process_domain::ATTACH_RIGHTS,
                },
                attachment,
            )
            .unwrap_or(false)
    }
}
