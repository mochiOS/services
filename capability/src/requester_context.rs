use mochi_user_platform as platform;
use mochios_posix_client::ObjectHandleAttachment;
use mochios_posix_protocol::SessionInfo;

/// Userspace permission-policy input, not a kernel ABI record. Package identity
/// comes from native authentication; IDs come exclusively from posix.service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequesterContext {
    pub process_id: u64,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub subject_key_id: [u8; 32],
    pub provenance: u8,
    pub package_id_len: u16,
    pub developer_id_len: u16,
    pub package_id: [u8; mnu_abi::APPLICATION_ID_FIELD_LEN],
    pub developer_id: [u8; mnu_abi::APPLICATION_ID_FIELD_LEN],
}

impl RequesterContext {
    fn from_authenticated_sources(
        native: platform::syscall::ThreadSecurityContext,
        credentials: SessionInfo,
    ) -> Self {
        Self {
            process_id: native.process_id,
            effective_uid: credentials.effective_uid,
            effective_gid: credentials.effective_gid,
            subject_key_id: native.subject_key_id,
            provenance: native.provenance,
            package_id_len: native.package_id_len,
            developer_id_len: native.developer_id_len,
            package_id: native.package_id,
            developer_id: native.developer_id,
        }
    }
}

impl Default for RequesterContext {
    fn default() -> Self {
        Self::from_authenticated_sources(
            platform::syscall::ThreadSecurityContext::default(),
            SessionInfo::default(),
        )
    }
}

/// Authenticate the process object before requesting its POSIX credentials.
/// The native record carries no POSIX credential fields.
pub(crate) fn read(
    endpoint: u64,
    credentials: impl FnOnce(
        ObjectHandleAttachment<platform::handle::Handle>,
    ) -> Result<SessionInfo, platform::syscall::SysError>,
) -> Result<RequesterContext, platform::syscall::SysError> {
    let context = platform::process::thread_security_context(endpoint)?;
    let handle = platform::process::open_handle_for_endpoint(
        endpoint,
        platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_TRANSFER,
    )?;
    let result = (|| {
        let process = platform::process::handle_status(handle)?;
        if process.process_id != context.process_id {
            return Err(platform::syscall::SysError::from_raw(
                platform::syscall::EACCES as i64,
            ));
        }
        let identity = credentials(ObjectHandleAttachment {
            handle,
            rights: platform::handle::HANDLE_RIGHT_WAIT,
        })?;
        Ok(RequesterContext::from_authenticated_sources(
            context, identity,
        ))
    })();
    let _ = platform::handle::close(handle);
    result
}
