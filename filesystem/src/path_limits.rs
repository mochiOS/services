//! Resolve once under the provider's serialized namespace borrow, without
//! opening or reading target data and without allocating an open description.
use super::*;

impl FilesystemService {
    /// Resolve under the authenticated root/base once; invoke only the owner
    /// retained by that Node, without allocating an open description.
    pub fn device_observation_at(
        &self,
        request: protocol::Header,
        payload: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        use protocol::device_observation as wire;
        let allowed = protocol::STAT_AT_ROOT_ATTACHED | protocol::STAT_AT_BASE_ATTACHED;
        if request.flags & !allowed != 0
            || (request.flags & protocol::STAT_AT_ROOT_ATTACHED != 0)
                != anchors.root_open_id.is_some()
            || (request.flags & protocol::STAT_AT_BASE_ATTACHED != 0)
                != anchors.base_open_id.is_some()
            || request.open_id != 0
            || request.mount_id != 0
            || request.node_id != 0
            || request.offset != 0
            || request.mode != 0
        {
            return Err(EINVAL);
        }
        let observation = wire::Request::decode(payload.get(..wire::REQUEST_LEN).ok_or(EINVAL)?)
            .map_err(|status| -status)?;
        let path = &payload[wire::REQUEST_LEN..];
        if path.is_empty() {
            return Err(ENOENT);
        }
        let node =
            match self.resolve_operation_target(path, anchors, FollowSymlinks::All, credentials)? {
                OperationTarget::Device(node) => node,
                OperationTarget::Disk(..) => return Err(ENOTSUP),
            };
        let bytes = self
            .namespace
            .as_ref()
            .ok_or(EIO)?
            .observe_external_device(&node, observation)?;
        let mut response = self.success(request);
        response.payload = bytes;
        response.header.length = response.payload.len() as u32;
        Ok(response)
    }

    pub fn object_limits_at(
        &self,
        request: protocol::Header,
        path: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        let allowed = protocol::STAT_AT_ROOT_ATTACHED | protocol::STAT_AT_BASE_ATTACHED;
        if request.flags & !allowed != 0
            || (request.flags & protocol::STAT_AT_ROOT_ATTACHED != 0)
                != anchors.root_open_id.is_some()
            || (request.flags & protocol::STAT_AT_BASE_ATTACHED != 0)
                != anchors.base_open_id.is_some()
        {
            return Err(EINVAL);
        }
        if path.is_empty() {
            return Err(ENOENT);
        }
        let (_, filesystem, _) = self.resolve_disk_operation_inode(
            path,
            anchors,
            FollowSymlinks::All,
            credentials,
            |_| 95,
        )?;
        let mut response = self.success(request);
        response.payload = crate::provider_limits::filesystem_limits(&filesystem)
            .encode()
            .to_vec();
        response.header.length = response.payload.len() as u32;
        Ok(response)
    }
    pub fn volume_status_at(
        &self,
        request: protocol::Header,
        path: &[u8],
        anchors: PathAnchors,
        credentials: protocol::Credentials,
    ) -> Result<Response, i32> {
        let allowed = protocol::STAT_AT_ROOT_ATTACHED | protocol::STAT_AT_BASE_ATTACHED;
        if request.opcode != protocol::OP_VOLUME_STATUS_AT
            || request.flags & !allowed != 0
            || (request.flags & protocol::STAT_AT_ROOT_ATTACHED != 0)
                != anchors.root_open_id.is_some()
            || (request.flags & protocol::STAT_AT_BASE_ATTACHED != 0)
                != anchors.base_open_id.is_some()
            || request.open_id != 0
            || request.mount_id != 0
            || request.node_id != 0
            || request.offset != 0
            || request.mode != 0
        {
            return Err(EINVAL);
        }
        if path.is_empty() {
            return Err(ENOENT);
        }
        let (_, filesystem, volume) = self.resolve_disk_operation_inode(
            path,
            anchors,
            FollowSymlinks::All,
            credentials,
            |_| ENOTSUP,
        )?;
        let mut response = self.success(request);
        response.payload = crate::volume_status::filesystem_status(&filesystem, volume)?
            .encode()
            .to_vec();
        response.header.length = response.payload.len() as u32;
        Ok(response)
    }
}
