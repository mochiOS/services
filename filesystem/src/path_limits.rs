//! Resolve once under the provider's serialized namespace borrow, without
//! opening or reading target data and without allocating an open description.
use super::*;

impl FilesystemService {
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
}
