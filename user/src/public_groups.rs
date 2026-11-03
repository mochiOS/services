//! Public queries use persisted group records, not numeric/name guesses.
use mochios_user_database::{UserDatabase, groups::GroupDatabase};
use mochios_user_protocol::public_group::{self as wire, Query, Record};
use std::{io, path::Path};

pub fn load(path: &Path, users: &UserDatabase) -> io::Result<GroupDatabase> {
    if let Some(bytes) = crate::storage::load_bytes(path)? {
        return GroupDatabase::parse(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
    }
    let groups = GroupDatabase::provision(users)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    save(path, &groups).map_err(io::Error::other)?;
    Ok(groups)
}
pub fn save(path: &Path, groups: &GroupDatabase) -> Result<(), crate::storage::SaveError> {
    let bytes = groups.encode().map_err(|error| {
        crate::storage::SaveError::new(
            "encode-groups",
            io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })?;
    crate::storage::save_bytes(path, &bytes)
}
pub fn reply(
    groups: &GroupDatabase,
    healthy: bool,
    request: &[u8],
    output: &mut [u8],
) -> Result<usize, i32> {
    let (id, query) = wire::decode_request(request).map_err(|_| -22)?;
    if !healthy {
        return Err(-5);
    }
    let group = match query {
        Query::Gid(gid) => groups.find_gid(gid),
        Query::Name(name) => groups.find_name(name),
    }
    .ok_or(-2)?;
    let mut members = [""; wire::MAX_MEMBERS];
    if group.members.len() > members.len() {
        return Err(-34);
    }
    for (target, member) in members.iter_mut().zip(&group.members) {
        *target = member;
    }
    let record =
        Record::new(group.gid, &group.name, &members[..group.members.len()]).map_err(|_| -5)?;
    wire::encode_reply(id, record, output).map_err(|_| -34)
}
