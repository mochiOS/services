//! Read-only projection of the authoritative account database. No hashes.
use mochios_user_database::UserDatabase;
use mochios_user_protocol::public_account::{self as wire, Query, Record};

pub fn reply(
    database: &UserDatabase,
    healthy: bool,
    request: &[u8],
    output: &mut [u8],
) -> Result<usize, i32> {
    let (id, query) = wire::decode_request(request).map_err(|_| -22)?;
    if !healthy {
        return Err(-5);
    }
    let user = match query {
        Query::Uid(uid) => database.find_uid(uid),
        Query::Name(name) => database.find_name(name),
    }
    .ok_or(-2)?;
    wire::encode_reply(
        id,
        Record {
            uid: user.uid,
            gid: user.gid,
            name: &user.name,
            display_name: &user.display_name,
            home: &user.home,
            shell: &user.shell,
        },
        output,
    )
    .map_err(|_| -5)
}
