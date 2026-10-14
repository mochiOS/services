//! Userspace policy for verified built-in startup, independent of kernel path
//! loading and of a filesystem/POSIX service which has not started yet.

use alloc::{format, string::String, vec, vec::Vec};
use mnu_abi::exec::*;
use sha2::{Digest, Sha256};

pub struct Plan {
    pub authorization: Vec<u8>,
    pub creation: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    TooLarge,
    Launch(mochios_posix_client::launch_arguments::EncodeError),
}

pub fn prepare(
    path: &str,
    identity: &[String],
    arguments: &[String],
    image: &[u8],
    random: [u8; 16],
) -> Result<Plan, Error> {
    let prefixes = [
        APPLICATION_PACKAGE_ID_PREFIX,
        APPLICATION_DEVELOPER_ID_PREFIX,
        APPLICATION_SUBJECT_KEY_ID_PREFIX,
        APPLICATION_PROVENANCE_PREFIX,
    ];
    if identity.len() != prefixes.len()
        || !identity.iter().zip(prefixes).all(|(item, prefix)| {
            item.strip_prefix(prefix)
                .is_some_and(|value| !value.is_empty() && !value.as_bytes().contains(&0))
        })
    {
        return Err(Error::Identity);
    }
    let mut fields = identity.to_vec();
    let digest = Sha256::digest(image);
    let mut digest_hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write;
        let _ = write!(digest_hex, "{byte:02x}");
    }
    fields.push(format!("{EXECUTABLE_DIGEST_PREFIX}{digest_hex}"));
    fields.push(format!(
        "{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_SPAWN}"
    ));
    fields.push(format!("{EXEC_AUTHORIZATION_CLASS_PREFIX}privileged"));
    let mut authorization = vec![0; 1024];
    let mut used = 0usize;
    for field in fields {
        let end = used
            .checked_add(field.len())
            .filter(|end| {
                end.checked_add(2)
                    .is_some_and(|length| length <= authorization.len())
            })
            .ok_or(Error::TooLarge)?;
        authorization[used..end].copy_from_slice(field.as_bytes());
        used = end + 1;
    }
    let label = path
        .rsplit('/')
        .next()
        .filter(|label| !label.is_empty())
        .ok_or(Error::Identity)?;
    let creation = mochios_posix_client::launch_arguments::encode_native_launch(
        path, label, arguments, random,
    )
    .map_err(Error::Launch)?;
    Ok(Plan {
        authorization,
        creation,
    })
}
