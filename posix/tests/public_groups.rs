use mochios_posix_client::{Client, Transport};
use mochios_posix_protocol as posix;
use mochios_user_database::{
    UserDatabase, UserRecord,
    groups::{Group, GroupDatabase},
};
use mochios_user_protocol::{self as user, public_group as wire};

#[path = "../../user/src/status.rs"]
mod status;
#[path = "../../user/src/storage.rs"]
mod storage;
#[path = "../../user/src/public_groups.rs"]
mod actual;

fn users() -> UserDatabase {
    let mut users = UserDatabase::with_root();
    users.add(UserRecord::regular("alice", 1000, 1000)).unwrap();
    users.add(UserRecord::regular("bob", 1001, 1000)).unwrap();
    users
}
fn groups() -> GroupDatabase {
    let mut groups = GroupDatabase::provision(&users()).unwrap();
    groups
        .add(Group {
            gid: 20,
            name: "staff".into(),
            members: vec!["alice".into(), "bob".into()],
        })
        .unwrap();
    groups
}

#[test]
fn authoritative_group_records_round_trip_shared_members_and_reject_ambiguity() {
    let groups = groups();
    let bytes = groups.encode().unwrap();
    assert_eq!(GroupDatabase::parse(&bytes), Ok(groups.clone()));
    assert_eq!(groups.find_gid(20).unwrap().members, ["alice", "bob"]);
    assert_eq!(groups.find_name("alice").unwrap().gid, 1000);
    assert!(groups.find_name("bob").is_none());
    for invalid in [
        "MGRPDB\t2\n",
        "MGRPDB\t1\n-1\tstaff\t\n",
        "MGRPDB\t1\n4294967296\tstaff\t\n",
        "MGRPDB\t1\n20\tstaff\talice,alice\n",
        "MGRPDB\t1\n20\tstaff\talice,,bob\n",
        "MGRPDB\t1\n20\t../staff\t\n",
        "MGRPDB\t1\n20\tstaff\tbad name\n",
        "MGRPDB\t1\n20\tstaff\t\n20\tother\t\n",
        "MGRPDB\t1\n20\tstaff\t\n21\tstaff\t\n",
        "MGRPDB\t1\n20\tstaff\t\textra\n",
    ] {
        assert!(
            GroupDatabase::parse(invalid.as_bytes()).is_err(),
            "{invalid:?}"
        );
    }
    let members = vec!["alice"; mochios_user_database::groups::MAX_MEMBERS + 1].join(",");
    assert!(GroupDatabase::parse(format!("MGRPDB\t1\n20\tstaff\t{members}\n").as_bytes()).is_err());
    assert!(GroupDatabase::parse(&[0; 1024 * 1024 + 1]).is_err());
}

#[test]
fn private_group_provisioning_preserves_configured_shared_groups() {
    let mut groups = groups();
    let before = groups.clone();
    assert!(
        !groups
            .ensure_private(&UserRecord::regular("newname", 20, 20))
            .unwrap()
    );
    assert_eq!(groups, before);
    assert!(
        groups
            .ensure_private(&UserRecord::regular("carol", 1002, 1002))
            .unwrap()
    );
    assert_eq!(groups.find_gid(1002).unwrap().name, "carol");
    assert!(
        !groups
            .ensure_private(&UserRecord::regular("dave", 1003, 20))
            .unwrap()
    );
    assert!(groups.find_name("dave").is_none());
}

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "mochios-groups341-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn persistent_metadata_is_authoritative_and_corruption_never_reprovisions_it() {
    use std::os::unix::fs::PermissionsExt;
    let directory = Directory::new();
    let path = directory.0.join("groups.db");
    let provisioned = actual::load(&path, &users()).unwrap();
    assert_eq!(provisioned, GroupDatabase::provision(&users()).unwrap());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let configured = GroupDatabase::parse(b"MGRPDB\t1\n20\tstaff\talice,bob\n").unwrap();
    actual::save(&path, &configured).unwrap();
    assert_eq!(actual::load(&path, &users()).unwrap(), configured);
    std::fs::rename(&path, path.with_extension("db.backup")).unwrap();
    assert_eq!(actual::load(&path, &users()).unwrap(), configured);
    std::fs::write(&path, b"broken").unwrap();
    assert!(actual::load(&path, &users()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"broken");
}

#[test]
fn bounded_group_wire_rejects_wrong_versions_ids_lengths_and_duplicate_members() {
    assert_eq!(
        wire::MAX_MEMBERS,
        mochios_user_database::groups::MAX_MEMBERS
    );
    assert!(wire::MAX_RECORD + user::HEADER_LEN <= user::MAX_MESSAGE_LEN);
    let record = wire::Record::new(20, "staff", &["alice", "bob"]).unwrap();
    let mut bytes = [0; wire::MAX_RECORD + user::HEADER_LEN];
    let n = wire::encode_reply(71, record, &mut bytes).unwrap();
    assert_eq!(wire::decode_response(71, &bytes[..n]), Ok(Ok(record)));
    for length in 0..n {
        assert!(wire::decode_response(71, &bytes[..length]).is_err());
    }
    assert!(wire::decode_response(72, &bytes[..n]).is_err());
    assert!(wire::decode_response(71, &bytes[..n + 1]).is_err());
    let mut bad = bytes;
    bad[4..6].copy_from_slice(&2u16.to_le_bytes());
    assert!(wire::decode_response(71, &bad[..n]).is_err());
    let mut bad = bytes;
    bad[user::HEADER_LEN + 6..user::HEADER_LEN + 8].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(wire::decode_response(71, &bad[..n]).is_err());
    assert!(wire::Record::new(0, "root", &["alice", "alice"]).is_err());
    assert!(wire::Record::new(0, "root", &vec!["alice"; wire::MAX_MEMBERS + 1]).is_err());
    assert!(wire::Record::new(0, "bad\0name", &[]).is_err());
}

struct Upstream {
    failure: Option<i32>,
    wrong_id: bool,
}
impl Transport for Upstream {
    type Error = i32;
    fn call(&self, request: &[u8], output: &mut [u8]) -> Result<usize, i32> {
        let (id, _) = wire::decode_request(request).unwrap();
        if let Some(error) = self.failure {
            return user::Status {
                request_id: id,
                status: error,
                generation: 1,
            }
            .encode(output)
            .map_err(|_| -5);
        }
        match actual::reply(&groups(), true, request, output) {
            Ok(n) => {
                if self.wrong_id {
                    output[8..16].copy_from_slice(&(id + 1).to_le_bytes());
                }
                Ok(n)
            }
            Err(error) => user::Status {
                request_id: id,
                status: error,
                generation: 1,
            }
            .encode(output)
            .map_err(|_| -5),
        }
    }
}
#[test]
fn delegated_group_rpc_preserves_errors_and_never_turns_bad_replies_into_records() {
    let mut request = [0; wire::MAX_QUERY];
    let n = wire::encode_query(wire::Query::Gid(20), &mut request).unwrap();
    let record = posix_service::account_lookup::lookup_group(
        &Upstream {
            failure: None,
            wrong_id: false,
        },
        7,
        &request[..n],
        |e| e,
    )
    .unwrap();
    let record = wire::decode_record(&record).unwrap();
    assert_eq!(
        (record.gid, record.name, record.members()),
        (20, "staff", &["alice", "bob"][..])
    );
    for (failure, wrong_id, expected) in [
        (Some(-13), false, -13),
        (Some(-32), false, -32),
        (None, true, -5),
    ] {
        assert_eq!(
            posix_service::account_lookup::lookup_group(
                &Upstream { failure, wrong_id },
                7,
                &request[..n],
                |e| e
            ),
            Err(expected)
        );
    }
    let n = wire::encode_request(1, wire::Query::Gid(20), &mut [0; user::MAX_MESSAGE_LEN]).unwrap();
    assert!(n > 0);
    let mut request = [0; user::MAX_MESSAGE_LEN];
    let n = wire::encode_request(1, wire::Query::Gid(20), &mut request).unwrap();
    assert_eq!(
        actual::reply(
            &groups(),
            false,
            &request[..n],
            &mut [0; user::MAX_MESSAGE_LEN]
        ),
        Err(-5)
    );
}

struct Posix;
impl Transport for Posix {
    type Error = i32;
    fn call(&self, request: &[u8], output: &mut [u8]) -> Result<usize, i32> {
        let (header, payload) = posix::decode(request).unwrap();
        assert_eq!(header.opcode, posix::OP_GROUP_LOOKUP);
        let payload = posix_service::account_lookup::lookup_group(
            &Upstream {
                failure: None,
                wrong_id: false,
            },
            header.request_id,
            payload,
            |e| e,
        )?;
        posix::encode(
            posix::Header {
                opcode: posix::OP_STATUS,
                request_id: header.request_id,
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            &payload,
            output,
        )
        .map_err(|_| -5)
    }
}
#[test]
fn client_uses_the_inherited_posix_route_for_both_gid_and_name_queries() {
    for query in [wire::Query::Gid(20), wire::Query::Name("staff")] {
        let mut output = [0; wire::MAX_RECORD];
        let n = Client::new(Posix).lookup_group(query, &mut output).unwrap();
        let record = wire::decode_record(&output[..n]).unwrap();
        assert_eq!((record.gid, record.name), (20, "staff"));
    }
}

#[test]
fn posix_endpoint_operation_numbers_do_not_collide_across_modules() {
    // The PTY factory has its own endpoint and therefore its own namespace.
    let sources = [
        (
            "protocol",
            include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        ),
        (
            "read_scope",
            include_str!("../../../user/crates/posix-protocol/src/read_scope.rs"),
        ),
        (
            "process_domain",
            include_str!("../../../user/crates/posix-protocol/src/process_domain.rs"),
        ),
    ];
    let mut seen = std::collections::BTreeMap::new();
    for (module, source) in sources {
        for line in source.lines() {
            let Some(declaration) = line.strip_prefix("pub const OP_") else {
                continue;
            };
            let (name, value) = declaration.split_once(": u16 = ").unwrap();
            let value = value.strip_suffix(';').unwrap();
            let opcode = if let Some(hex) = value.strip_prefix("0x") {
                u16::from_str_radix(hex, 16).unwrap()
            } else {
                value.parse::<u16>().unwrap()
            };
            let qualified = format!("{module}::OP_{name}");
            assert_eq!(
                seen.insert(opcode, qualified.clone()),
                None,
                "{qualified}: {opcode}"
            );
        }
    }
}
