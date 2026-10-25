use mochios_posix_client::{Client, Transport};
use mochios_posix_protocol::{self as protocol, account as wire};
use mochios_user_database::UserDatabase;
#[path = "../../user/src/public_accounts.rs"]
mod implementation;

fn root_record() -> wire::Record<'static> {
    wire::Record {
        uid: 0,
        gid: 0,
        name: "root",
        display_name: "System Administrator",
        home: "/home/root",
        shell: "/bin/msh",
    }
}

#[test]
fn real_database_lookup_exports_public_fields_without_password_hashes() {
    let mut database = UserDatabase::with_root();
    database.find_name_mut("root").unwrap().password_hash = "sensitive-test-marker".into();
    for query in [wire::Query::Uid(0), wire::Query::Name("root")] {
        let mut request = [0; wire::MAX_MESSAGE];
        let n = wire::encode_request(42, query, &mut request).unwrap();
        let mut response = [0; wire::MAX_MESSAGE];
        let n = implementation::reply(&database, true, &request[..n], &mut response).unwrap();
        assert_eq!(
            wire::decode_response(42, &response[..n]),
            Ok(Ok(root_record()))
        );
        assert!(
            !response[..n]
                .windows(21)
                .any(|b| b == b"sensitive-test-marker")
        );
        assert!(wire::decode_response(43, &response[..n]).is_err());
    }
    let mut request = [0; wire::MAX_MESSAGE];
    let n = wire::encode_request(7, wire::Query::Uid(9000), &mut request).unwrap();
    assert_eq!(
        implementation::reply(&database, true, &request[..n], &mut [0; wire::MAX_MESSAGE]),
        Err(-2)
    );
    assert_eq!(
        implementation::reply(&database, false, &request[..n], &mut [0; wire::MAX_MESSAGE]),
        Err(-5)
    );
}

#[test]
fn public_wire_rejects_truncation_invalid_text_lengths_tags_and_trailing_bytes() {
    let mut bytes = [0; wire::MAX_MESSAGE];
    let n = wire::encode_record(root_record(), &mut bytes).unwrap();
    for length in 0..n {
        assert!(wire::decode_record(&bytes[..length]).is_err());
    }
    assert!(wire::decode_record(&bytes[..n + 1]).is_err());
    let mut invalid = bytes;
    invalid[16] = 0;
    assert!(wire::decode_record(&invalid[..n]).is_err());
    for query in [
        wire::Query::Uid(u32::MAX),
        wire::Query::Name("valid-name_1"),
    ] {
        let n = wire::encode_query(query, &mut bytes).unwrap();
        assert_eq!(wire::decode_query(&bytes[..n]), Ok(query));
        for length in 0..n {
            assert!(wire::decode_query(&bytes[..length]).is_err());
        }
        assert!(wire::decode_query(&bytes[..n + 1]).is_err());
        let mut invalid = bytes;
        invalid[..4].copy_from_slice(&2u32.to_le_bytes());
        assert!(wire::decode_query(&invalid[..n]).is_err());
    }
    for invalid in ["", "contains\0nul", "../root", "two words"] {
        assert!(wire::encode_query(wire::Query::Name(invalid), &mut bytes).is_err());
    }
}

struct AccountTransport {
    failure: Option<i32>,
    wrong_id: bool,
}
impl Transport for AccountTransport {
    type Error = i32;
    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, i32> {
        let (id, query) = wire::decode_request(request).unwrap();
        assert_eq!(query, wire::Query::Uid(0));
        if let Some(error) = self.failure {
            return Err(error);
        }
        wire::encode_reply(id + u64::from(self.wrong_id), root_record(), response).map_err(|_| -5)
    }
}

#[test]
fn delegated_account_rpc_validates_reply_identity_and_propagates_failure() {
    let mut request = [0; wire::MAX_QUERY];
    let n = wire::encode_query(wire::Query::Uid(0), &mut request).unwrap();
    let response = posix_service::account_lookup::lookup(
        &AccountTransport {
            failure: None,
            wrong_id: false,
        },
        7,
        &request[..n],
        |e| e,
    )
    .unwrap();
    assert_eq!(wire::decode_record(&response), Ok(root_record()));
    for (failure, wrong_id, expected) in [(Some(-32), false, -32), (None, true, -5)] {
        assert_eq!(
            posix_service::account_lookup::lookup(
                &AccountTransport { failure, wrong_id },
                7,
                &request[..n],
                |e| e
            ),
            Err(expected)
        );
    }
}

struct PosixTransport;
impl Transport for PosixTransport {
    type Error = ();
    fn call(&self, request: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, protocol::OP_ACCOUNT_LOOKUP);
        assert_eq!(wire::decode_query(payload), Ok(wire::Query::Uid(0)));
        let mut body = [0; wire::MAX_RECORD];
        let n = wire::encode_record(root_record(), &mut body).unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: n as u32,
                ..Default::default()
            },
            &body[..n],
            output,
        )
        .map_err(|_| ())
    }
}
#[test]
fn posix_client_transmits_a_lookup_key_without_claiming_credentials() {
    let mut bytes = [0; wire::MAX_RECORD];
    let n = Client::new(PosixTransport)
        .lookup_account(wire::Query::Uid(0), &mut bytes)
        .unwrap();
    assert_eq!(wire::decode_record(&bytes[..n]), Ok(root_record()));
}
