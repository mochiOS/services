use std::cell::RefCell;

use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use posix_service::{PeerIdentity, PosixService};

struct LocalTransport {
    service: RefCell<PosixService>,
    peer: PeerIdentity,
}

impl Transport for LocalTransport {
    type Error = ();

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        let reply = self.service.borrow_mut().handle(self.peer, header, payload);
        protocol::encode(reply.header, &reply.payload, response).map_err(|_| ())
    }
}

fn client(peer: PeerIdentity) -> Client<LocalTransport> {
    Client::new(LocalTransport {
        service: RefCell::new(PosixService::new()),
        peer,
    })
}

#[test]
fn ping_round_trip_preserves_request_identity() {
    client(PeerIdentity {
        process_id: 7,
        effective_uid: 501,
        effective_gid: 20,
    })
    .ping()
    .unwrap();
}

#[test]
fn unknown_opcode_returns_enosys() {
    let client = client(PeerIdentity {
        process_id: 7,
        effective_uid: 501,
        effective_gid: 20,
    });
    let error = client.request(0x7fff, 0, &[], &mut []).unwrap_err();
    assert_eq!(error, ClientError::Remote(protocol::STATUS_ENOSYS));
}

#[test]
fn session_uses_authenticated_peer_instead_of_request_payload() {
    let peer = PeerIdentity {
        process_id: 41,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = PosixService::new();
    let response = service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            request_id: 9,
            ..protocol::Header::default()
        },
        &[],
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
    let session = service.session(41).unwrap();
    assert_eq!(session.real_uid, 501);
    assert_eq!(session.real_gid, 20);
    assert_eq!(session.umask, 0o022);
}

#[test]
fn client_registers_an_authenticated_session() {
    let peer = PeerIdentity {
        process_id: 73,
        effective_uid: 502,
        effective_gid: 21,
    };
    let client = client(peer);
    client.register_session().unwrap();

    let transport = client.into_transport();
    let service = transport.service.borrow();
    let session = service.session(peer.process_id).unwrap();
    assert_eq!(session.effective_uid, peer.effective_uid);
    assert_eq!(session.effective_gid, peer.effective_gid);
}

#[test]
fn session_info_and_umask_round_trip_through_the_client() {
    let peer = PeerIdentity {
        process_id: 91,
        effective_uid: 503,
        effective_gid: 22,
    };
    let client = client(peer);
    assert_eq!(
        client.session_info().unwrap_err(),
        ClientError::Remote(protocol::STATUS_ESRCH)
    );

    client.register_session().unwrap();
    let initial = client.session_info().unwrap();
    assert_eq!(initial.real_uid, peer.effective_uid);
    assert_eq!(initial.effective_uid, peer.effective_uid);
    assert_eq!(initial.real_gid, peer.effective_gid);
    assert_eq!(initial.effective_gid, peer.effective_gid);
    assert_eq!(initial.umask, 0o022);

    assert_eq!(client.set_umask(0o1755).unwrap(), 0o022);
    assert_eq!(client.session_info().unwrap().umask, 0o755);
}

#[test]
fn fixed_size_session_payloads_reject_trailing_bytes() {
    let mut encoded = [0u8; protocol::SESSION_INFO_LEN + 1];
    protocol::encode_session_info(protocol::SessionInfo::default(), &mut encoded).unwrap();
    assert_eq!(
        protocol::decode_session_info(&encoded),
        Err(protocol::ProtocolError::InvalidLength)
    );
    assert_eq!(
        protocol::decode_umask(&[0; protocol::UMASK_PAYLOAD_LEN + 1]),
        Err(protocol::ProtocolError::InvalidLength)
    );
}

struct LocalObjectTransport;

impl Transport for LocalObjectTransport {
    type Error = ();

    fn call(&self, _request: &[u8], _response: &mut [u8]) -> Result<usize, Self::Error> {
        Err(())
    }
}

impl ObjectTransport for LocalObjectTransport {
    type Handle = u32;

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let (header, _) = protocol::decode(request).map_err(|_| ())?;
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 41,
                rights: 0x5,
            })
        );
        handles.clear();
        handles
            .push(ObjectHandleAttachment {
                handle: 73,
                rights: 0x1,
            })
            .unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status: protocol::STATUS_OK,
                ..protocol::Header::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn object_transport_replaces_request_handles_with_reply_handles() {
    let client = Client::new(LocalObjectTransport);
    let mut handles = ObjectHandles::new();
    handles
        .push(ObjectHandleAttachment {
            handle: 41,
            rights: 0x5,
        })
        .unwrap();

    client
        .request_with_handles(protocol::OP_PING, 0, &[], &mut [], &mut handles)
        .unwrap();

    assert_eq!(handles.len(), 1);
    assert_eq!(
        handles.get(0),
        Some(ObjectHandleAttachment {
            handle: 73,
            rights: 0x1,
        })
    );
}
