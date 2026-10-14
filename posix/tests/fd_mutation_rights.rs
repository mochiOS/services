use mnu_abi::{
    HANDLE_RIGHT_CONTROL as CONTROL, HANDLE_RIGHT_READ as READ, HANDLE_RIGHT_TRANSFER as TRANSFER,
    HANDLE_RIGHT_WRITE as WRITE,
};
use mochios_filesystem_protocol as filesystem;
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as posix;
use std::cell::Cell;

struct MutationTransport {
    opcode: u16,
    rights: u64,
    calls: Cell<usize>,
}

impl Transport for &MutationTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("mutation requires an explicit Handle")
    }
}

impl ObjectTransport for &MutationTransport {
    type Handle = u32;

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, _) = posix::decode(request).unwrap();
        assert_eq!(header.opcode, self.opcode);
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 7,
                rights: self.rights
            })
        );
        self.calls.set(self.calls.get() + 1);
        handles.clear();
        posix::encode(
            posix::Header {
                opcode: posix::OP_STATUS,
                request_id: header.request_id,
                ..Default::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_rejects_missing_authority_without_rpc_and_forwards_only_required_rights() {
    for opcode in [
        posix::OP_FTRUNCATE,
        posix::OP_FCHMOD,
        posix::OP_FCHOWN,
        posix::OP_FSETFL,
    ] {
        let required = posix::file_mutation_rights(opcode).unwrap();
        let transport = MutationTransport {
            opcode,
            rights: required,
            calls: Cell::new(0),
        };
        let client = Client::new(&transport);
        for rights in [READ | TRANSFER, required & !TRANSFER, u64::MAX] {
            let file = ObjectHandleAttachment { handle: 7, rights };
            let result = match opcode {
                posix::OP_FTRUNCATE => client.ftruncate(file, 1),
                posix::OP_FCHMOD => client.fchmod(file, 0o600),
                posix::OP_FCHOWN => client.fchown(file, u32::MAX, u32::MAX),
                posix::OP_FSETFL => client.set_status_flags(file, posix::OPEN_NONBLOCK),
                _ => unreachable!(),
            };
            if rights == u64::MAX {
                assert_eq!(result, Ok(()));
            } else {
                assert_eq!(result, Err(ClientError::Remote(-13)));
            }
        }
        assert_eq!(transport.calls.get(), 1);
    }
}

#[test]
fn owner_and_policy_service_require_actual_mutation_authority_not_posix_identity() {
    for (operation, owner_operation, needed) in [
        (posix::OP_FTRUNCATE, filesystem::OP_TRUNCATE_HANDLE, WRITE),
        (posix::OP_FCHMOD, filesystem::OP_CHMOD_HANDLE, CONTROL),
        (posix::OP_FCHOWN, filesystem::OP_CHOWN_HANDLE, CONTROL),
        (posix::OP_FSETFL, filesystem::OP_SET_FLAGS_HANDLE, CONTROL),
        (
            posix::OP_FUPDATEFL,
            filesystem::OP_UPDATE_FLAGS_HANDLE,
            CONTROL,
        ),
    ] {
        assert_eq!(
            posix::file_mutation_rights(operation),
            Some(needed | TRANSFER)
        );
        let unrelated = if needed == WRITE { CONTROL } else { WRITE };
        for rights in [0, READ, TRANSFER, READ | TRANSFER, unrelated | TRANSFER] {
            assert_eq!(
                filesystem_service::handle_access::authorize(owner_operation, rights),
                Err(13)
            );
        }
        assert_eq!(
            filesystem_service::handle_access::authorize(owner_operation, needed),
            Err(13)
        );
        assert_eq!(
            filesystem_service::handle_access::authorize(owner_operation, needed | TRANSFER),
            Ok(())
        );
    }
    assert_eq!(
        filesystem_service::handle_access::authorize(filesystem::OP_GET_FLAGS_HANDLE, TRANSFER),
        Ok(())
    );
    assert_eq!(
        filesystem_service::handle_access::authorize(0xffff, u64::MAX),
        Err(38)
    );
}
