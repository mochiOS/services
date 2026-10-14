use mochios_posix_client::{
    socket_record, Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles,
    ObjectTransport, Transport,
};
use mochios_posix_protocol::{
    self as protocol,
    socket_record::{self as wire, Operation, Reply, Request},
};
use std::cell::Cell;

struct Mock {
    case: u8,
    calls: Cell<usize>,
}
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("attachments required")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn call_with_handles(
        &self,
        bytes: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        self.calls.set(self.calls.get() + 1);
        if bytes.starts_with(&protocol::socket_route::MAGIC) {
            assert_eq!(
                protocol::socket_route::decode(bytes),
                Ok((3, protocol::socket::Address::UnixPath(b"/server")))
            );
            assert_eq!(handles.len(), 1);
            assert_eq!(
                handles.get(0),
                Some(Handle {
                    handle: 10,
                    rights: mnu_abi::HANDLE_RIGHT_WRITE
                })
            );
            handles.clear();
            if self.case != 1 {
                handles
                    .push(Handle {
                        handle: 42,
                        rights: protocol::socket_route::RIGHTS
                            | if self.case == 2 {
                                mnu_abi::HANDLE_RIGHT_CONTROL
                            } else {
                                0
                            },
                    })
                    .unwrap();
                if self.case == 3 {
                    handles.push(handles.get(0).unwrap()).unwrap();
                }
            }
            if self.case == 4 {
                return Err(());
            }
            response[..4].copy_from_slice(&(if self.case == 1 { -13i32 } else { 0 }).to_le_bytes());
            return Ok(if self.case == 5 { 3 } else { 4 });
        }
        if bytes.starts_with(b"POSX") {
            let (header, payload) = protocol::decode(bytes).unwrap();
            assert_eq!(header.opcode, protocol::OP_SOCKET_RECORD_ENDPOINT);
            assert!(payload.is_empty() && handles.is_empty());
            handles
                .push(Handle {
                    handle: 42,
                    rights: if self.case == 0 {
                        wire::ENDPOINT_RIGHTS
                    } else {
                        mnu_abi::HANDLE_RIGHT_ALL
                    },
                })
                .unwrap();
            return Ok(protocol::encode(
                protocol::Header {
                    opcode: protocol::OP_STATUS,
                    request_id: header.request_id,
                    ..Default::default()
                },
                &[],
                response,
            )
            .unwrap());
        }
        let request = Request::decode(bytes).unwrap();
        assert_eq!(
            handles.get(0),
            Some(Handle {
                handle: 10,
                rights: request.socket_rights()
            })
        );
        let waiting = request.operation == Operation::WaitSend;
        assert_eq!(handles.len(), if waiting { 1 } else { 2 });
        if !waiting {
            assert_eq!(
                handles.get(1),
                Some(Handle {
                    handle: 20,
                    rights: request.buffer_rights()
                })
            );
        }
        handles.clear();
        if self.case >= 2 {
            handles
                .push(Handle {
                    handle: 42,
                    rights: protocol::socket::receive_wait_job_rights()
                        | if waiting && self.case == 2 {
                            mnu_abi::HANDLE_RIGHT_CONTROL
                        } else {
                            0
                        },
                })
                .unwrap();
            if self.case == 3 {
                handles.push(handles.get(0).unwrap()).unwrap();
            }
        }
        if self.case == 4 {
            return Err(());
        }
        if waiting {
            if self.case == 0 {
                handles
                    .push(Handle {
                        handle: 42,
                        rights: protocol::socket::receive_wait_job_rights(),
                    })
                    .unwrap();
            }
            response[..4].copy_from_slice(&(if self.case == 1 { -11i32 } else { 0 }).to_le_bytes());
            return Ok(if self.case == 5 { 3 } else { 4 });
        }
        if self.case == 1 {
            response[..4].copy_from_slice(&(-11i32).to_le_bytes());
            return Ok(4);
        }
        let count = Reply {
            copied: request.length,
            length: request.length,
            source: None,
        }
        .encode(request, response)
        .unwrap();
        if self.case == 5 {
            response[8] ^= 0x80;
        }
        Ok(count)
    }
}
fn source(handle: u32) -> Handle<u32> {
    Handle {
        handle,
        rights: mnu_abi::HANDLE_RIGHT_ALL,
    }
}

#[test]
fn endpoint_is_owned_send_only_transport_not_data_authority() {
    for case in [0, 1] {
        let client = Client::new(Mock {
            case,
            calls: Cell::new(0),
        });
        let mut closed = vec![];
        let result = client.socket_record_endpoint(|handle| closed.push(handle));
        if case == 0 {
            assert_eq!(
                result,
                Ok(Handle {
                    handle: 42,
                    rights: wire::ENDPOINT_RIGHTS
                })
            );
            assert!(closed.is_empty());
        } else {
            assert!(result.is_err());
            assert_eq!(closed, [42]);
        }
    }
}

#[test]
fn direct_data_calls_attenuate_both_borrowed_resources_and_clean_bad_replies() {
    let request = Request {
        operation: Operation::Send,
        offset: 17,
        length: 3,
        peek: false,
    };
    for case in 0..6 {
        let mock = Mock {
            case,
            calls: Cell::new(0),
        };
        let mut response = [0; wire::MAX_REPLY_LEN];
        let mut closed = vec![];
        let result = socket_record::exchange(
            &mock,
            request,
            source(10),
            source(20),
            &mut response,
            |handle| closed.push(handle),
        );
        if case == 0 {
            assert_eq!(result.unwrap().copied, 3);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(closed, if case >= 2 { vec![42] } else { vec![] });
        assert_eq!(mock.calls.get(), 1);
    }
}

#[test]
fn direct_wait_calls_own_only_notification_and_never_close_borrowed_socket() {
    for case in 0..6 {
        let mock = Mock {
            case,
            calls: Cell::new(0),
        };
        let mut closed = vec![];
        let result =
            socket_record::wait_send(&mock, source(10), 30000, |handle| closed.push(handle));
        if case == 0 {
            assert_eq!(
                result,
                Ok(Handle {
                    handle: 42,
                    rights: protocol::socket::receive_wait_job_rights()
                })
            );
        } else {
            assert!(result.is_err());
        }
        assert_eq!(closed, if case >= 2 { vec![42] } else { vec![] });
    }
}

#[test]
fn missing_direction_or_transfer_authority_is_rejected_without_rpc() {
    let mock = Mock {
        case: 0,
        calls: Cell::new(0),
    };
    let request = Request {
        operation: Operation::Send,
        offset: 0,
        length: 1,
        peek: false,
    };
    for (handle, right) in [
        (10, mnu_abi::HANDLE_RIGHT_WRITE),
        (10, mnu_abi::HANDLE_RIGHT_TRANSFER),
        (20, mnu_abi::HANDLE_RIGHT_READ),
        (20, mnu_abi::HANDLE_RIGHT_MAP),
        (20, mnu_abi::HANDLE_RIGHT_TRANSFER),
    ] {
        let mut socket = source(10);
        let mut buffer = source(20);
        if handle == 10 {
            socket.rights &= !right;
        } else {
            buffer.rights &= !right;
        }
        assert!(matches!(
            socket_record::exchange(
                &mock,
                request,
                socket,
                buffer,
                &mut [0; wire::MAX_REPLY_LEN],
                |_| panic!()
            ),
            Err(ClientError::Remote(-13))
        ));
    }
    assert_eq!(mock.calls.get(), 0);
}

#[test]
fn prepare_route_returns_only_scoped_write_wait_authority_and_cleans_bad_replies() {
    for case in 0..6 {
        let mock = Mock {
            case,
            calls: Cell::new(0),
        };
        let mut closed = vec![];
        let result = socket_record::prepare_route(
            &mock,
            source(10),
            3,
            protocol::socket::Address::UnixPath(b"/server"),
            |handle| closed.push(handle),
        );
        if case == 0 {
            assert_eq!(
                result,
                Ok(Handle {
                    handle: 42,
                    rights: protocol::socket_route::RIGHTS
                })
            );
            assert_eq!(
                protocol::socket_route::RIGHTS
                    & (mnu_abi::HANDLE_RIGHT_READ
                        | mnu_abi::HANDLE_RIGHT_MAP
                        | mnu_abi::HANDLE_RIGHT_CONTROL
                        | mnu_abi::HANDLE_RIGHT_DUPLICATE),
                0
            );
        } else {
            assert!(result.is_err());
        }
        assert_eq!(closed, if case >= 2 { vec![42] } else { vec![] });
    }
    let mock = Mock {
        case: 0,
        calls: Cell::new(0),
    };
    for right in [mnu_abi::HANDLE_RIGHT_WRITE, mnu_abi::HANDLE_RIGHT_TRANSFER] {
        let mut socket = source(10);
        socket.rights &= !right;
        assert!(matches!(
            socket_record::prepare_route(
                &mock,
                socket,
                3,
                protocol::socket::Address::UnixPath(b"/server"),
                |_| panic!()
            ),
            Err(ClientError::Remote(-13))
        ));
    }
    assert_eq!(mock.calls.get(), 0);
}
