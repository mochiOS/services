use mochios_posix_client::{
    AccessAtBase, Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles,
    ObjectTransport, OpenAtBase, StatAtBase, Transport,
};
use mochios_posix_protocol as wire;
use std::cell::{Cell, RefCell};

struct Replies {
    mode: u8,
    incoming: Vec<u32>,
    closed: RefCell<Vec<u32>>,
    calls: Cell<usize>,
    borrowed: Vec<u32>,
}
impl Transport for &Replies {
    type Error = u8;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u8> {
        panic!("explicit Handle required")
    }
}
impl ObjectTransport for &Replies {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        input: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, u8> {
        let (header, _) = wire::decode(input).unwrap();
        assert_eq!(
            handles.iter().map(|entry| entry.handle).collect::<Vec<_>>(),
            self.borrowed
        );
        self.calls.set(self.calls.get() + 1);
        handles.clear();
        for handle in &self.incoming {
            handles
                .push(Handle {
                    handle: *handle,
                    rights: 1,
                })
                .unwrap();
        }
        if self.mode == 1 {
            return Err(42);
        }
        if self.mode == 2 {
            return Ok(output.len() + 1);
        }
        if self.mode == 3 {
            output[0] = 0;
            return Ok(1);
        }
        let payload = match header.opcode {
            wire::OP_FGETFL => vec![0; wire::FILE_FLAGS_PAYLOAD_LEN],
            wire::OP_FSTAT | wire::OP_STAT_AT => vec![0; wire::FILE_STATUS_LEN],
            wire::OP_READLINK_AT => b"destination".to_vec(),
            _ => vec![],
        };
        wire::encode(
            wire::Header {
                opcode: if self.mode == 6 {
                    wire::OP_PING
                } else {
                    wire::OP_STATUS
                },
                request_id: header.request_id + u64::from(self.mode == 4),
                payload_len: payload.len() as u32,
                status: if self.mode == 5 { -13 } else { 0 },
                ..Default::default()
            },
            &payload,
            output,
        )
        .map_err(|_| 99)
    }
}

fn invoke(client: &Client<&Replies>, opcode: u16) -> Result<(), ClientError<u8>> {
    let file = Handle {
        handle: 7,
        rights: mnu_abi::HANDLE_RIGHT_ALL,
    };
    match opcode {
        wire::OP_FTRUNCATE => client.ftruncate(file, 5),
        wire::OP_FSYNC => client.fsync(file),
        wire::OP_FCHMOD => client.fchmod(file, 0o600),
        wire::OP_FCHOWN => client.fchown(file, 1, 2),
        wire::OP_FSETFL => client.set_status_flags(file, wire::OPEN_NONBLOCK),
        wire::OP_FGETFL => client.get_status_flags(file).map(|_| ()),
        wire::OP_FSTAT => client.fstat(file).map(|_| ()),
        _ => unreachable!(),
    }
}

#[test]
fn every_file_reply_is_drained_once_without_closing_the_borrowed_source_or_replaying() {
    for opcode in [
        wire::OP_FTRUNCATE,
        wire::OP_FSYNC,
        wire::OP_FCHMOD,
        wire::OP_FCHOWN,
        wire::OP_FSETFL,
        wire::OP_FGETFL,
        wire::OP_FSTAT,
    ] {
        for mode in 0..7 {
            for incoming in [vec![], vec![8], vec![8, 8, 9, 0], vec![7, 8, 7, 0]] {
                let replies = Replies {
                    mode,
                    incoming,
                    closed: RefCell::new(vec![]),
                    calls: Cell::new(0),
                    borrowed: vec![7],
                };
                let result = invoke(&Client::new(&replies), opcode);
                match mode {
                    0 if replies.incoming.is_empty() => assert_eq!(result, Ok(())),
                    0 | 4 | 6 => assert_eq!(result, Err(ClientError::MismatchedResponse)),
                    1 => assert_eq!(result, Err(ClientError::Transport(42))),
                    2 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
                    3 => assert!(matches!(result, Err(ClientError::Protocol(_)))),
                    5 => assert_eq!(result, Err(ClientError::Remote(-13))),
                    _ => unreachable!(),
                }
                let mut expected = vec![];
                for handle in &replies.incoming {
                    if *handle != 0 && *handle != 7 && !expected.contains(handle) {
                        expected.push(*handle);
                    }
                }
                assert_eq!(
                    *replies.closed.borrow(),
                    expected,
                    "opcode={opcode} mode={mode}"
                );
                assert_eq!(replies.calls.get(), 1);
            }
        }
    }
}

fn path_operation(
    client: &Client<&Replies>,
    opcode: u16,
    old: StatAtBase<u32>,
    new: StatAtBase<u32>,
    path: &str,
) -> Result<(), ClientError<u8>> {
    match opcode {
        wire::OP_STAT_AT => client.stat_at(old, 0, path).map(|_| ()),
        wire::OP_ACCESS_AT => {
            let base = match old {
                StatAtBase::ProcessRoot => AccessAtBase::ProcessRoot,
                StatAtBase::ProcessCwd => AccessAtBase::ProcessCwd,
                StatAtBase::Directory(handle) => AccessAtBase::Directory(handle),
            };
            client.access_at(base, 0, 0, path)
        }
        wire::OP_CHDIR_AT => client.chdir_at(old, path),
        wire::OP_CHROOT_AT => client.chroot_at(old, path),
        wire::OP_MKDIR_AT => {
            let base = match old {
                StatAtBase::ProcessRoot => OpenAtBase::ProcessRoot,
                StatAtBase::ProcessCwd => OpenAtBase::ProcessCwd,
                StatAtBase::Directory(handle) => OpenAtBase::Directory(handle),
            };
            client.mkdir_at(base, 0o700, path)
        }
        wire::OP_UNLINK_AT => client.unlink_at(old, 0, path),
        wire::OP_RENAME_AT => client.rename_at(old, path, new, "renamed"),
        wire::OP_LINK_AT => client.link_at(old, path, new, "linked", 0),
        wire::OP_TRUNCATE_AT => client.truncate_at(old, path, 5),
        wire::OP_SYMLINK_AT => client.symlink_at("destination", old, path),
        wire::OP_READLINK_AT => {
            let mut output = [0; 3];
            let result = client.readlink_at(old, path, &mut output);
            if result.is_ok() {
                assert_eq!(output, *b"des");
                assert_eq!(result, Ok(3));
            }
            result.map(|_| ())
        }
        wire::OP_CHMOD_AT => client.chmod_at(old, path, 0o600),
        wire::OP_CHOWN_AT => client.chown_at(old, path, 1, 2, 0),
        wire::OP_FCHDIR => {
            if let StatAtBase::Directory(handle) = old {
                client.fchdir(handle)
            } else {
                unreachable!()
            }
        }
        _ => unreachable!(),
    }
}

#[test]
fn path_replies_preserve_every_directory_borrow_and_never_replay_mutations() {
    let directory = |handle| {
        StatAtBase::Directory(Handle {
            handle,
            rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        })
    };
    let bases = [
        StatAtBase::ProcessRoot,
        StatAtBase::ProcessCwd,
        directory(7),
        directory(11),
    ];
    for opcode in [
        wire::OP_STAT_AT,
        wire::OP_ACCESS_AT,
        wire::OP_CHDIR_AT,
        wire::OP_CHROOT_AT,
        wire::OP_MKDIR_AT,
        wire::OP_UNLINK_AT,
        wire::OP_RENAME_AT,
        wire::OP_LINK_AT,
        wire::OP_TRUNCATE_AT,
        wire::OP_SYMLINK_AT,
        wire::OP_READLINK_AT,
        wire::OP_CHMOD_AT,
        wire::OP_CHOWN_AT,
        wire::OP_FCHDIR,
    ] {
        for old in bases {
            if opcode == wire::OP_FCHDIR && !matches!(old, StatAtBase::Directory(_)) {
                continue;
            }
            let two = matches!(opcode, wire::OP_RENAME_AT | wire::OP_LINK_AT);
            for new in bases.into_iter().take(if two { 4 } else { 1 }) {
                let borrowed = [Some(old), two.then_some(new)]
                    .into_iter()
                    .flatten()
                    .filter_map(|base| match base {
                        StatAtBase::Directory(handle) => Some(handle.handle),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                for mode in 0..7 {
                    for incoming in [vec![], vec![8], vec![8, 8, 9, 0], vec![7, 11, 8, 0]] {
                        let replies = Replies {
                            mode,
                            incoming,
                            borrowed: borrowed.clone(),
                            closed: RefCell::new(vec![]),
                            calls: Cell::new(0),
                        };
                        let result =
                            path_operation(&Client::new(&replies), opcode, old, new, "entry");
                        match mode {
                            0 if replies.incoming.is_empty() => assert_eq!(result, Ok(())),
                            0 | 4 | 6 => assert_eq!(result, Err(ClientError::MismatchedResponse)),
                            1 => assert_eq!(result, Err(ClientError::Transport(42))),
                            2 => assert_eq!(result, Err(ClientError::ResponseTooLarge)),
                            3 => assert!(matches!(result, Err(ClientError::Protocol(_)))),
                            5 => assert_eq!(result, Err(ClientError::Remote(-13))),
                            _ => unreachable!(),
                        }
                        let mut expected = vec![];
                        for handle in &replies.incoming {
                            if *handle != 0
                                && !borrowed.contains(handle)
                                && !expected.contains(handle)
                            {
                                expected.push(*handle);
                            }
                        }
                        assert_eq!(
                            *replies.closed.borrow(),
                            expected,
                            "opcode={opcode} mode={mode}"
                        );
                        assert_eq!(replies.calls.get(), 1);
                    }
                }
            }
        }
    }
}

#[test]
fn invalid_paths_neither_send_a_request_nor_release_directory_borrows() {
    let directory = |handle| {
        StatAtBase::Directory(Handle {
            handle,
            rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        })
    };
    let path = "x".repeat(wire::MAX_PATH_LEN + 1);
    for opcode in [
        wire::OP_STAT_AT,
        wire::OP_ACCESS_AT,
        wire::OP_CHDIR_AT,
        wire::OP_CHROOT_AT,
        wire::OP_MKDIR_AT,
        wire::OP_UNLINK_AT,
        wire::OP_RENAME_AT,
        wire::OP_LINK_AT,
        wire::OP_TRUNCATE_AT,
        wire::OP_SYMLINK_AT,
        wire::OP_READLINK_AT,
        wire::OP_CHMOD_AT,
        wire::OP_CHOWN_AT,
    ] {
        let replies = Replies {
            mode: 0,
            incoming: vec![8],
            borrowed: vec![7, 11],
            closed: RefCell::new(vec![]),
            calls: Cell::new(0),
        };
        assert!(matches!(
            path_operation(
                &Client::new(&replies),
                opcode,
                directory(7),
                directory(11),
                &path
            ),
            Err(ClientError::Protocol(_))
        ));
        assert_eq!(replies.calls.get(), 0);
        assert!(replies.closed.borrow().is_empty());
    }
}
