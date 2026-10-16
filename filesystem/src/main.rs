#[cfg(target_os = "mochios")]
fn main() {
    use std::sync::Arc;

    use ext4plus::Ext4;
    use filesystem_service::ext4::{Ext4Storage, ImmutableExt4Storage};
    use filesystem_service::platform_storage::{
        MochiDisk, find_data_partition, find_system_partition,
    };
    use filesystem_service::service::FilesystemService;
    use filesystem_service::storage::PartitionIo;
    use mochi_user_platform as platform;
    use mochios_filesystem_protocol as protocol;

    let _ = platform::logger::init_from_env();
    platform::logln!("filesystem.service: start");
    let Some(ready_target) = platform::service_ready::take_bootstrap_target() else {
        platform::logln!("filesystem.service: missing ready target");
        platform::process::exit(1);
    };
    let (first_lba, sector_count) = match find_data_partition(0) {
        Ok(range) => range,
        Err(error) => {
            platform::logln!("filesystem.service: Data partition discovery failed: {error}");
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    let partition = Arc::new(PartitionIo::new(MochiDisk::new(0), first_lba, sector_count));
    let storage = Ext4Storage::new(partition.clone());
    let fs = match Ext4::load_with_writer(Box::new(storage.clone()), Some(Box::new(storage))) {
        Ok(fs) => fs,
        Err(error) => {
            platform::logln!("filesystem.service: ext4 mount failed: {error}");
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    let mut service = FilesystemService::new(fs);
    let system = find_system_partition(0)
        .map_err(|error| error.to_string())
        .and_then(|(first_lba, sector_count)| {
            let partition = Arc::new(PartitionIo::new(MochiDisk::new(0), first_lba, sector_count));
            // The selected, verified System image is immutable. Do not give
            // its backend a writer, even for a POSIX uid-zero caller.
            Ext4::load(Box::new(ImmutableExt4Storage::new(partition)))
                .map(|system| (system, first_lba))
                .map_err(|error| error.to_string())
        })
        .and_then(|(system, first_lba)| {
            service
                .mount_named_volume(b"/", b"system", system, b"/system")
                .map(|_| first_lba)
                .map_err(|error| format!("namespace mount error {error}"))
        });
    let system_first_lba = match system {
        Ok(first_lba) => first_lba,
        Err(error) => {
            platform::logln!("filesystem.service: native System mount failed: {error}");
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    if let Err(error) = service.mount_devices(
        b"/dev", filesystem_service::devfs::DeviceFilesystem::default(),
    ) {
        platform::logln!("filesystem.service: device mount failed: {error}");
        let _ = platform::service_ready::notify(ready_target, -1);
        platform::process::exit(1);
    }
    let endpoint = match platform::ipc::create_handle() {
        Ok(endpoint) => endpoint,
        Err(_) => {
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    if let Err(error) = service.configure_memory_updates(Box::new(
        filesystem_service::memory_updates::ProviderUpdates::new(endpoint),
    )) {
        platform::logln!("filesystem.service: memory-update setup failed: {error}");
        let _ = platform::service_ready::notify(ready_target, -1);
        platform::process::exit(1);
    }
    let delegated_rights = platform::handle::HANDLE_RIGHT_SEND
        | platform::handle::HANDLE_RIGHT_DUPLICATE
        | platform::handle::HANDLE_RIGHT_TRANSFER;
    if platform::service_ready::notify_handle(ready_target, 0, endpoint, delegated_rights).is_err()
    {
        platform::process::exit(1);
    }
    platform::logln!("filesystem.service: ready");
    eprintln!("filesystem.service: native System mounted at LBA {system_first_lba} (ready)");
    let mut request_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let mut response_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let mut provider_buffer = filesystem_service::provider_buffer::ProviderReadBuffer::default();
    loop {
        let mut attached = platform::ipc::IpcObjectHandles::default();
        let message = match platform::ipc::wait_object_handles(
            endpoint as u64,
            &mut request_bytes,
            &mut attached,
        ) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        let request = &request_bytes[..length.min(request_bytes.len())];
        if request.starts_with(&mnu_abi::provider::MAGIC.to_le_bytes()) {
            // Object IDs are identifiers, not authority. Only native object
            // dispatch may invoke this protocol; ordinary IPC cannot forge
            // this receiver-only delivery flag, even with the same sender ID.
            if attached.delivery_flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT {
                close_attached_handles(&attached);
                if let Ok((header, _)) = mnu_abi::provider::RequestHeader::decode(request) {
                    if let Ok(length) = (mnu_abi::provider::ResponseHeader {
                        opcode: header.opcode,
                        object_id: header.object_id,
                        status: -13,
                        value: 0,
                        data_length: 0,
                    })
                    .encode(&[], &mut response_bytes)
                    {
                        let _ = platform::ipc::reply(sender, &response_bytes[..length]);
                    }
                }
                continue;
            }
            let response_len = handle_provider_request(
                &mut service,
                request,
                &mut response_bytes,
                &attached,
                &mut provider_buffer,
            );
            close_attached_handles(&attached);
            if let Some(response_len) = response_len {
                let _ = platform::ipc::reply(sender, &response_bytes[..response_len]);
            }
            continue;
        }
        let response = match protocol::decode(&request_bytes[..length.min(request_bytes.len())]) {
            Ok((header, payload)) => {
                // Credentials and namespace control are trusted only through
                // the explicitly delegated control endpoint, never its global ID.
                if attached.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
                    close_attached_handles(&attached);
                    let denied = protocol::Header {
                        opcode: protocol::OP_STATUS,
                        request_id: header.request_id,
                        status: -13,
                        ..protocol::Header::default()
                    };
                    if let Ok(length) = protocol::encode(denied, &[], &mut response_bytes) {
                        let _ = platform::ipc::reply(sender, &response_bytes[..length]);
                    }
                    continue;
                }
                if filesystem_service::admission_ipc::requested(header) {
                    let result = handle_admitted_mutation(&mut service, header, payload, &attached);
                    reply_admitted_mutation(
                        &mut service, endpoint, sender, header, result, &mut response_bytes,
                    );
                    // In particular, keep an incoming borrowed ticket alive
                    // until reply_object_handles has copied its reference.
                    close_attached_handles(&attached);
                    continue;
                }
                if matches!(
                    header.opcode,
                    protocol::OP_OPEN_AT
                        | protocol::OP_CREATE_SOCKET_AT
                        | protocol::OP_OPEN_SOCKET_AT
                ) {
                    let socket = header.opcode != protocol::OP_OPEN_AT;
                    let (root_flag, base_flag) = if socket {
                        (
                            protocol::SOCKET_AT_ROOT_ATTACHED,
                            protocol::SOCKET_AT_BASE_ATTACHED,
                        )
                    } else {
                        (
                            protocol::OPEN_AT_ROOT_ATTACHED,
                            protocol::OPEN_AT_BASE_ATTACHED,
                        )
                    };
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            decode_path_anchors(
                                header.flags,
                                root_flag,
                                base_flag,
                                &attached,
                            )
                            .and_then(|anchors| {
                                if header.opcode == protocol::OP_OPEN_SOCKET_AT {
                                    service.open_socket_at_retained(
                                        header, payload, anchors, credentials,
                                    )
                                } else if socket {
                                    service.create_socket_at_retained(
                                        header, payload, anchors, credentials,
                                    )
                                } else {
                                    service.open_at(header, payload, anchors, credentials)
                                }
                            })
                        });
                    close_attached_handles(&attached);
                    match result {
                        Ok(response) => {
                            let rights = if socket {
                                // Namespace identity only: no byte I/O, mapping,
                                // seeking, or provider control authority.
                                platform::handle::HANDLE_RIGHT_DUPLICATE
                                    | platform::handle::HANDLE_RIGHT_TRANSFER
                            } else {
                                open_handle_rights(header.flags)
                            };
                            let opened = match platform::handle::create_provider_object(
                                endpoint,
                                response.header.open_id,
                                rights,
                            ) {
                                Ok(opened) => opened,
                                Err(_) => {
                                    let _ = service.provider_close(response.header.open_id);
                                    let failed = filesystem_service::service::Response {
                                        header: protocol::Header {
                                            opcode: protocol::OP_STATUS,
                                            request_id: header.request_id,
                                            status: -5,
                                            ..protocol::Header::default()
                                        },
                                        payload: Vec::new(),
                                    };
                                    if let Ok(length) = protocol::encode(
                                        failed.header,
                                        &failed.payload,
                                        &mut response_bytes,
                                    ) {
                                        let _ =
                                            platform::ipc::reply(sender, &response_bytes[..length]);
                                    }
                                    continue;
                                }
                            };
                            if let Ok(length) = protocol::encode(
                                response.header,
                                &response.payload,
                                &mut response_bytes,
                            ) {
                                let mut outgoing = platform::ipc::IpcObjectHandles::default();
                                outgoing.count = 1;
                                outgoing.handles[0] = platform::ipc::IpcObjectHandle {
                                    handle: opened,
                                    reserved: 0,
                                    rights,
                                };
                                let sent = platform::ipc::reply_object_handles(
                                    sender,
                                    &response_bytes[..length],
                                    &outgoing,
                                );
                                if sent.is_err() {
                                    let _ = service.provider_close(response.header.open_id);
                                }
                            }
                            let _ = platform::handle::close(opened);
                            continue;
                        }
                        Err(error) => {
                            let failed = filesystem_service::service::Response {
                                header: protocol::Header {
                                    opcode: protocol::OP_STATUS,
                                    request_id: header.request_id,
                                    status: -error,
                                    ..protocol::Header::default()
                                },
                                payload: Vec::new(),
                            };
                            if let Ok(length) = protocol::encode(
                                failed.header,
                                &failed.payload,
                                &mut response_bytes,
                            ) {
                                let _ = platform::ipc::reply(sender, &response_bytes[..length]);
                            }
                            continue;
                        }
                    }
                } else if matches!(
                    header.opcode,
                    protocol::OP_STAT_AT | protocol::OP_CANONICAL_PATH_AT
                ) {
                    let anchors = decode_path_anchors(
                        header.flags,
                        protocol::STAT_AT_ROOT_ATTACHED,
                        protocol::STAT_AT_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                if header.opcode == protocol::OP_CANONICAL_PATH_AT {
                                    service.canonical_path_at(header, payload, anchors, credentials)
                                } else {
                                    service.stat_at(header, payload, anchors, credentials)
                                }
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_STAT_HANDLE {
                    let open_id = if attached.count == 1 {
                        let file = attached.handles[0];
                        if file.reserved != 0
                            || file.rights & platform::handle::HANDLE_RIGHT_TRANSFER == 0
                        {
                            Err(22)
                        } else {
                            platform::handle::identify_provider_object(file.handle).map_err(|_| 9)
                        }
                    } else {
                        Err(22)
                    };
                    match open_id.and_then(|open_id| service.stat_handle(header, open_id)) {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_PATH_HANDLE {
                    match decode_open_pair(&attached)
                        .and_then(|(root, directory)| service.path_handle(header, root, directory))
                    {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if matches!(
                    header.opcode,
                    protocol::OP_TRUNCATE_HANDLE
                        | protocol::OP_SYNC_HANDLE
                        | protocol::OP_GET_FLAGS_HANDLE
                        | protocol::OP_SET_FLAGS_HANDLE
                        | protocol::OP_UPDATE_FLAGS_HANDLE
                        | protocol::OP_CHMOD_HANDLE
                        | protocol::OP_CHOWN_HANDLE
                ) {
                    let open_id = decode_single_open(&attached).and_then(|id| {
                        filesystem_service::handle_access::authorize(
                            header.opcode,
                            attached.handles[0].rights,
                        )?;
                        Ok(id)
                    });
                    let result = open_id.and_then(|open_id| match header.opcode {
                        protocol::OP_TRUNCATE_HANDLE => service.truncate_handle(header, open_id),
                        protocol::OP_SYNC_HANDLE => service.sync_handle(header, open_id),
                        protocol::OP_GET_FLAGS_HANDLE => service.get_flags_handle(header, open_id),
                        protocol::OP_SET_FLAGS_HANDLE => service.set_flags_handle(header, open_id),
                        protocol::OP_UPDATE_FLAGS_HANDLE => <[u8; 4]>::try_from(payload)
                            .map_err(|_| 22)
                            .and_then(|mask| {
                                service.update_flags_handle(header, open_id, u32::from_le_bytes(mask))
                            }),
                        protocol::OP_CHMOD_HANDLE => protocol::decode_credentials_payload(payload)
                            .map_err(|_| 22)
                            .and_then(|(credentials, payload)| {
                                if payload.is_empty() {
                                    service.chmod_handle(header, open_id, credentials)
                                } else {
                                    Err(22)
                                }
                            }),
                        protocol::OP_CHOWN_HANDLE => protocol::decode_credentials_payload(payload)
                            .map_err(|_| 22)
                            .and_then(|(credentials, payload)| {
                                if payload.is_empty() {
                                    service.chown_handle(header, open_id, credentials)
                                } else {
                                    Err(22)
                                }
                            }),
                        _ => unreachable!(),
                    });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_ACCESS_AT {
                    let anchors = decode_path_anchors(
                        header.flags,
                        protocol::ACCESS_AT_ROOT_ATTACHED,
                        protocol::ACCESS_AT_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.access_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_MKDIR_AT {
                    let anchors = decode_path_anchors(
                        header.flags,
                        protocol::MKDIR_AT_ROOT_ATTACHED,
                        protocol::MKDIR_AT_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.mkdir_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_UNLINK_AT {
                    let anchors = decode_path_anchors(
                        header.flags,
                        protocol::UNLINK_AT_ROOT_ATTACHED,
                        protocol::UNLINK_AT_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.unlink_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_RENAME_AT {
                    let anchors = decode_two_path_anchors(
                        header.flags,
                        protocol::RENAME_AT_FLAGS_ALL,
                        protocol::RENAME_AT_ROOT_ATTACHED,
                        protocol::RENAME_AT_OLD_BASE_ATTACHED,
                        protocol::RENAME_AT_NEW_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.rename_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_LINK_AT {
                    let anchors = decode_two_path_anchors(
                        header.flags,
                        protocol::LINK_AT_FLAGS_ALL,
                        protocol::LINK_AT_ROOT_ATTACHED,
                        protocol::LINK_AT_OLD_BASE_ATTACHED,
                        protocol::LINK_AT_NEW_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.link_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_TRUNCATE_AT {
                    let anchors = decode_path_anchors(
                        header.flags,
                        protocol::TRUNCATE_AT_ROOT_ATTACHED,
                        protocol::TRUNCATE_AT_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.truncate_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_SYMLINK_AT {
                    let anchors = decode_path_anchors(
                        header.flags,
                        protocol::SYMLINK_AT_ROOT_ATTACHED,
                        protocol::SYMLINK_AT_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.symlink_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_READLINK_AT {
                    let anchors = decode_path_anchors(
                        header.flags,
                        protocol::READLINK_AT_ROOT_ATTACHED,
                        protocol::READLINK_AT_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.readlink_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_CHMOD_AT {
                    let anchors = decode_path_anchors(
                        header.flags,
                        protocol::CHMOD_AT_ROOT_ATTACHED,
                        protocol::CHMOD_AT_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.chmod_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if header.opcode == protocol::OP_CHOWN_AT {
                    let anchors = decode_path_anchors(
                        header.flags,
                        protocol::CHOWN_AT_ROOT_ATTACHED,
                        protocol::CHOWN_AT_BASE_ATTACHED,
                        &attached,
                    );
                    let result = protocol::decode_credentials_payload(payload)
                        .map_err(|_| 22)
                        .and_then(|(credentials, payload)| {
                            anchors.and_then(|anchors| {
                                service.chown_at(header, payload, anchors, credentials)
                            })
                        });
                    match result {
                        Ok(response) => response,
                        Err(error) => filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -error,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        },
                    }
                } else if attached.count != 0 {
                    filesystem_service::service::Response {
                        header: protocol::Header {
                            opcode: protocol::OP_STATUS,
                            request_id: header.request_id,
                            status: -22,
                            ..protocol::Header::default()
                        },
                        payload: Vec::new(),
                    }
                } else {
                    if header.opcode == protocol::OP_SYNC {
                        if partition.flush().is_err() {
                            let response = filesystem_service::service::Response {
                                header: protocol::Header {
                                    opcode: protocol::OP_STATUS,
                                    request_id: header.request_id,
                                    mount_id: header.mount_id,
                                    status: -5,
                                    ..protocol::Header::default()
                                },
                                payload: Vec::new(),
                            };
                            if let Ok(length) = protocol::encode(
                                response.header,
                                &response.payload,
                                &mut response_bytes,
                            ) {
                                let _ = platform::ipc::reply(sender, &response_bytes[..length]);
                            }
                            continue;
                        }
                    }
                    service.handle(header, payload)
                }
            }
            Err(_) => filesystem_service::service::Response {
                header: protocol::Header {
                    opcode: protocol::OP_STATUS,
                    status: -22,
                    ..protocol::Header::default()
                },
                payload: Vec::new(),
            },
        };
        close_attached_handles(&attached);
        if let Ok(length) =
            protocol::encode(response.header, &response.payload, &mut response_bytes)
        {
            let _ = platform::ipc::reply(sender, &response_bytes[..length]);
        }
    }
}

#[cfg(target_os = "mochios")]
fn handle_admitted_mutation(
    service: &mut filesystem_service::service::FilesystemService,
    header: mochios_filesystem_protocol::Header,
    payload: &[u8],
    attached: &mochi_user_platform::ipc::IpcObjectHandles,
) -> filesystem_service::memory_updates::MutationResult<filesystem_service::service::Response> {
    use filesystem_service::memory_updates::MutationResult;
    use mochios_filesystem_protocol as protocol;
    let result = (|| {
        let request = filesystem_service::admission_ipc::Request::decode(header, attached)?;
        let header = request.header;
        match header.opcode {
            protocol::OP_OPEN_AT | protocol::OP_TRUNCATE_AT => {
                let (credentials, payload) =
                    protocol::decode_credentials_payload(payload).map_err(|_| 22)?;
                let (root, base) = if header.opcode == protocol::OP_OPEN_AT {
                    (
                        protocol::OPEN_AT_ROOT_ATTACHED,
                        protocol::OPEN_AT_BASE_ATTACHED,
                    )
                } else {
                    (
                        protocol::TRUNCATE_AT_ROOT_ATTACHED,
                        protocol::TRUNCATE_AT_BASE_ATTACHED,
                    )
                };
                let anchors = decode_path_anchors(header.flags, root, base, &request.sources)?;
                Ok(if header.opcode == protocol::OP_OPEN_AT {
                    service.open_at_admitted(header, payload, anchors, credentials, request.ticket)
                } else {
                    service.truncate_at_admitted(
                        header,
                        payload,
                        anchors,
                        credentials,
                        request.ticket,
                    )
                })
            }
            protocol::OP_TRUNCATE_HANDLE => {
                if !payload.is_empty() {
                    return Err(22);
                }
                let open_id = decode_single_open(&request.sources)?;
                filesystem_service::handle_access::authorize(
                    header.opcode,
                    request.sources.handles[0].rights,
                )?;
                Ok(service.truncate_handle_admitted(header, open_id, request.ticket))
            }
            _ => Err(22),
        }
    })();
    result.unwrap_or_else(|error| MutationResult::Complete(Err(error)))
}

#[cfg(target_os = "mochios")]
fn reply_admitted_mutation(
    service: &mut filesystem_service::service::FilesystemService,
    endpoint: mochi_user_platform::handle::Handle,
    sender: u64,
    request: mochios_filesystem_protocol::Header,
    result: filesystem_service::memory_updates::MutationResult<
        filesystem_service::service::Response,
    >,
    bytes: &mut [u8],
) {
    use filesystem_service::memory_updates::MutationResult;
    use filesystem_service::service::Response;
    use mochi_user_platform as platform;
    use mochios_filesystem_protocol as protocol;
    let failure = |error: i32| Response {
        header: protocol::Header {
            opcode: protocol::OP_STATUS,
            request_id: request.request_id,
            status: -error,
            ..Default::default()
        },
        payload: Vec::new(),
    };
    let (mut response, ticket) = match result {
        MutationResult::Wait(ticket) => {
            (failure(protocol::ERROR_MEMORY_ADMISSION_BUSY), Some(ticket))
        }
        MutationResult::Complete(Ok(response)) => (response, None),
        MutationResult::Complete(Err(error)) => {
            // An error without a position must never advertise queued replay.
            (
                failure(if error == protocol::ERROR_MEMORY_ADMISSION_BUSY {
                    5
                } else {
                    error
                }),
                None,
            )
        }
    };
    let mut outgoing = platform::ipc::IpcObjectHandles::default();
    let mut opened = None;
    if let Some(ticket) = ticket.as_ref() {
        outgoing = filesystem_service::admission_ipc::reply_attachment(ticket.handle());
    } else if response.header.status == 0 && request.opcode == protocol::OP_OPEN_AT {
        let rights = open_handle_rights(request.flags);
        let open_id = response.header.open_id;
        match platform::handle::create_provider_object(endpoint, open_id, rights) {
            Ok(handle) => {
                opened = Some((handle, open_id));
                outgoing.count = 1;
                outgoing.handles[0] = platform::ipc::IpcObjectHandle {
                    handle,
                    reserved: 0,
                    rights,
                };
            }
            Err(_) => {
                let _ = service.provider_close(open_id);
                response = failure(5);
            }
        }
    }
    let sent = protocol::encode(response.header, &response.payload, bytes)
        .map_err(|_| ())
        .and_then(|length| {
            if outgoing.count == 0 {
                platform::ipc::reply(sender, &bytes[..length]).map_err(|_| ())
            } else {
                platform::ipc::reply_object_handles(sender, &bytes[..length], &outgoing)
                    .map_err(|_| ())
            }
        });
    if let Some((handle, open_id)) = opened {
        if sent.is_err() {
            let _ = service.provider_close(open_id);
        }
        let _ = platform::handle::close(handle);
    }
    // Owned positions are closed here on success AND encode/send failure.
    // Borrowed positions remain the original request cleanup's responsibility.
    drop(ticket);
}

#[cfg(target_os = "mochios")]
fn decode_open_pair(
    attached: &mochi_user_platform::ipc::IpcObjectHandles,
) -> Result<(u64, u64), i32> {
    use mochi_user_platform as platform;

    if attached.count != 2 {
        return Err(22);
    }
    let mut open_ids = [0u64; 2];
    let required = platform::handle::HANDLE_RIGHT_READ | platform::handle::HANDLE_RIGHT_TRANSFER;
    for (index, object) in attached.handles.iter().take(2).enumerate() {
        if object.handle == 0 || object.reserved != 0 || object.rights & required != required {
            return Err(13);
        }
        open_ids[index] =
            platform::handle::identify_provider_object(object.handle).map_err(|_| 9)?;
    }
    Ok((open_ids[0], open_ids[1]))
}

#[cfg(target_os = "mochios")]
fn decode_single_open(attached: &mochi_user_platform::ipc::IpcObjectHandles) -> Result<u64, i32> {
    use mochi_user_platform as platform;

    if attached.count != 1 {
        return Err(22);
    }
    let object = attached.handles[0];
    if object.handle == 0
        || object.reserved != 0
        || object.rights & platform::handle::HANDLE_RIGHT_TRANSFER == 0
    {
        return Err(13);
    }
    platform::handle::identify_provider_object(object.handle).map_err(|_| 9)
}

#[cfg(target_os = "mochios")]
fn decode_path_anchors(
    flags: u32,
    root_flag: u32,
    base_flag: u32,
    attached: &mochi_user_platform::ipc::IpcObjectHandles,
) -> Result<filesystem_service::service::PathAnchors, i32> {
    use mochi_user_platform as platform;

    let root_attached = flags & root_flag != 0;
    let base_attached = flags & base_flag != 0;
    let expected = usize::from(root_attached) + usize::from(base_attached);
    if attached.count as usize != expected || expected > attached.handles.len() {
        return Err(22);
    }
    let mut index = 0usize;
    let mut next_open_id = || -> Result<u64, i32> {
        let directory = attached.handles[index];
        index += 1;
        let required =
            platform::handle::HANDLE_RIGHT_READ | platform::handle::HANDLE_RIGHT_TRANSFER;
        if directory.handle == 0
            || directory.reserved != 0
            || directory.rights & required != required
        {
            return Err(13);
        }
        platform::handle::identify_provider_object(directory.handle).map_err(|_| 9)
    };
    Ok(filesystem_service::service::PathAnchors {
        root_open_id: if root_attached {
            Some(next_open_id()?)
        } else {
            None
        },
        base_open_id: if base_attached {
            Some(next_open_id()?)
        } else {
            None
        },
    })
}

#[cfg(target_os = "mochios")]
fn decode_two_path_anchors(
    flags: u32,
    allowed_flags: u32,
    root_flag: u32,
    old_base_flag: u32,
    new_base_flag: u32,
    attached: &mochi_user_platform::ipc::IpcObjectHandles,
) -> Result<filesystem_service::service::RenameAnchors, i32> {
    use mochi_user_platform as platform;

    if flags & !allowed_flags != 0 {
        return Err(22);
    }
    let mut index = 0usize;
    let mut next_open = |present: bool| -> Result<Option<u64>, i32> {
        if !present {
            return Ok(None);
        }
        let object = *attached.handles.get(index).ok_or(22)?;
        index += 1;
        let required =
            platform::handle::HANDLE_RIGHT_READ | platform::handle::HANDLE_RIGHT_TRANSFER;
        if object.handle == 0 || object.reserved != 0 || object.rights & required != required {
            return Err(13);
        }
        platform::handle::identify_provider_object(object.handle)
            .map(Some)
            .map_err(|_| 9)
    };
    let anchors = filesystem_service::service::RenameAnchors {
        root_open_id: next_open(flags & root_flag != 0)?,
        old_base_open_id: next_open(flags & old_base_flag != 0)?,
        new_base_open_id: next_open(flags & new_base_flag != 0)?,
    };
    if index != attached.count as usize {
        return Err(22);
    }
    Ok(anchors)
}

#[cfg(target_os = "mochios")]
fn open_handle_rights(flags: u32) -> u64 {
    filesystem_service::handle_access::open_rights(flags)
}

#[cfg(target_os = "mochios")]
fn close_attached_handles(handles: &mochi_user_platform::ipc::IpcObjectHandles) {
    for attached in handles.handles.iter().take(handles.count as usize) {
        let _ = mochi_user_platform::handle::close(attached.handle);
    }
}

#[cfg(target_os = "mochios")]
fn handle_provider_request(
    service: &mut filesystem_service::service::FilesystemService,
    request: &[u8],
    response: &mut [u8],
    attached: &mochi_user_platform::ipc::IpcObjectHandles,
    buffer: &mut filesystem_service::provider_buffer::ProviderReadBuffer,
) -> Option<usize> {
    use mnu_abi::provider;
    let (header, payload) = provider::RequestHeader::decode(request).ok()?;
    if header.opcode == provider::OP_RELEASE {
        let _ = service.provider_close(header.object_id);
        return None;
    }
    let result = match header.opcode {
        provider::OP_READ_SHARED => read_provider_shared(service, header, attached, buffer),
        provider::OP_READ => service
            .provider_read(header.object_id, header.length as usize)
            .map(|data| (data.len() as u64, data)),
        provider::OP_READ_WITH_POSITION => service
            .provider_read_with_offset(header.object_id, header.length as usize)
            .map(|(data, start)| {
                let length = data.len() as u64;
                let mut positioned = start.to_le_bytes().to_vec();
                positioned.extend_from_slice(&data);
                (length, positioned)
            }),
        provider::OP_WRITE => service
            .provider_write_with_offset(header.object_id, payload)
            .map(|(written, start)| (written as u64, start.to_le_bytes().to_vec())),
        provider::OP_WRITE_BOUNDED => service
            .provider_write_bounded(header.object_id, payload, header.basis)
            .map(|(written, start)| (written as u64, start.to_le_bytes().to_vec())),
        provider::OP_READ_AT => service
            .provider_read_at(header.object_id, header.basis, header.length as usize)
            .map(|data| (data.len() as u64, data)),
        provider::OP_WRITE_AT => service
            .provider_write_at(header.object_id, header.basis, payload)
            .map(|written| (written as u64, Vec::new())),
        provider::OP_SYNC => service
            .provider_sync(header.object_id)
            .map(|_| (0, Vec::new())),
        provider::OP_MEMORY_OBJECT => service
            .provider_memory_object(header.object_id)
            .map(|identity| (identity, Vec::new())),
        provider::OP_SEEK => service
            .provider_seek(header.object_id, header.argument, header.basis)
            .map(|offset| (offset, Vec::new())),
        _ => Err(38),
    };
    let (status, value, data) = match result {
        Ok((value, data)) => (0, value, data),
        Err(errno) => (-(errno as i64), 0, Vec::new()),
    };
    provider::ResponseHeader {
        opcode: header.opcode,
        status,
        object_id: header.object_id,
        value,
        data_length: data.len() as u32,
    }
    .encode(&data, response)
    .ok()
}

#[cfg(target_os = "mochios")]
fn read_provider_shared(
    service: &mut filesystem_service::service::FilesystemService,
    header: mnu_abi::provider::RequestHeader,
    attached: &mochi_user_platform::ipc::IpcObjectHandles,
    buffer: &mut filesystem_service::provider_buffer::ProviderReadBuffer,
) -> Result<(u64, Vec<u8>), i32> {
    use mochi_user_platform::{handle, memory};
    if attached.count != 1 || attached.delivery_flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT {
        return Err(22);
    }
    let attachment = attached.handles[0];
    let required = handle::HANDLE_RIGHT_READ | handle::HANDLE_RIGHT_WRITE | handle::HANDLE_RIGHT_MAP;
    if attachment.reserved != 0 || attachment.rights & required != required {
        return Err(13);
    }
    // Checking type as well as size avoids writing a provider or file object
    // that could recurse into this service while it is processing this call.
    let object_length = memory::object_length(attachment.handle as u64).map_err(|_| 22)?;
    let end = header.basis.checked_add(header.length as u64).ok_or(22)?;
    if end > object_length {
        return Err(22);
    }
    let output = buffer.get(header.length as usize)?;
    let (count, start) = service.provider_read_into(header.object_id, output)?;
    // Native positioned I/O already supports anonymous VM objects. Avoid a
    // temporary address-space mapping and one user fault per destination page.
    filesystem_service::provider_buffer::publish(&output[..count], header.basis, |bytes, offset| {
        handle::write_at(attachment.handle, bytes, offset)
            .map_err(|error| error.raw().unsigned_abs() as i32)
    })?;
    Ok((count as u64, start.to_le_bytes().to_vec()))
}

#[cfg(not(target_os = "mochios"))]
fn main() {}
