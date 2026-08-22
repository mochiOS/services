use mboot_protocol::{
    Argument, Body, Destination, ErrorCode, KnownCommand, MAX_IPC_MESSAGE_LEN, Message,
    MessageType, STAGE_SHARED_CHUNK_LEN, STAGE_SHARED_CHUNK_MAGIC, decode_line, encode_to_string,
};
use mochi_user_platform as platform;

use crate::codec::{decode_hex, decode_rle32};

const AGENT_NAME: &str = "mboot-agent.service";
const FRAME_CHUNK_BYTES: u64 = 1536;
const STAGE_CHUNK_BYTES: usize = mboot_protocol::MAX_BULK_STAGE_BYTES;
const PAGE_SIZE: usize = 4096;
const PORTAL_CHUNK_BYTES: usize = 1536;
const PORTAL_EXPORT_CHUNK_BYTES: usize = 1536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostError {
    Unavailable,
    InvalidReply,
    Rejected(ErrorCode),
}

pub(crate) struct WindowInfo {
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) generation: u64,
    pub(crate) frame_size: usize,
    pub(crate) encoded_size: usize,
    pub(crate) title: String,
}

pub(crate) struct FrameChunk {
    pub(crate) total: usize,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) enum PortalEntryKind {
    Directory,
    File,
}

pub(crate) struct PortalEntry {
    pub(crate) kind: PortalEntryKind,
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) mode: u32,
}

pub(crate) struct HostClient {
    agent: u64,
    next_request_id: u64,
    stage_buffer: Option<SharedStageBuffer>,
}

struct SharedStageBuffer {
    address: u64,
    capacity: usize,
}

impl HostClient {
    pub(crate) fn connect() -> Result<Self, HostError> {
        let agent =
            platform::process::find_by_name(AGENT_NAME).map_err(|_| HostError::Unavailable)?;
        if agent == 0 {
            return Err(HostError::Unavailable);
        }
        Ok(Self {
            agent,
            next_request_id: 1,
            stage_buffer: None,
        })
    }

    pub(crate) fn launch(&mut self, instance: u64, application: &str) -> Result<(), HostError> {
        self.call(
            KnownCommand::LinuxLaunch,
            vec![
                Argument::new("application", application),
                Argument::new("instance", instance.to_string()),
            ],
        )?;
        Ok(())
    }

    pub(crate) fn stage_bundle(
        &mut self,
        instance: u64,
        bundle: &str,
        path: &str,
        size: u64,
        digest: &str,
    ) -> Result<(), HostError> {
        let response = self.call(
            KnownCommand::LinuxStageBegin,
            vec![
                Argument::new("instance", instance.to_string()),
                Argument::new("bundle", bundle),
                Argument::new("size", size.to_string()),
                Argument::new("digest", digest),
            ],
        )?;
        if response.argument("cached") == Some("1") {
            return Ok(());
        }
        if response.argument("cached") != Some("0") {
            return Err(HostError::InvalidReply);
        }
        let result = self.send_stage_file(instance, path, 0, size);
        if result.is_err() {
            let _ = self.call(
                KnownCommand::LinuxStageCancel,
                vec![Argument::new("instance", instance.to_string())],
            );
            return result;
        }
        self.call(
            KnownCommand::LinuxStageCommit,
            vec![Argument::new("instance", instance.to_string())],
        )?;
        Ok(())
    }

    pub(crate) fn stage_bundle_range(
        &mut self,
        instance: u64,
        bundle: &str,
        source_path: &str,
        source_offset: u64,
        size: u64,
        digest: &str,
    ) -> Result<(), HostError> {
        let response = self.call(
            KnownCommand::LinuxStageBegin,
            vec![
                Argument::new("instance", instance.to_string()),
                Argument::new("bundle", bundle),
                Argument::new("size", size.to_string()),
                Argument::new("digest", digest),
            ],
        )?;
        if response.argument("cached") == Some("1") {
            return Ok(());
        }
        if response.argument("cached") != Some("0") {
            return Err(HostError::InvalidReply);
        }
        let result = self.send_stage_file(instance, source_path, source_offset, size);
        if result.is_err() {
            let _ = self.call(
                KnownCommand::LinuxStageCancel,
                vec![Argument::new("instance", instance.to_string())],
            );
            return result;
        }
        self.call(
            KnownCommand::LinuxStageCommit,
            vec![Argument::new("instance", instance.to_string())],
        )?;
        Ok(())
    }

    pub(crate) fn launch_bundle(
        &mut self,
        instance: u64,
        bundle: &str,
        entrypoint: &str,
        user: &str,
        writable_paths: &[String],
        network: bool,
    ) -> Result<(), HostError> {
        let writable = if writable_paths.is_empty() {
            String::from("none")
        } else {
            writable_paths.join(",")
        };
        self.call(
            KnownCommand::LinuxBundleLaunch,
            vec![
                Argument::new("instance", instance.to_string()),
                Argument::new("bundle", bundle),
                Argument::new("entry", entrypoint),
                Argument::new("user", user),
                Argument::new("writable", writable),
                Argument::new("network", if network { "client" } else { "none" }),
            ],
        )?;
        Ok(())
    }

    pub(crate) fn portal_reset(&mut self, instance: u64) -> Result<(), HostError> {
        self.call(
            KnownCommand::LinuxPortalReset,
            vec![Argument::new("instance", instance.to_string())],
        )?;
        Ok(())
    }

    pub(crate) fn portal_grant(
        &mut self,
        instance: u64,
        grant: u64,
        path: &str,
        writable: bool,
        mode: u32,
    ) -> Result<(), HostError> {
        self.call(
            KnownCommand::LinuxPortalGrant,
            vec![
                Argument::new("instance", instance.to_string()),
                Argument::new("grant", grant.to_string()),
                Argument::new("access", if writable { "write" } else { "read" }),
                Argument::new("path", encode_hex(path.as_bytes())),
                Argument::new("mode", mode.to_string()),
            ],
        )?;
        Ok(())
    }

    pub(crate) fn portal_mkdir(
        &mut self,
        instance: u64,
        grant: u64,
        path: &str,
        mode: u32,
    ) -> Result<(), HostError> {
        self.call(
            KnownCommand::LinuxPortalMkdir,
            vec![
                Argument::new("instance", instance.to_string()),
                Argument::new("grant", grant.to_string()),
                Argument::new("path", encode_hex(path.as_bytes())),
                Argument::new("mode", mode.to_string()),
            ],
        )?;
        Ok(())
    }

    pub(crate) fn portal_file(
        &mut self,
        instance: u64,
        grant: u64,
        path: &str,
        source: &str,
        size: u64,
        mode: u32,
    ) -> Result<(), HostError> {
        self.call(
            KnownCommand::LinuxPortalFileBegin,
            vec![
                Argument::new("instance", instance.to_string()),
                Argument::new("grant", grant.to_string()),
                Argument::new("path", encode_hex(path.as_bytes())),
                Argument::new("size", size.to_string()),
                Argument::new("mode", mode.to_string()),
            ],
        )?;
        let result = self.send_portal_file(instance, source, size);
        if result.is_err() {
            let _ = self.call(
                KnownCommand::LinuxPortalFileCancel,
                vec![Argument::new("instance", instance.to_string())],
            );
            return result;
        }
        self.call(
            KnownCommand::LinuxPortalFileCommit,
            vec![Argument::new("instance", instance.to_string())],
        )?;
        Ok(())
    }

    fn send_portal_file(
        &mut self,
        instance: u64,
        path: &str,
        expected_size: u64,
    ) -> Result<(), HostError> {
        let fd = platform::file::open_path(path, 0).map_err(|_| HostError::Unavailable)?;
        let mut offset = 0u64;
        let mut buffer = [0u8; PORTAL_CHUNK_BYTES];
        let result = loop {
            let read =
                match platform::file::read(fd, buffer.as_mut_ptr() as u64, buffer.len() as u64) {
                    Ok(read) => read as usize,
                    Err(_) => break Err(HostError::Unavailable),
                };
            if read == 0 {
                break if offset == expected_size {
                    Ok(())
                } else {
                    Err(HostError::InvalidReply)
                };
            }
            if offset.saturating_add(read as u64) > expected_size {
                break Err(HostError::InvalidReply);
            }
            if let Err(error) = self.call(
                KnownCommand::LinuxPortalFileChunk,
                vec![
                    Argument::new("instance", instance.to_string()),
                    Argument::new("offset", offset.to_string()),
                    Argument::new("data", encode_hex(&buffer[..read])),
                ],
            ) {
                break Err(error);
            }
            offset += read as u64;
        };
        let _ = platform::file::close(fd);
        result
    }

    pub(crate) fn portal_export_begin(
        &mut self,
        instance: u64,
        grant: u64,
    ) -> Result<(usize, u32), HostError> {
        let response = self.call(
            KnownCommand::LinuxPortalExportBegin,
            vec![
                Argument::new("instance", instance.to_string()),
                Argument::new("grant", grant.to_string()),
            ],
        )?;
        Ok((
            parse_argument(&response, "entries")?,
            parse_argument(&response, "mode")?,
        ))
    }

    pub(crate) fn portal_export_entry(
        &mut self,
        instance: u64,
        index: usize,
    ) -> Result<PortalEntry, HostError> {
        let response = self.call(
            KnownCommand::LinuxPortalExportEntry,
            vec![
                Argument::new("instance", instance.to_string()),
                Argument::new("index", index.to_string()),
            ],
        )?;
        let kind = match response.argument("kind") {
            Some("directory") => PortalEntryKind::Directory,
            Some("file") => PortalEntryKind::File,
            _ => return Err(HostError::InvalidReply),
        };
        let path = decode_hex(response.argument("path").ok_or(HostError::InvalidReply)?)
            .map_err(|_| HostError::InvalidReply)?;
        let path = String::from_utf8(path).map_err(|_| HostError::InvalidReply)?;
        Ok(PortalEntry {
            kind,
            path,
            size: parse_argument(&response, "size")?,
            mode: parse_argument(&response, "mode")?,
        })
    }

    pub(crate) fn portal_export_chunk(
        &mut self,
        instance: u64,
        index: usize,
        offset: u64,
    ) -> Result<(u64, Vec<u8>), HostError> {
        let response = self.call(
            KnownCommand::LinuxPortalExportChunk,
            vec![
                Argument::new("instance", instance.to_string()),
                Argument::new("index", index.to_string()),
                Argument::new("offset", offset.to_string()),
                Argument::new("maximum", PORTAL_EXPORT_CHUNK_BYTES.to_string()),
            ],
        )?;
        let total = parse_argument(&response, "total_size")?;
        let data = match response.argument("data") {
            Some("none") => Vec::new(),
            Some(encoded) => decode_hex(encoded).map_err(|_| HostError::InvalidReply)?,
            None => return Err(HostError::InvalidReply),
        };
        Ok((total, data))
    }

    pub(crate) fn portal_export_end(&mut self, instance: u64) -> Result<(), HostError> {
        self.call(
            KnownCommand::LinuxPortalExportEnd,
            vec![Argument::new("instance", instance.to_string())],
        )?;
        Ok(())
    }

    pub(crate) fn portal_release(&mut self, instance: u64) -> Result<(), HostError> {
        self.call(
            KnownCommand::LinuxPortalRelease,
            vec![Argument::new("instance", instance.to_string())],
        )?;
        Ok(())
    }

    fn send_stage_file(
        &mut self,
        instance: u64,
        path: &str,
        source_offset: u64,
        expected_size: u64,
    ) -> Result<(), HostError> {
        let fd = platform::file::open_path(path, 0).map_err(|_| HostError::Unavailable)?;
        if platform::file::seek(
            fd,
            i64::try_from(source_offset).map_err(|_| HostError::InvalidReply)?,
            0,
        )
        .is_err()
        {
            let _ = platform::file::close(fd);
            return Err(HostError::Unavailable);
        }
        self.ensure_stage_buffer()?;
        let (buffer_address, buffer_capacity) = self
            .stage_buffer
            .as_ref()
            .map(|buffer| (buffer.address, buffer.capacity))
            .ok_or(HostError::Unavailable)?;
        let mut offset = 0u64;
        let result = loop {
            if offset == expected_size {
                break Ok(());
            }
            let remaining = expected_size - offset;
            let requested = core::cmp::min(remaining, buffer_capacity as u64);
            let read = match platform::file::read(fd, buffer_address, requested) {
                Ok(read) => read as usize,
                Err(_) => break Err(HostError::Unavailable),
            };
            if read == 0 {
                break Err(HostError::InvalidReply);
            }
            if let Err(error) = self.send_shared_stage_chunk(instance, offset, read) {
                break Err(error);
            }
            offset += read as u64;
        };
        let _ = platform::file::close(fd);
        result
    }

    fn ensure_stage_buffer(&mut self) -> Result<(), HostError> {
        if self.stage_buffer.is_some() {
            return Ok(());
        }
        let page_count = STAGE_CHUNK_BYTES.div_ceil(PAGE_SIZE);
        let address = platform::memory::alloc_shared_page_count(page_count)
            .map_err(|_| HostError::Unavailable)?;
        platform::ipc::send_page_count(self.agent, page_count, address)
            .map_err(|_| HostError::Unavailable)?;
        self.stage_buffer = Some(SharedStageBuffer {
            address,
            capacity: page_count * PAGE_SIZE,
        });
        Ok(())
    }

    fn send_shared_stage_chunk(
        &mut self,
        instance: u64,
        offset: u64,
        length: usize,
    ) -> Result<(), HostError> {
        let mut request = [0u8; STAGE_SHARED_CHUNK_LEN];
        request[..8].copy_from_slice(&STAGE_SHARED_CHUNK_MAGIC);
        request[8..16].copy_from_slice(&instance.to_le_bytes());
        request[16..24].copy_from_slice(&offset.to_le_bytes());
        request[24..32].copy_from_slice(&(length as u64).to_le_bytes());
        let mut reply = [0u8; 4];
        let raw = platform::ipc::call(self.agent, &request, &mut reply)
            .map_err(|_| HostError::Unavailable)?;
        let reply_length = (raw & 0xffff_ffff) as usize;
        if reply_length != reply.len() || i32::from_le_bytes(reply) != 0 {
            return Err(HostError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn windows(&mut self, instance: u64) -> Result<Vec<u32>, HostError> {
        let response = self.call(
            KnownCommand::LinuxWindows,
            vec![Argument::new("instance", instance.to_string())],
        )?;
        let value = response
            .argument("windows")
            .ok_or(HostError::InvalidReply)?;
        if value == "none" {
            return Ok(Vec::new());
        }
        value
            .split(',')
            .map(|item| item.parse().map_err(|_| HostError::InvalidReply))
            .collect()
    }

    pub(crate) fn window_info(
        &mut self,
        instance: u64,
        window: u32,
    ) -> Result<WindowInfo, HostError> {
        let response = self.call(
            KnownCommand::LinuxWindowInfo,
            window_arguments(instance, window),
        )?;
        if response.argument("encoding") != Some("rle32") {
            return Err(HostError::InvalidReply);
        }
        let title = decode_hex(response.argument("title").ok_or(HostError::InvalidReply)?)
            .map_err(|_| HostError::InvalidReply)?;
        let title = String::from_utf8(title).map_err(|_| HostError::InvalidReply)?;
        Ok(WindowInfo {
            width: parse_argument(&response, "width")?,
            height: parse_argument(&response, "height")?,
            generation: parse_argument(&response, "generation")?,
            frame_size: parse_argument(&response, "frame_size")?,
            encoded_size: parse_argument(&response, "encoded_size")?,
            title,
        })
    }

    pub(crate) fn frame_chunk(
        &mut self,
        instance: u64,
        window: u32,
        generation: u64,
        offset: usize,
    ) -> Result<FrameChunk, HostError> {
        let mut arguments = window_arguments(instance, window);
        arguments.extend([
            Argument::new("generation", generation.to_string()),
            Argument::new("offset", offset.to_string()),
            Argument::new("maximum", FRAME_CHUNK_BYTES.to_string()),
        ]);
        let response = self.call(KnownCommand::LinuxFrame, arguments)?;
        let total = parse_argument(&response, "total_size")?;
        let bytes = decode_hex(response.argument("data").ok_or(HostError::InvalidReply)?)
            .map_err(|_| HostError::InvalidReply)?;
        if bytes.is_empty() || bytes.len() > FRAME_CHUNK_BYTES as usize {
            return Err(HostError::InvalidReply);
        }
        Ok(FrameChunk { total, bytes })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn input(
        &mut self,
        instance: u64,
        window: u32,
        kind: &str,
        code: u8,
        value: i32,
        x: i16,
        y: i16,
        modifiers: u32,
    ) -> Result<(), HostError> {
        let mut arguments = window_arguments(instance, window);
        arguments.extend([
            Argument::new("kind", kind),
            Argument::new("code", code.to_string()),
            Argument::new("value", value.to_string()),
            Argument::new("x", x.to_string()),
            Argument::new("y", y.to_string()),
            Argument::new("modifiers", modifiers.to_string()),
        ]);
        self.call(KnownCommand::LinuxInput, arguments)?;
        Ok(())
    }

    pub(crate) fn configure(
        &mut self,
        instance: u64,
        window: u32,
        width: u16,
        height: u16,
    ) -> Result<(), HostError> {
        let mut arguments = window_arguments(instance, window);
        arguments.extend([
            Argument::new("width", width.to_string()),
            Argument::new("height", height.to_string()),
        ]);
        self.call(KnownCommand::LinuxConfigure, arguments)?;
        Ok(())
    }

    pub(crate) fn close(&mut self, instance: u64, window: u32) -> Result<(), HostError> {
        self.call(KnownCommand::LinuxClose, window_arguments(instance, window))?;
        Ok(())
    }

    fn call(
        &mut self,
        command: KnownCommand,
        arguments: Vec<Argument>,
    ) -> Result<Message, HostError> {
        let request_id = self.allocate_request_id();
        let request = Message::command(
            Destination::Mboot,
            MessageType::Request,
            request_id,
            command,
            arguments,
        );
        let encoded = encode_to_string(&request).map_err(|_| HostError::InvalidReply)?;
        let mut reply = [0u8; MAX_IPC_MESSAGE_LEN];
        let raw = platform::ipc::call(self.agent, encoded.as_bytes(), &mut reply)
            .map_err(|_| HostError::Unavailable)?;
        let length = (raw & 0xffff_ffff) as usize;
        let response = decode_line(reply.get(..length).ok_or(HostError::InvalidReply)?)
            .map_err(|_| HostError::InvalidReply)?;
        if response.request_id != request_id
            || response.destination != Destination::Mochios
            || response.message_type != MessageType::Response
        {
            return Err(HostError::InvalidReply);
        }
        match response.body {
            Body::Ok => Ok(response),
            Body::Error(error) => Err(HostError::Rejected(error)),
            Body::Command(_) => Err(HostError::InvalidReply),
        }
    }

    fn allocate_request_id(&mut self) -> u64 {
        let current = self.next_request_id.max(1);
        self.next_request_id = current.wrapping_add(1).max(1);
        current
    }
}

pub(crate) fn decode_frame(encoded: &[u8], expected: usize) -> Result<Vec<u8>, HostError> {
    decode_rle32(encoded, expected).map_err(|_| HostError::InvalidReply)
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn window_arguments(instance: u64, window: u32) -> Vec<Argument> {
    vec![
        Argument::new("instance", instance.to_string()),
        Argument::new("window", window.to_string()),
    ]
}

fn parse_argument<T: core::str::FromStr>(message: &Message, name: &str) -> Result<T, HostError> {
    message
        .argument(name)
        .and_then(|value| value.parse().ok())
        .ok_or(HostError::InvalidReply)
}
