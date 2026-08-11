use mboot_protocol::{
    Argument, Body, Destination, ErrorCode, KnownCommand, MAX_MESSAGE_LEN, Message, MessageType,
    decode_line, encode_to_string,
};
use mochi_user_platform as platform;

use crate::codec::{decode_hex, decode_rle32};

const AGENT_NAME: &str = "mboot-agent.service";
const FRAME_CHUNK_BYTES: u64 = 1536;

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

pub(crate) struct HostClient {
    agent: u64,
    next_request_id: u64,
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

    pub(crate) fn frame(
        &mut self,
        instance: u64,
        window: u32,
        info: &WindowInfo,
    ) -> Result<Vec<u8>, HostError> {
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(info.encoded_size)
            .map_err(|_| HostError::InvalidReply)?;
        while frame.len() < info.encoded_size {
            let mut arguments = window_arguments(instance, window);
            arguments.extend([
                Argument::new("generation", info.generation.to_string()),
                Argument::new("offset", frame.len().to_string()),
                Argument::new("maximum", FRAME_CHUNK_BYTES.to_string()),
            ]);
            let response = self.call(KnownCommand::LinuxFrame, arguments)?;
            let total: usize = parse_argument(&response, "total_size")?;
            if total != info.encoded_size {
                return Err(HostError::InvalidReply);
            }
            let bytes = decode_hex(response.argument("data").ok_or(HostError::InvalidReply)?)
                .map_err(|_| HostError::InvalidReply)?;
            if bytes.is_empty() || frame.len().saturating_add(bytes.len()) > info.encoded_size {
                return Err(HostError::InvalidReply);
            }
            frame.extend_from_slice(&bytes);
        }
        decode_rle32(&frame, info.frame_size).map_err(|_| HostError::InvalidReply)
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
        let mut reply = [0u8; MAX_MESSAGE_LEN];
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
