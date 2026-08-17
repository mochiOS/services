use std::collections::VecDeque;

use mboot_protocol::{
    Argument, Body, Destination, ErrorCode, KnownCommand, Message, MessageType, VERSION,
    decode_line, encode_to_string,
};

use crate::decoder::LineDecoder;
use crate::transport::{ControlTransport, TransportError};

const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
const EXTERNAL_REQUEST_TIMEOUT_MS: u64 = 5_000;
const WIFI_REQUEST_TIMEOUT_MS: u64 = 15_000;
const MAX_HEARTBEAT_MS: u64 = 3_600_000;
const READ_CHUNK: usize = 1024;
const MAX_READS_PER_TICK: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadyStage {
    Kernel = 1,
    Userspace = 2,
    Display = 3,
    Desktop = 4,
}

impl ReadyStage {
    pub const ALL: [Self; 4] = [Self::Kernel, Self::Userspace, Self::Display, Self::Desktop];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Userspace => "userspace",
            Self::Display => "display",
            Self::Desktop => "desktop",
        }
    }

    const fn number(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingKind {
    Sync,
    Hello,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingRequest {
    id: u64,
    kind: PendingKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Disconnected,
    AwaitingSync,
    AwaitingWelcome,
    Negotiated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentError {
    InvalidReadyTransition,
    Encode,
    Transport(TransportError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalRequestError {
    NotNegotiated,
    Busy,
    InvalidRequest,
    Encode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExternalRequest {
    host_request_id: u64,
    client_request_id: u64,
    deadline_ms: u64,
}

pub struct Agent {
    version: String,
    boot_id: String,
    boot_started_ms: u64,
    phase: Phase,
    decoder: LineDecoder,
    outbound: VecDeque<u8>,
    next_request_id: u64,
    pending: Option<PendingRequest>,
    external_pending: Option<ExternalRequest>,
    external_response: Option<Message>,
    handshake_deadline_ms: Option<u64>,
    session: Option<String>,
    heartbeat_ms: Option<u64>,
    next_heartbeat_ms: Option<u64>,
    achieved_stage: ReadyStage,
    sent_stage: u8,
}

impl Agent {
    pub fn new(version: impl Into<String>, boot_id: impl Into<String>, started_ms: u64) -> Self {
        Self {
            version: version.into(),
            boot_id: boot_id.into(),
            boot_started_ms: started_ms,
            phase: Phase::Disconnected,
            decoder: LineDecoder::new(),
            outbound: VecDeque::new(),
            next_request_id: 1,
            pending: None,
            external_pending: None,
            external_response: None,
            handshake_deadline_ms: None,
            session: None,
            heartbeat_ms: None,
            next_heartbeat_ms: None,
            achieved_stage: ReadyStage::Kernel,
            sent_stage: 0,
        }
    }

    pub const fn is_negotiated(&self) -> bool {
        matches!(self.phase, Phase::Negotiated)
    }

    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }

    pub const fn achieved_stage(&self) -> ReadyStage {
        self.achieved_stage
    }

    pub fn queue_external_request(
        &mut self,
        message: Message,
        now_ms: u64,
    ) -> Result<(), ExternalRequestError> {
        if !self.is_negotiated() {
            return Err(ExternalRequestError::NotNegotiated);
        }
        if self.external_pending.is_some() {
            return Err(ExternalRequestError::Busy);
        }
        if message.destination != Destination::Mboot
            || message.message_type != MessageType::Request
            || !matches!(
                message.known_command(),
                Some(
                    KnownCommand::DeveloperBegin
                        | KnownCommand::DeveloperChunk
                        | KnownCommand::DeveloperCompile
                        | KnownCommand::DeveloperRead
                        | KnownCommand::DeveloperCancel
                        | KnownCommand::LinuxLaunch
                        | KnownCommand::LinuxStageBegin
                        | KnownCommand::LinuxStageChunk
                        | KnownCommand::LinuxStageCommit
                        | KnownCommand::LinuxStageCancel
                        | KnownCommand::LinuxPortalReset
                        | KnownCommand::LinuxPortalGrant
                        | KnownCommand::LinuxPortalMkdir
                        | KnownCommand::LinuxPortalFileBegin
                        | KnownCommand::LinuxPortalFileChunk
                        | KnownCommand::LinuxPortalFileCommit
                        | KnownCommand::LinuxPortalFileCancel
                        | KnownCommand::LinuxPortalRelease
                        | KnownCommand::LinuxPortalExportBegin
                        | KnownCommand::LinuxPortalExportEntry
                        | KnownCommand::LinuxPortalExportChunk
                        | KnownCommand::LinuxPortalExportEnd
                        | KnownCommand::LinuxBundleLaunch
                        | KnownCommand::LinuxWindows
                        | KnownCommand::LinuxWindowInfo
                        | KnownCommand::LinuxFrame
                        | KnownCommand::LinuxInput
                        | KnownCommand::LinuxConfigure
                        | KnownCommand::LinuxClose
                        | KnownCommand::WifiStatus
                        | KnownCommand::WifiScan
                        | KnownCommand::WifiSetEnabled
                        | KnownCommand::WifiConnect
                        | KnownCommand::WifiDisconnect
                )
            )
        {
            return Err(ExternalRequestError::InvalidRequest);
        }
        let host_request_id = self.allocate_request_id();
        let client_request_id = message.request_id;
        let command = message
            .known_command()
            .ok_or(ExternalRequestError::InvalidRequest)?;
        self.queue_message(Message::command(
            Destination::Mboot,
            MessageType::Request,
            host_request_id,
            command,
            message.arguments,
        ))
        .map_err(|_| ExternalRequestError::Encode)?;
        self.external_pending = Some(ExternalRequest {
            host_request_id,
            client_request_id,
            deadline_ms: now_ms.saturating_add(external_request_timeout_ms(command)),
        });
        Ok(())
    }

    pub fn take_external_response(&mut self) -> Option<Message> {
        self.external_response.take()
    }

    pub const fn external_request_pending(&self) -> bool {
        self.external_pending.is_some()
    }

    pub fn mark_ready(&mut self, stage: ReadyStage) -> Result<(), AgentError> {
        if stage < self.achieved_stage || stage.number() > self.achieved_stage.number() + 1 {
            return Err(AgentError::InvalidReadyTransition);
        }
        if stage > self.achieved_stage {
            self.achieved_stage = stage;
        }
        Ok(())
    }

    pub fn tick(
        &mut self,
        transport: &mut impl ControlTransport,
        now_ms: u64,
    ) -> Result<(), AgentError> {
        if let Err(error) = transport.poll() {
            return self.transport_failed(transport, error);
        }
        if !transport.is_connected() {
            self.reset_session();
            return Ok(());
        }
        if self.phase == Phase::Disconnected {
            self.begin_handshake(now_ms)?;
        }
        if self
            .handshake_deadline_ms
            .is_some_and(|deadline| now_ms >= deadline)
        {
            transport.reset_connection();
            self.reset_session();
            return Ok(());
        }

        self.flush(transport)?;
        self.receive(transport, now_ms)?;
        self.expire_external_request(now_ms);
        if self.phase == Phase::Negotiated {
            self.queue_ready_stages()?;
            if self
                .next_heartbeat_ms
                .is_some_and(|deadline| now_ms >= deadline)
            {
                self.queue_heartbeat(now_ms)?;
            }
        }
        self.flush(transport)
    }

    fn expire_external_request(&mut self, now_ms: u64) {
        let Some(pending) = self
            .external_pending
            .filter(|pending| now_ms >= pending.deadline_ms)
        else {
            return;
        };
        self.external_pending = None;
        self.external_response = Some(Message::error(
            Destination::Mochios,
            pending.client_request_id,
            ErrorCode::Timeout,
            Vec::new(),
        ));
    }

    fn begin_handshake(&mut self, now_ms: u64) -> Result<(), AgentError> {
        self.decoder.reset();
        self.outbound.clear();
        self.pending = None;
        self.session = None;
        self.heartbeat_ms = None;
        self.next_heartbeat_ms = None;
        self.sent_stage = 0;
        let id = self.allocate_request_id();
        self.queue_message(Message::command(
            Destination::Mboot,
            MessageType::Request,
            id,
            KnownCommand::ProtocolSync,
            Vec::new(),
        ))?;
        self.pending = Some(PendingRequest {
            id,
            kind: PendingKind::Sync,
        });
        self.phase = Phase::AwaitingSync;
        self.handshake_deadline_ms = Some(now_ms.saturating_add(HANDSHAKE_TIMEOUT_MS));
        Ok(())
    }

    fn receive(
        &mut self,
        transport: &mut impl ControlTransport,
        now_ms: u64,
    ) -> Result<(), AgentError> {
        let mut bytes = [0u8; READ_CHUNK];
        for _ in 0..MAX_READS_PER_TICK {
            let length = match transport.read(&mut bytes) {
                Ok(0) | Err(TransportError::WouldBlock) => break,
                Ok(length) => length.min(bytes.len()),
                Err(error) => return self.transport_failed(transport, error),
            };
            for line in self.decoder.push(&bytes[..length]) {
                let Ok(line) = line else {
                    continue;
                };
                let Ok(message) = decode_line(&line) else {
                    continue;
                };
                self.handle_message(message, now_ms)?;
            }
        }
        Ok(())
    }

    fn handle_message(&mut self, message: Message, now_ms: u64) -> Result<(), AgentError> {
        if message.message_type == MessageType::Request {
            return self.handle_request(message, now_ms);
        }
        if let Some(external) = self.external_pending
            && message.destination == Destination::Mochios
            && message.message_type == MessageType::Response
            && message.request_id == external.host_request_id
        {
            let mut response = message;
            response.request_id = external.client_request_id;
            self.external_pending = None;
            self.external_response = Some(response);
            return Ok(());
        }
        let Some(pending) = self.pending else {
            return Ok(());
        };
        if message.destination != Destination::Mochios
            || message.message_type != MessageType::Response
            || message.request_id != pending.id
        {
            return Ok(());
        }
        match pending.kind {
            PendingKind::Sync if matches!(message.body, Body::Ok) => {
                self.pending = None;
                let id = self.allocate_request_id();
                self.queue_message(Message::command(
                    Destination::Mboot,
                    MessageType::Request,
                    id,
                    KnownCommand::ProtocolHello,
                    vec![
                        Argument::new("system", "mochios"),
                        Argument::new("version", self.version.clone()),
                        Argument::new("boot_id", self.boot_id.clone()),
                        Argument::new("capabilities", "ready,heartbeat,status,linux.x11,wifi"),
                    ],
                ))?;
                self.pending = Some(PendingRequest {
                    id,
                    kind: PendingKind::Hello,
                });
                self.phase = Phase::AwaitingWelcome;
                self.handshake_deadline_ms = Some(now_ms.saturating_add(HANDSHAKE_TIMEOUT_MS));
            }
            PendingKind::Hello if self.valid_welcome(&message) => {
                let heartbeat_ms = message
                    .argument("heartbeat_ms")
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
                self.session = message.argument("session").map(str::to_owned);
                self.heartbeat_ms = Some(heartbeat_ms);
                self.next_heartbeat_ms = Some(now_ms.saturating_add(heartbeat_ms));
                self.pending = None;
                self.phase = Phase::Negotiated;
                self.handshake_deadline_ms = None;
                self.sent_stage = 0;
            }
            _ => {}
        }
        Ok(())
    }

    fn valid_welcome(&self, message: &Message) -> bool {
        message.known_command() == Some(KnownCommand::ProtocolWelcome)
            && message.version == VERSION
            && message.argument("version") == Some("1")
            && message
                .argument("session")
                .is_some_and(|session| !session.is_empty())
            && message
                .argument("heartbeat_ms")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|interval| interval > 0 && interval <= MAX_HEARTBEAT_MS)
    }

    fn handle_request(&mut self, request: Message, now_ms: u64) -> Result<(), AgentError> {
        if request.destination != Destination::Mochios || request.request_id == 0 {
            return Ok(());
        }
        let response = match request.known_command() {
            Some(KnownCommand::ProtocolPing | KnownCommand::ProtocolSync) => {
                Message::ok(Destination::Mboot, request.request_id, Vec::new())
            }
            Some(KnownCommand::GuestStatus) => Message::ok(
                Destination::Mboot,
                request.request_id,
                vec![
                    Argument::new("stage", self.achieved_stage.as_str()),
                    Argument::new(
                        "uptime_ms",
                        now_ms.saturating_sub(self.boot_started_ms).to_string(),
                    ),
                ],
            ),
            _ => Message::error(
                Destination::Mboot,
                request.request_id,
                ErrorCode::Unsupported,
                Vec::new(),
            ),
        };
        self.queue_message(response)
    }

    fn queue_ready_stages(&mut self) -> Result<(), AgentError> {
        for stage in ReadyStage::ALL {
            if stage.number() <= self.sent_stage || stage > self.achieved_stage {
                continue;
            }
            self.queue_message(Message::command(
                Destination::Mboot,
                MessageType::Event,
                0,
                KnownCommand::GuestReady,
                vec![Argument::new("stage", stage.as_str())],
            ))?;
            self.sent_stage = stage.number();
        }
        Ok(())
    }

    fn queue_heartbeat(&mut self, now_ms: u64) -> Result<(), AgentError> {
        let Some(interval) = self.heartbeat_ms else {
            return Ok(());
        };
        self.queue_message(Message::command(
            Destination::Mboot,
            MessageType::Event,
            0,
            KnownCommand::GuestHeartbeat,
            vec![Argument::new(
                "uptime_ms",
                now_ms.saturating_sub(self.boot_started_ms).to_string(),
            )],
        ))?;
        self.next_heartbeat_ms = Some(now_ms.saturating_add(interval));
        Ok(())
    }

    fn queue_message(&mut self, message: Message) -> Result<(), AgentError> {
        let encoded = encode_to_string(&message).map_err(|_| AgentError::Encode)?;
        self.outbound.extend(encoded.bytes());
        Ok(())
    }

    fn flush(&mut self, transport: &mut impl ControlTransport) -> Result<(), AgentError> {
        while !self.outbound.is_empty() {
            let contiguous = self.outbound.make_contiguous();
            let written = match transport.write(contiguous) {
                Ok(0) | Err(TransportError::WouldBlock) => return Ok(()),
                Ok(written) => written.min(contiguous.len()),
                Err(error) => return self.transport_failed(transport, error),
            };
            self.outbound.drain(..written);
        }
        Ok(())
    }

    fn allocate_request_id(&mut self) -> u64 {
        let id = self.next_request_id.max(1);
        self.next_request_id = id.wrapping_add(1);
        if self.next_request_id == 0 {
            self.next_request_id = 1;
        }
        id
    }

    fn transport_failed<T>(
        &mut self,
        transport: &mut impl ControlTransport,
        error: TransportError,
    ) -> Result<T, AgentError> {
        transport.reset_connection();
        self.reset_session();
        Err(AgentError::Transport(error))
    }

    fn reset_session(&mut self) {
        self.phase = Phase::Disconnected;
        self.decoder.reset();
        self.outbound.clear();
        self.pending = None;
        self.external_pending = None;
        self.external_response = None;
        self.handshake_deadline_ms = None;
        self.session = None;
        self.heartbeat_ms = None;
        self.next_heartbeat_ms = None;
        self.sent_stage = 0;
    }
}

const fn external_request_timeout_ms(command: KnownCommand) -> u64 {
    match command {
        KnownCommand::WifiStatus
        | KnownCommand::WifiScan
        | KnownCommand::WifiSetEnabled
        | KnownCommand::WifiConnect
        | KnownCommand::WifiDisconnect => WIFI_REQUEST_TIMEOUT_MS,
        _ => EXTERNAL_REQUEST_TIMEOUT_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ControlTransport;

    #[derive(Default)]
    struct MockTransport {
        connected: bool,
        input: VecDeque<u8>,
        output: Vec<u8>,
        read_limit: usize,
        write_limit: usize,
    }

    impl MockTransport {
        fn connected() -> Self {
            Self {
                connected: true,
                read_limit: usize::MAX,
                write_limit: usize::MAX,
                ..Self::default()
            }
        }

        fn push(&mut self, bytes: &[u8]) {
            self.input.extend(bytes);
        }

        fn lines(&self) -> Vec<Message> {
            self.output
                .split_inclusive(|byte| *byte == b'\n')
                .filter_map(|line| decode_line(line).ok())
                .collect()
        }
    }

    impl ControlTransport for MockTransport {
        fn poll(&mut self) -> Result<(), TransportError> {
            Ok(())
        }

        fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
            let length = buffer.len().min(self.read_limit).min(self.input.len());
            for destination in &mut buffer[..length] {
                if let Some(byte) = self.input.pop_front() {
                    *destination = byte;
                }
            }
            Ok(length)
        }

        fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError> {
            if !self.connected {
                return Err(TransportError::Disconnected);
            }
            let length = buffer.len().min(self.write_limit);
            self.output.extend_from_slice(&buffer[..length]);
            Ok(length)
        }

        fn is_connected(&self) -> bool {
            self.connected
        }

        fn reset_connection(&mut self) {
            self.connected = false;
        }
    }

    fn response(message: Message) -> Vec<u8> {
        encode_to_string(&message).unwrap().into_bytes()
    }

    fn negotiate(agent: &mut Agent, transport: &mut MockTransport, now: u64) {
        agent.tick(transport, now).unwrap();
        let sync = transport.lines().pop().unwrap();
        transport.push(&response(Message::ok(
            Destination::Mochios,
            sync.request_id,
            Vec::new(),
        )));
        agent.tick(transport, now + 1).unwrap();
        let hello = transport.lines().pop().unwrap();
        assert_eq!(hello.known_command(), Some(KnownCommand::ProtocolHello));
        assert_eq!(
            hello.argument("capabilities"),
            Some("ready,heartbeat,status,linux.x11,wifi")
        );
        transport.push(&response(Message::command(
            Destination::Mochios,
            MessageType::Response,
            hello.request_id,
            KnownCommand::ProtocolWelcome,
            vec![
                Argument::new("version", "1"),
                Argument::new("session", "session-a"),
                Argument::new("heartbeat_ms", "25"),
            ],
        )));
        agent.tick(transport, now + 2).unwrap();
    }

    #[test]
    fn sync_hello_and_welcome_establish_session() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        let mut transport = MockTransport::connected();
        negotiate(&mut agent, &mut transport, 10);
        assert!(agent.is_negotiated());
        assert_eq!(agent.session(), Some("session-a"));
        let messages = transport.lines();
        assert_eq!(
            messages[0].known_command(),
            Some(KnownCommand::ProtocolSync)
        );
        assert_eq!(messages[1].argument("version"), Some("26.0.0"));
        assert_eq!(messages[1].argument("boot_id"), Some("boot-a"));
        assert_eq!(messages[2].argument("stage"), Some("kernel"));
    }

    #[test]
    fn invalid_and_mismatched_welcome_are_rejected() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        let mut transport = MockTransport::connected();
        agent.tick(&mut transport, 1).unwrap();
        let sync = transport.lines().pop().unwrap();
        transport.push(&response(Message::ok(
            Destination::Mochios,
            sync.request_id,
            Vec::new(),
        )));
        agent.tick(&mut transport, 2).unwrap();
        let hello = transport.lines().pop().unwrap();
        for (request_id, heartbeat) in [(hello.request_id + 1, "25"), (hello.request_id, "0")] {
            transport.push(&response(Message::command(
                Destination::Mochios,
                MessageType::Response,
                request_id,
                KnownCommand::ProtocolWelcome,
                vec![
                    Argument::new("version", "1"),
                    Argument::new("session", "session-a"),
                    Argument::new("heartbeat_ms", heartbeat),
                ],
            )));
            agent.tick(&mut transport, 3).unwrap();
            assert!(!agent.is_negotiated());
        }
    }

    #[test]
    fn ready_order_is_enforced_and_replayed_after_reconnect() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        assert_eq!(
            agent.mark_ready(ReadyStage::Display),
            Err(AgentError::InvalidReadyTransition)
        );
        agent.mark_ready(ReadyStage::Userspace).unwrap();
        assert_eq!(
            agent.mark_ready(ReadyStage::Kernel),
            Err(AgentError::InvalidReadyTransition)
        );
        let mut transport = MockTransport::connected();
        negotiate(&mut agent, &mut transport, 1);
        let stages: Vec<_> = transport
            .lines()
            .into_iter()
            .filter(|message| message.known_command() == Some(KnownCommand::GuestReady))
            .map(|message| message.argument("stage").unwrap().to_owned())
            .collect();
        assert_eq!(stages, ["kernel", "userspace"]);

        transport.connected = false;
        agent.tick(&mut transport, 10).unwrap();
        assert!(!agent.is_negotiated());
        transport.output.clear();
        transport.connected = true;
        negotiate(&mut agent, &mut transport, 20);
        let replayed: Vec<_> = transport
            .lines()
            .into_iter()
            .filter(|message| message.known_command() == Some(KnownCommand::GuestReady))
            .map(|message| message.argument("stage").unwrap().to_owned())
            .collect();
        assert_eq!(replayed, ["kernel", "userspace"]);
    }

    #[test]
    fn heartbeat_uses_welcome_interval_and_monotonic_uptime() {
        let mut agent = Agent::new("26.0.0", "boot-a", 5);
        let mut transport = MockTransport::connected();
        negotiate(&mut agent, &mut transport, 10);
        let before = transport.lines().len();
        agent.tick(&mut transport, 36).unwrap();
        assert_eq!(transport.lines().len(), before);
        agent.tick(&mut transport, 37).unwrap();
        let heartbeat = transport.lines().pop().unwrap();
        assert_eq!(
            heartbeat.known_command(),
            Some(KnownCommand::GuestHeartbeat)
        );
        assert_eq!(heartbeat.argument("uptime_ms"), Some("32"));
    }

    #[test]
    fn partial_io_and_multiple_input_lines_are_supported() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        let mut transport = MockTransport::connected();
        transport.write_limit = 3;
        agent.tick(&mut transport, 1).unwrap();
        let sync = transport.lines().pop().unwrap();
        let mut replies = response(Message::ok(
            Destination::Mochios,
            sync.request_id,
            Vec::new(),
        ));
        replies.extend_from_slice(&response(Message::command(
            Destination::Mochios,
            MessageType::Request,
            99,
            KnownCommand::GuestShutdown,
            Vec::new(),
        )));
        transport.read_limit = 2;
        transport.push(&replies);
        agent.tick(&mut transport, 2).unwrap();
        assert!(transport.lines().iter().any(|message| {
            message.request_id == 99 && matches!(message.body, Body::Error(ErrorCode::Unsupported))
        }));
    }

    #[test]
    fn disconnect_destroys_session_and_pending_state() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        let mut transport = MockTransport::connected();
        negotiate(&mut agent, &mut transport, 1);
        transport.connected = false;
        agent.tick(&mut transport, 5).unwrap();
        assert!(!agent.is_negotiated());
        assert_eq!(agent.session(), None);
    }

    #[test]
    fn welcome_requires_the_expected_shape_and_success_status() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        let mut transport = MockTransport::connected();
        agent.tick(&mut transport, 1).unwrap();
        let sync = transport.lines().pop().unwrap();
        transport.push(&response(Message::ok(
            Destination::Mochios,
            sync.request_id,
            Vec::new(),
        )));
        agent.tick(&mut transport, 2).unwrap();
        let hello = transport.lines().pop().unwrap();

        let valid = Message::command(
            Destination::Mochios,
            MessageType::Response,
            hello.request_id,
            KnownCommand::ProtocolWelcome,
            vec![
                Argument::new("version", "1"),
                Argument::new("session", "session-a"),
                Argument::new("heartbeat_ms", "25"),
            ],
        );
        let mut invalid_messages = Vec::new();
        let mut wrong_destination = valid.clone();
        wrong_destination.destination = Destination::Mboot;
        invalid_messages.push(wrong_destination);
        let mut wrong_type = valid.clone();
        wrong_type.message_type = MessageType::Event;
        wrong_type.request_id = 0;
        invalid_messages.push(wrong_type);
        let mut failed = valid.clone();
        failed.body = Body::Error(ErrorCode::Internal);
        invalid_messages.push(failed);
        let mut missing_session = valid.clone();
        missing_session
            .arguments
            .retain(|argument| argument.key != "session");
        invalid_messages.push(missing_session);

        for message in invalid_messages {
            agent.handle_message(message, 3).unwrap();
            assert!(!agent.is_negotiated());
        }
        agent.handle_message(valid, 3).unwrap();
        assert!(agent.is_negotiated());
    }

    #[test]
    fn guest_status_reports_stage_and_monotonic_uptime() {
        let mut agent = Agent::new("26.0.0", "boot-a", 10);
        agent.mark_ready(ReadyStage::Userspace).unwrap();
        let mut transport = MockTransport::connected();
        negotiate(&mut agent, &mut transport, 20);
        transport.push(&response(Message::command(
            Destination::Mochios,
            MessageType::Request,
            77,
            KnownCommand::GuestStatus,
            Vec::new(),
        )));
        agent.tick(&mut transport, 45).unwrap();
        let status = transport
            .lines()
            .into_iter()
            .find(|message| message.request_id == 77)
            .unwrap();
        assert!(matches!(status.body, Body::Ok));
        assert_eq!(status.argument("stage"), Some("userspace"));
        assert_eq!(status.argument("uptime_ms"), Some("35"));
    }

    #[test]
    fn power_requests_return_unsupported_without_executing_actions() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        let mut transport = MockTransport::connected();
        negotiate(&mut agent, &mut transport, 1);
        for (request_id, command) in [
            (81, KnownCommand::GuestShutdown),
            (82, KnownCommand::GuestReboot),
        ] {
            transport.push(&response(Message::command(
                Destination::Mochios,
                MessageType::Request,
                request_id,
                command,
                Vec::new(),
            )));
        }
        agent.tick(&mut transport, 10).unwrap();
        for request_id in 81..=82 {
            assert!(transport.lines().iter().any(|message| {
                message.request_id == request_id
                    && matches!(message.body, Body::Error(ErrorCode::Unsupported))
            }));
        }
    }

    #[test]
    fn request_ids_wrap_without_using_zero() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        agent.next_request_id = u64::MAX;
        assert_eq!(agent.allocate_request_id(), u64::MAX);
        assert_eq!(agent.allocate_request_id(), 1);
        assert_eq!(agent.allocate_request_id(), 2);
    }

    #[test]
    fn external_request_is_forwarded_and_response_id_is_restored() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        let mut transport = MockTransport::connected();
        negotiate(&mut agent, &mut transport, 1);
        transport.output.clear();

        agent
            .queue_external_request(
                Message::command(
                    Destination::Mboot,
                    MessageType::Request,
                    91,
                    KnownCommand::DeveloperBegin,
                    vec![
                        Argument::new("transaction", "7"),
                        Argument::new("size", "12"),
                    ],
                ),
                4,
            )
            .unwrap();
        agent.tick(&mut transport, 5).unwrap();
        let forwarded = transport.lines().pop().unwrap();
        assert_ne!(forwarded.request_id, 91);
        assert_eq!(
            forwarded.known_command(),
            Some(KnownCommand::DeveloperBegin)
        );

        transport.push(&response(Message::ok(
            Destination::Mochios,
            forwarded.request_id,
            Vec::new(),
        )));
        agent.tick(&mut transport, 6).unwrap();
        let restored = agent.take_external_response().unwrap();
        assert_eq!(restored.request_id, 91);
        assert!(matches!(restored.body, Body::Ok));
        assert!(!agent.external_request_pending());
    }

    #[test]
    fn external_request_timeout_releases_the_waiting_client() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        let mut transport = MockTransport::connected();
        negotiate(&mut agent, &mut transport, 1);
        transport.output.clear();

        agent
            .queue_external_request(
                Message::command(
                    Destination::Mboot,
                    MessageType::Request,
                    95,
                    KnownCommand::LinuxWindows,
                    vec![Argument::new("instance", "1")],
                ),
                10,
            )
            .unwrap();
        agent.tick(&mut transport, 10).unwrap();
        assert!(agent.external_request_pending());

        agent
            .tick(&mut transport, 10 + EXTERNAL_REQUEST_TIMEOUT_MS)
            .unwrap();
        let response = agent.take_external_response().unwrap();
        assert_eq!(response.request_id, 95);
        assert!(matches!(response.body, Body::Error(ErrorCode::Timeout)));
        assert!(!agent.external_request_pending());
    }

    #[test]
    fn linux_request_is_forwarded_without_expanding_the_host_command_boundary() {
        let mut agent = Agent::new("26.0.0", "boot-a", 0);
        let mut transport = MockTransport::connected();
        negotiate(&mut agent, &mut transport, 1);
        transport.output.clear();

        agent
            .queue_external_request(
                Message::command(
                    Destination::Mboot,
                    MessageType::Request,
                    92,
                    KnownCommand::LinuxWindows,
                    vec![Argument::new("instance", "7")],
                ),
                4,
            )
            .unwrap();
        agent.tick(&mut transport, 5).unwrap();
        let forwarded = transport.lines().pop().unwrap();
        assert_eq!(forwarded.known_command(), Some(KnownCommand::LinuxWindows));
        assert_eq!(forwarded.argument("instance"), Some("7"));
        transport.push(&response(Message::ok(
            Destination::Mochios,
            forwarded.request_id,
            Vec::new(),
        )));
        agent.tick(&mut transport, 6).unwrap();
        assert!(agent.take_external_response().is_some());

        assert_eq!(
            agent.queue_external_request(
                Message::command(
                    Destination::Mboot,
                    MessageType::Request,
                    93,
                    KnownCommand::HostPoweroff,
                    Vec::new(),
                ),
                7,
            ),
            Err(ExternalRequestError::InvalidRequest)
        );
    }

    #[test]
    fn linux_bundle_staging_commands_cross_only_the_external_boundary() {
        for (command, arguments) in [
            (
                KnownCommand::LinuxPortalReset,
                vec![Argument::new("instance", "7")],
            ),
            (
                KnownCommand::LinuxPortalGrant,
                vec![
                    Argument::new("instance", "7"),
                    Argument::new("grant", "8"),
                    Argument::new("access", "read"),
                    Argument::new("path", "2f6170706c69636174696f6e73"),
                    Argument::new("mode", "493"),
                ],
            ),
            (
                KnownCommand::LinuxPortalMkdir,
                vec![
                    Argument::new("instance", "7"),
                    Argument::new("grant", "8"),
                    Argument::new("path", "2f6170706c69636174696f6e732f4578616d706c65"),
                    Argument::new("mode", "493"),
                ],
            ),
            (
                KnownCommand::LinuxPortalFileBegin,
                vec![
                    Argument::new("instance", "7"),
                    Argument::new("grant", "8"),
                    Argument::new("path", "2f6170706c69636174696f6e732f612e747874"),
                    Argument::new("size", "1"),
                    Argument::new("mode", "420"),
                ],
            ),
            (
                KnownCommand::LinuxPortalFileChunk,
                vec![
                    Argument::new("instance", "7"),
                    Argument::new("offset", "0"),
                    Argument::new("data", "61"),
                ],
            ),
            (
                KnownCommand::LinuxPortalFileCommit,
                vec![Argument::new("instance", "7")],
            ),
            (
                KnownCommand::LinuxPortalFileCancel,
                vec![Argument::new("instance", "7")],
            ),
            (
                KnownCommand::LinuxPortalRelease,
                vec![Argument::new("instance", "7")],
            ),
            (
                KnownCommand::LinuxPortalExportBegin,
                vec![Argument::new("instance", "7"), Argument::new("grant", "8")],
            ),
            (
                KnownCommand::LinuxPortalExportEntry,
                vec![Argument::new("instance", "7"), Argument::new("index", "0")],
            ),
            (
                KnownCommand::LinuxPortalExportChunk,
                vec![
                    Argument::new("instance", "7"),
                    Argument::new("index", "0"),
                    Argument::new("offset", "0"),
                    Argument::new("maximum", "1024"),
                ],
            ),
            (
                KnownCommand::LinuxPortalExportEnd,
                vec![Argument::new("instance", "7")],
            ),
        ] {
            let mut agent = Agent::new("26.0.0", "boot-a", 0);
            let mut transport = MockTransport::connected();
            negotiate(&mut agent, &mut transport, 1);
            transport.output.clear();
            agent
                .queue_external_request(
                    Message::command(
                        Destination::Mboot,
                        MessageType::Request,
                        94,
                        command,
                        arguments,
                    ),
                    4,
                )
                .unwrap();
            agent.tick(&mut transport, 5).unwrap();
            assert_eq!(
                transport.lines().pop().unwrap().known_command(),
                Some(command)
            );
        }
    }
}
