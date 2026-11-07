use mochios_ime_engine::Engine;
use std::sync::{Arc, OnceLock};

pub const DICTIONARY_PATH: &str = "/system/libraries/ime/ja.mime";
pub const CONVERT_OPCODE: u32 = u32::from_le_bytes(*b"IMEC");
pub const STATUS_OPCODE: u32 = u32::from_le_bytes(*b"IMES");
pub const TOGGLE_OPCODE: u32 = u32::from_le_bytes(*b"IMET");
pub const REQUEST_HEADER_LEN: usize = 12;
pub const RESPONSE_HEADER_LEN: usize = 8;
pub const MAX_REQUEST_LEN: usize = 4096;
pub const MAX_READING_LEN: usize = MAX_REQUEST_LEN - REQUEST_HEADER_LEN;
pub const MAX_CANDIDATES: usize = 20;

const STATUS_OK: i32 = 0;
const STATUS_UNAVAILABLE: i32 = -1;
const STATUS_INVALID_REQUEST: i32 = -2;

pub struct InputMethod {
    engine: Arc<OnceLock<Option<Engine>>>,
    enabled: bool,
    warmup: Option<std::sync::mpsc::Sender<()>>,
}

impl InputMethod {
    pub fn open_system_dictionary() -> Self {
        Self::open_dictionary(DICTIONARY_PATH)
    }

    /// Dictionary preparation must not prevent basic input from becoming ready.
    pub fn start_system_dictionary() -> std::io::Result<Self> {
        Self::load_when_requested(|| {
            eprintln!("input.service: loading IME dictionary");
            let engine = Engine::open(DICTIONARY_PATH).ok();
            if engine.is_some() {
                mochi_user_platform::logln!("input.service: Japanese IME dictionary loaded");
            } else {
                mochi_user_platform::logln!(
                    "input.service: Japanese IME unavailable path={}",
                    DICTIONARY_PATH
                );
            }
            eprintln!(
                "input.service: IME initialization finished available={}",
                engine.is_some()
            );
            engine
        })
    }

    fn load_when_requested(
        load: impl FnOnce() -> Option<Engine> + Send + 'static,
    ) -> std::io::Result<Self> {
        let (warmup, requested) = std::sync::mpsc::channel();
        let mut input = Self::load_in_background(move || {
            requested.recv().ok()?;
            load()
        })?;
        input.warmup = Some(warmup);
        Ok(input)
    }

    fn load_in_background(
        load: impl FnOnce() -> Option<Engine> + Send + 'static,
    ) -> std::io::Result<Self> {
        let engine = Arc::new(OnceLock::new());
        let loaded = Arc::clone(&engine);
        std::thread::Builder::new()
            .name("ime-dictionary".into())
            .spawn(move || {
                // This worker is the only publisher. Readers use get(), which
                // never waits and only exposes a completely initialized engine.
                let _ = loaded.set(load());
            })?;
        Ok(Self {
            engine,
            enabled: false,
            warmup: None,
        })
    }

    pub fn unavailable() -> Self {
        Self {
            engine: Arc::new(OnceLock::from(None)),
            enabled: false,
            warmup: None,
        }
    }

    /// Opens the same conversion engine against an explicitly supplied dictionary.
    pub fn open_dictionary(path: impl AsRef<std::path::Path>) -> Self {
        Self {
            engine: Arc::new(OnceLock::from(Engine::open(path).ok())),
            enabled: false,
            warmup: None,
        }
    }

    pub fn is_available(&self) -> bool {
        self.engine.get().and_then(Option::as_ref).is_some()
    }

    pub fn handle(&self, request: &[u8]) -> Vec<u8> {
        let Some((reading, limit)) = decode_request(request) else {
            return status_response(STATUS_INVALID_REQUEST);
        };
        let Some(engine) = self.engine.get().and_then(Option::as_ref) else {
            return status_response(STATUS_UNAVAILABLE);
        };
        encode_candidates(
            engine
                .candidates(reading, limit)
                .into_iter()
                .map(|candidate| candidate.text),
        )
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn toggle(&mut self) -> bool {
        self.enabled = !self.enabled;
        if self.enabled {
            self.warmup();
        }
        self.enabled
    }

    pub fn warmup(&mut self) {
        if let Some(warmup) = self.warmup.take()
            && warmup.send(()).is_err()
        {
            mochi_user_platform::logln!("input.service: IME worker stopped before warmup");
        }
    }

    pub fn state_response(&self) -> Vec<u8> {
        vec![self.enabled as u8]
    }
}

pub fn is_convert_request(request: &[u8]) -> bool {
    request
        .get(..4)
        .is_some_and(|bytes| bytes == CONVERT_OPCODE.to_le_bytes())
}

pub fn is_status_request(request: &[u8]) -> bool {
    request == STATUS_OPCODE.to_le_bytes()
}

pub fn is_toggle_request(request: &[u8]) -> bool {
    request == TOGGLE_OPCODE.to_le_bytes()
}

fn decode_request(request: &[u8]) -> Option<(&str, usize)> {
    if request.len() < REQUEST_HEADER_LEN || request.len() > MAX_REQUEST_LEN {
        return None;
    }
    if u32::from_le_bytes(request[0..4].try_into().ok()?) != CONVERT_OPCODE {
        return None;
    }
    let reading_len = u16::from_le_bytes(request[4..6].try_into().ok()?) as usize;
    let limit = u16::from_le_bytes(request[6..8].try_into().ok()?) as usize;
    if request[8..12] != [0; 4]
        || reading_len == 0
        || reading_len > MAX_READING_LEN
        || limit == 0
        || limit > MAX_CANDIDATES
        || request.len() != REQUEST_HEADER_LEN + reading_len
    {
        return None;
    }
    std::str::from_utf8(&request[REQUEST_HEADER_LEN..])
        .ok()
        .map(|reading| (reading, limit))
}

fn encode_candidates(candidates: impl IntoIterator<Item = String>) -> Vec<u8> {
    let mut response = vec![0; RESPONSE_HEADER_LEN];
    response[..4].copy_from_slice(&STATUS_OK.to_le_bytes());
    let mut count = 0u16;
    for candidate in candidates {
        let bytes = candidate.as_bytes();
        let Ok(length) = u16::try_from(bytes.len()) else {
            continue;
        };
        if response.len() + 2 + bytes.len() > MAX_REQUEST_LEN {
            break;
        }
        response.extend_from_slice(&length.to_le_bytes());
        response.extend_from_slice(bytes);
        count = count.saturating_add(1);
    }
    response[4..6].copy_from_slice(&count.to_le_bytes());
    response
}

fn status_response(status: i32) -> Vec<u8> {
    let mut response = vec![0; RESPONSE_HEADER_LEN];
    response[..4].copy_from_slice(&status.to_le_bytes());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(reading: &str, limit: u16) -> Vec<u8> {
        let mut request = Vec::with_capacity(REQUEST_HEADER_LEN + reading.len());
        request.extend_from_slice(&CONVERT_OPCODE.to_le_bytes());
        request.extend_from_slice(&(reading.len() as u16).to_le_bytes());
        request.extend_from_slice(&limit.to_le_bytes());
        request.extend_from_slice(&[0; 4]);
        request.extend_from_slice(reading.as_bytes());
        request
    }

    #[test]
    fn request_requires_bounded_utf8_reading_and_limit() {
        assert_eq!(decode_request(&request("きょう", 10)), Some(("きょう", 10)));
        assert!(decode_request(&request("", 10)).is_none());
        assert!(decode_request(&request("きょう", 0)).is_none());
        assert!(decode_request(&request("きょう", (MAX_CANDIDATES + 1) as u16)).is_none());
        let mut invalid_utf8 = request("a", 1);
        *invalid_utf8.last_mut().unwrap() = 0xff;
        assert!(decode_request(&invalid_utf8).is_none());
    }

    #[test]
    fn candidate_response_is_bounded_and_length_prefixed() {
        let response = encode_candidates([String::from("今日"), String::from("京")]);
        assert_eq!(&response[..4], &STATUS_OK.to_le_bytes());
        assert_eq!(u16::from_le_bytes(response[4..6].try_into().unwrap()), 2);
        let first_len = u16::from_le_bytes(response[8..10].try_into().unwrap()) as usize;
        assert_eq!(&response[10..10 + first_len], "今日".as_bytes());
    }

    #[test]
    fn input_mode_toggle_is_reported_to_clients() {
        let mut input_method = InputMethod::unavailable();
        assert!(!input_method.enabled());
        assert_eq!(input_method.state_response(), vec![0]);
        assert!(input_method.toggle());
        assert!(input_method.enabled());
        assert_eq!(input_method.state_response(), vec![1]);
    }

    #[test]
    fn deferred_warmup_waits_for_the_desktop_or_input_request_without_changing_mode() {
        use std::sync::mpsc;
        let (started, ready) = mpsc::channel();
        let mut input = InputMethod::load_when_requested(move || {
            started.send(()).unwrap();
            None
        })
        .unwrap();
        assert_eq!(ready.try_recv(), Err(mpsc::TryRecvError::Empty));
        assert!(!input.enabled());
        input.warmup();
        ready
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        input.warmup();
        assert!(!input.enabled());
        assert!(input.warmup.is_none());
    }

    #[test]
    fn pending_dictionary_does_not_block_input_or_conversion_requests() {
        use std::sync::mpsc;
        let (started, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let mut input_method = InputMethod::load_in_background(move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
            None
        })
        .unwrap();
        ready
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(!input_method.is_available());
        assert!(input_method.toggle());
        assert_eq!(input_method.state_response(), vec![1]);
        assert_eq!(
            input_method.handle(&request("きょう", 10)),
            status_response(STATUS_UNAVAILABLE)
        );
        release.send(()).unwrap();
    }
}
