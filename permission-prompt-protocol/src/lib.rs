#![no_std]

pub const MAX_MESSAGE_LEN: usize = 1024;
const MAGIC: [u8; 8] = *b"MPRMPT01";
const HEADER_LEN: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptRequest<'a> {
    Network {
        token: u64,
        application: &'a str,
    },
    Directory {
        token: u64,
        application: &'a str,
        path: &'a str,
        writable: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Invalid,
    BufferTooSmall,
}

impl<'a> PromptRequest<'a> {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        let (kind, writable, token, application, path) = match self {
            Self::Network { token, application } => (1u8, 0u8, *token, *application, ""),
            Self::Directory {
                token,
                application,
                path,
                writable,
            } => (2u8, u8::from(*writable), *token, *application, *path),
        };
        if token == 0
            || application.is_empty()
            || application.len() > u16::MAX as usize
            || path.len() > u16::MAX as usize
            || path.as_bytes().contains(&0)
            || application.as_bytes().contains(&0)
        {
            return Err(ProtocolError::Invalid);
        }
        let length = HEADER_LEN + application.len() + path.len();
        if length > MAX_MESSAGE_LEN || output.len() < length {
            return Err(ProtocolError::BufferTooSmall);
        }
        output[..8].copy_from_slice(&MAGIC);
        output[8] = kind;
        output[9] = writable;
        output[10..12].copy_from_slice(&(application.len() as u16).to_le_bytes());
        output[12..14].copy_from_slice(&(path.len() as u16).to_le_bytes());
        output[14..16].fill(0);
        output[16..24].copy_from_slice(&token.to_le_bytes());
        let application_end = HEADER_LEN + application.len();
        output[HEADER_LEN..application_end].copy_from_slice(application.as_bytes());
        output[application_end..length].copy_from_slice(path.as_bytes());
        Ok(length)
    }

    pub fn decode(input: &'a [u8]) -> Result<Self, ProtocolError> {
        if input.len() < HEADER_LEN || input[..8] != MAGIC || input[14..16] != [0, 0] {
            return Err(ProtocolError::Invalid);
        }
        let application_len = usize::from(u16::from_le_bytes([input[10], input[11]]));
        let path_len = usize::from(u16::from_le_bytes([input[12], input[13]]));
        let expected = HEADER_LEN + application_len + path_len;
        if input.len() != expected || expected > MAX_MESSAGE_LEN || application_len == 0 {
            return Err(ProtocolError::Invalid);
        }
        let application_end = HEADER_LEN + application_len;
        let token = u64::from_le_bytes(
            input[16..24]
                .try_into()
                .map_err(|_| ProtocolError::Invalid)?,
        );
        if token == 0 {
            return Err(ProtocolError::Invalid);
        }
        let application = core::str::from_utf8(&input[HEADER_LEN..application_end])
            .map_err(|_| ProtocolError::Invalid)?;
        let path =
            core::str::from_utf8(&input[application_end..]).map_err(|_| ProtocolError::Invalid)?;
        match (input[8], input[9]) {
            (1, 0) if path.is_empty() => Ok(Self::Network { token, application }),
            (2, writable @ 0..=1) if !path.is_empty() => Ok(Self::Directory {
                token,
                application,
                path,
                writable: writable == 1,
            }),
            _ => Err(ProtocolError::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_both_prompt_kinds() {
        let requests = [
            PromptRequest::Network {
                token: 42,
                application: "Chromium.app",
            },
            PromptRequest::Directory {
                token: 43,
                application: "Chromium.app",
                path: "/home/user/Downloads",
                writable: true,
            },
        ];
        for request in requests {
            let mut bytes = [0; MAX_MESSAGE_LEN];
            let length = request.encode(&mut bytes).unwrap();
            assert_eq!(PromptRequest::decode(&bytes[..length]), Ok(request));
        }
    }
}
