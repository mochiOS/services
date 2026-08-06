use mboot_protocol::MAX_MESSAGE_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamDecodeError {
    TooLong,
}

#[derive(Debug, Default)]
pub struct LineDecoder {
    buffer: Vec<u8>,
    discarding: bool,
}

impl LineDecoder {
    pub const fn new() -> Self {
        Self {
            buffer: Vec::new(),
            discarding: false,
        }
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.discarding = false;
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<Result<Vec<u8>, StreamDecodeError>> {
        let mut lines = Vec::new();
        for &byte in bytes {
            if self.discarding {
                if byte == b'\n' {
                    self.discarding = false;
                }
                continue;
            }
            if self.buffer.len() == MAX_MESSAGE_LEN {
                self.buffer.clear();
                self.discarding = byte != b'\n';
                lines.push(Err(StreamDecodeError::TooLong));
                continue;
            }
            self.buffer.push(byte);
            if byte == b'\n' {
                lines.push(Ok(core::mem::take(&mut self.buffer)));
            }
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_split_lines_and_returns_multiple_lines() {
        let mut decoder = LineDecoder::new();
        assert!(decoder.push(b"first").is_empty());
        assert_eq!(
            decoder.push(b" line\nsecond\n"),
            vec![Ok(b"first line\n".to_vec()), Ok(b"second\n".to_vec())]
        );
    }

    #[test]
    fn oversized_line_is_discarded_without_poisoning_the_next_line() {
        let mut decoder = LineDecoder::new();
        let mut oversized = vec![b'a'; MAX_MESSAGE_LEN + 20];
        oversized.extend_from_slice(b"\ngood\n");
        assert_eq!(
            decoder.push(&oversized),
            vec![Err(StreamDecodeError::TooLong), Ok(b"good\n".to_vec())]
        );
    }

    #[test]
    fn reset_drops_partial_input() {
        let mut decoder = LineDecoder::new();
        assert!(decoder.push(b"stale").is_empty());
        decoder.reset();
        assert_eq!(decoder.push(b"fresh\n"), vec![Ok(b"fresh\n".to_vec())]);
    }
}
