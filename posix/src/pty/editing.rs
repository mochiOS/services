//! Implementation-defined canonical editing, with bounded deferred echo.
use super::{BUFFER_CAPACITY, PseudoTerminal, posix_protocol as wire};

impl PseudoTerminal {
    // At most one operation is deferred: word erase generates <= 3 bytes per
    // input byte; reprint generates <= 2 per byte plus its control/newline.
    // Store encoded bytes so later termios changes cannot reinterpret them.
    fn queue_edit_echo(&mut self, bytes: impl IntoIterator<Item = u8>) {
        debug_assert!(self.edit_echo.is_empty());
        for byte in bytes {
            if self.output_bytes_for(byte) == 2 {
                self.edit_echo.push_back(b'\r');
            }
            self.edit_echo.push_back(byte);
        }
        debug_assert!(self.edit_echo.len() <= BUFFER_CAPACITY * 3 + 4);
        self.refill_edit_echo();
    }

    pub(super) fn refill_edit_echo(&mut self) {
        let count = self
            .edit_echo
            .len()
            .min(BUFFER_CAPACITY - self.output.len());
        self.output.extend(self.edit_echo.drain(..count));
    }

    /// The caller has already handled literal-next, signals and flow control,
    /// and invokes this only in canonical mode. Err means retry this byte;
    /// no input mutation or echo publication has occurred on that path.
    pub(super) fn extended_edit(&mut self, byte: u8) -> Result<bool, ()> {
        if self.attributes.local_flags & wire::TERMINAL_LFLAG_IEXTEN == 0 {
            return Ok(false);
        }
        let word = self.attributes.control_characters[wire::TERMINAL_CC_VWERASE];
        let reprint = self.attributes.control_characters[wire::TERMINAL_CC_VREPRINT];
        let erase = word != 0 && byte == word;
        if !erase && !(reprint != 0 && byte == reprint) {
            return Ok(false);
        }
        if !self.edit_echo.is_empty() {
            return Err(());
        }
        let echo = self.attributes.local_flags & wire::TERMINAL_LFLAG_ECHO != 0;
        if erase {
            let mut end = self.canonical_input.len();
            let mut characters = 0;
            // Words are runs separated by ASCII whitespace, independent of
            // the application's locale. Never cross a committed record.
            while end != 0 && self.canonical_input[end - 1].is_ascii_whitespace() {
                end -= 1;
                characters += 1;
            }
            while end != 0 && !self.canonical_input[end - 1].is_ascii_whitespace() {
                end -= self.canonical_erase_length(end);
                characters += 1;
            }
            if characters != 0 && echo {
                if self.attributes.local_flags & wire::TERMINAL_LFLAG_ECHOE != 0 {
                    self.queue_edit_echo((0..characters).flat_map(|_| *b"\x08 \x08"));
                } else {
                    self.queue_edit_echo([byte]);
                }
            }
            self.canonical_input.truncate(end);
        } else if echo {
            // One bounded snapshot avoids aliasing the input queue while
            // publishing output. A reprint never creates an input record.
            let bytes = [byte, b'\n']
                .into_iter()
                .chain(self.canonical_input.iter().copied())
                .collect::<Vec<_>>();
            self.queue_edit_echo(bytes);
        }
        Ok(true)
    }
}
