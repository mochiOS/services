#[path = "../../../applications/terminal/src/pending_input.rs"]
mod production;
use std::io::{self, Write};
struct Writer {
    bytes: Vec<u8>,
    block: bool,
    zero: bool,
}
impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.block {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.zero {
            return Ok(0);
        }
        let count = bytes.len().min(7);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn partial_writes_and_backpressure_preserve_utf8_and_order_without_spinning() {
    let mut queue = production::PendingInput::default();
    let text = "日本語0123456789".repeat(20);
    queue.enqueue(text.as_bytes()).unwrap();
    let mut writer = Writer {
        bytes: Vec::new(),
        block: true,
        zero: false,
    };
    queue.flush(&mut writer).unwrap();
    assert!(writer.bytes.is_empty());
    writer.block = false;
    queue.flush(&mut writer).unwrap();
    assert_eq!(writer.bytes.len(), 28);
    queue.enqueue(b"suffix").unwrap();
    for _ in 0..100 {
        queue.flush(&mut writer).unwrap();
    }
    assert_eq!(writer.bytes, [text.as_bytes(), b"suffix"].concat());
}
#[test]
fn queue_overflow_is_atomic_and_zero_write_does_not_discard_pending_input() {
    let mut queue = production::PendingInput::default();
    let fill = vec![b'a'; 65534];
    queue.enqueue(&fill).unwrap();
    assert_eq!(
        queue.enqueue("あ".as_bytes()).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let mut output = Vec::new();
    for _ in 0..8 {
        queue.flush(&mut output).unwrap();
    }
    assert_eq!(output, fill);
    queue.enqueue(b"keep").unwrap();
    let mut writer = Writer {
        bytes: Vec::new(),
        block: false,
        zero: true,
    };
    assert_eq!(
        queue.flush(&mut writer).unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    writer.zero = false;
    queue.flush(&mut writer).unwrap();
    assert_eq!(writer.bytes, b"keep");
}
