#[path = "../../../applications/terminal/src/input.rs"]
mod production;
use production::{Special, character, special, text};
#[test]
fn unicode_and_control_keys_are_terminal_bytes_not_binary_events() {
    assert_eq!(text("日本語\r\nnext\r"), "日本語\nnext\n".as_bytes());
    for (key, byte) in [
        ('c', 3),
        ('d', 4),
        ('z', 26),
        ('C', 3),
        (' ', 0),
        ('?', 127),
    ] {
        assert_eq!(character(key, true, false).unwrap(), [byte]);
    }
    assert_eq!(character('あ', false, true).unwrap(), "\x1bあ".as_bytes());
    assert!(character('あ', true, false).is_none());
}
#[test]
fn navigation_and_modifier_sequences_follow_the_terminal_encoding() {
    assert_eq!(special(Special::Up, false, false, false), b"\x1b[A");
    assert_eq!(special(Special::Left, false, false, true), b"\x1b[1;5D");
    assert_eq!(special(Special::PageDown, true, true, false), b"\x1b[6;4~");
    assert_eq!(special(Special::BackTab, true, false, false), b"\x1b[Z");
    for key in [
        Special::Escape,
        Special::Delete,
        Special::Home,
        Special::End,
        Special::Right,
        Special::Down,
        Special::PageUp,
    ] {
        assert!(!special(key, false, false, false).is_empty());
    }
}
