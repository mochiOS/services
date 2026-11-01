use mochi_user_platform as platform;
pub(crate) fn keycode_for_scancode(scancode: u8, extended: bool) -> Option<u16> {
    use platform::input::*;
    Some(match (scancode, extended) {
        (0x01, false) => KEY_ESC,
        (0x0e, false) => KEY_BACKSPACE,
        (0x0f, false) => KEY_TAB,
        (0x1c, false) => KEY_ENTER,
        (0x1d, false) => KEY_LEFT_CTRL,
        (0x1d, true) => KEY_RIGHT_CTRL,
        (0x2a, false) => KEY_LEFT_SHIFT,
        (0x36, false) => KEY_RIGHT_SHIFT,
        (0x38, false) => KEY_LEFT_ALT,
        (0x38, true) => KEY_RIGHT_ALT,
        (0x3a, false) => KEY_CAPS_LOCK,
        (0x39, false) => KEY_SPACE,
        (0x10, false) => KEY_Q,
        (0x11, false) => KEY_W,
        (0x12, false) => KEY_E,
        (0x13, false) => KEY_R,
        (0x14, false) => KEY_T,
        (0x15, false) => KEY_Y,
        (0x16, false) => KEY_U,
        (0x17, false) => KEY_I,
        (0x18, false) => KEY_O,
        (0x19, false) => KEY_P,
        (0x1e, false) => KEY_A,
        (0x1f, false) => KEY_S,
        (0x20, false) => KEY_D,
        (0x21, false) => KEY_F,
        (0x22, false) => KEY_G,
        (0x23, false) => KEY_H,
        (0x24, false) => KEY_J,
        (0x25, false) => KEY_K,
        (0x26, false) => KEY_L,
        (0x2c, false) => KEY_Z,
        (0x2d, false) => KEY_X,
        (0x2e, false) => KEY_C,
        (0x2f, false) => KEY_V,
        (0x30, false) => KEY_B,
        (0x31, false) => KEY_N,
        (0x32, false) => KEY_M,
        (0x02, false) => KEY_1,
        (0x03, false) => KEY_2,
        (0x04, false) => KEY_3,
        (0x05, false) => KEY_4,
        (0x06, false) => KEY_5,
        (0x07, false) => KEY_6,
        (0x08, false) => KEY_7,
        (0x09, false) => KEY_8,
        (0x0a, false) => KEY_9,
        (0x0b, false) => KEY_0,
        (0x0c, false) => KEY_MINUS,
        (0x0d, false) => KEY_EQUAL,
        (0x1a, false) => KEY_LEFT_BRACKET,
        (0x1b, false) => KEY_RIGHT_BRACKET,
        (0x27, false) => KEY_SEMICOLON,
        (0x28, false) => KEY_APOSTROPHE,
        (0x29, false) => KEY_GRAVE,
        (0x2b, false) => KEY_BACKSLASH,
        (0x33, false) => KEY_COMMA,
        (0x34, false) => KEY_DOT,
        (0x35, false) => KEY_SLASH,
        (0x47, true) => KEY_HOME,
        (0x48, true) => KEY_UP,
        (0x49, true) => KEY_PAGE_UP,
        (0x4b, true) => KEY_LEFT,
        (0x4d, true) => KEY_RIGHT,
        (0x4f, true) => KEY_END,
        (0x50, true) => KEY_DOWN,
        (0x51, true) => KEY_PAGE_DOWN,
        (0x53, true) => KEY_DELETE,
        (0x3b, false) => KEY_F1,
        (0x3c, false) => KEY_F2,
        (0x3d, false) => KEY_F3,
        (0x3e, false) => KEY_F4,
        (0x3f, false) => KEY_F5,
        (0x40, false) => KEY_F6,
        (0x41, false) => KEY_F7,
        (0x42, false) => KEY_F8,
        (0x43, false) => KEY_F9,
        (0x44, false) => KEY_F10,
        (0x57, false) => KEY_F11,
        (0x58, false) => KEY_F12,
        (0x52, true) => KEY_INSERT,
        _ => return None,
    })
}

#[cfg(test)]
mod terminal_key_tests {
    use super::*;
    #[test]
    fn function_keys_and_insert_have_stable_input_codes() {
        for (n, scan) in [
            0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x57, 0x58,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(keycode_for_scancode(scan, false), Some(88 + n as u16));
        }
        assert_eq!(
            keycode_for_scancode(0x52, true),
            Some(platform::input::KEY_INSERT)
        );
        assert_eq!(
            keycode_for_scancode(0x53, true),
            Some(platform::input::KEY_DELETE)
        );
    }
}
