pub(crate) const fn x11_keycode(key: u16) -> Option<u8> {
    Some(match key {
        1 => 9,
        2 => 22,
        3 => 23,
        4 => 36,
        5 => 65,
        6 => 50,
        7 => 62,
        8 => 37,
        9 => 105,
        10 => 64,
        11 => 108,
        12 => 66,
        32 => 38,
        33 => 56,
        34 => 54,
        35 => 40,
        36 => 26,
        37 => 41,
        38 => 42,
        39 => 43,
        40 => 31,
        41 => 44,
        42 => 45,
        43 => 46,
        44 => 58,
        45 => 57,
        46 => 32,
        47 => 33,
        48 => 24,
        49 => 27,
        50 => 39,
        51 => 28,
        52 => 30,
        53 => 55,
        54 => 25,
        55 => 53,
        56 => 29,
        57 => 52,
        58 => 19,
        59 => 10,
        60 => 11,
        61 => 12,
        62 => 13,
        63 => 14,
        64 => 15,
        65 => 16,
        66 => 17,
        67 => 18,
        68 => 20,
        69 => 21,
        70 => 34,
        71 => 35,
        72 => 47,
        73 => 48,
        74 => 49,
        75 => 51,
        76 => 59,
        77 => 60,
        78 => 61,
        79 => 119,
        80 => 110,
        81 => 115,
        82 => 113,
        83 => 114,
        84 => 111,
        85 => 116,
        86 => 112,
        87 => 117,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::x11_keycode;

    #[test]
    fn maps_letters_digits_modifiers_and_navigation_to_xorg_keycodes() {
        assert_eq!(x11_keycode(32), Some(38));
        assert_eq!(x11_keycode(57), Some(52));
        assert_eq!(x11_keycode(59), Some(10));
        assert_eq!(x11_keycode(58), Some(19));
        assert_eq!(x11_keycode(6), Some(50));
        assert_eq!(x11_keycode(9), Some(105));
        assert_eq!(x11_keycode(82), Some(113));
        assert_eq!(x11_keycode(87), Some(117));
    }

    #[test]
    fn rejects_unknown_keycodes() {
        assert_eq!(x11_keycode(0), None);
        assert_eq!(x11_keycode(u16::MAX), None);
    }
}
