//! Exercise the native ViewKit adapter with the input service's release wire
//! behavior: character presses have text, releases only retain physical codes.
#[path = "../../../libraries/viewkit/src/platform/mochios/pressed_keys.rs"]
mod production;

#[test]
fn decision_character_release_survives_an_empty_release_codepoint() {
    let mut keys = production::PressedKeys::new();
    assert_eq!(keys.transition(49, Some('n'), true), Some('n'));
    // A repeat still belongs to the same press and must not orphan its release.
    assert_eq!(keys.transition(49, Some('N'), true), Some('N'));
    assert_eq!(keys.transition(49, Some('N'), false), Some('n'));
    assert_eq!(keys.transition(49, None, false), None);
}

#[test]
fn concurrent_keys_modifiers_and_focus_changes_do_not_reuse_old_releases() {
    let mut keys = production::PressedKeys::new();
    keys.transition(30, Some('A'), true);
    keys.transition(21, Some('y'), true);
    assert_eq!(keys.transition(30, Some('a'), false), Some('A'));
    assert_eq!(keys.transition(21, None, false), Some('y'));
    keys.transition(49, Some('n'), true);
    keys.clear();
    assert_eq!(keys.transition(49, None, false), None);
    assert_eq!(keys.transition(1, Some('\u{1b}'), false), Some('\u{1b}'));
}
