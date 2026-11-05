#[path = "../../capability/src/text_evidence.rs"]
mod production;
use mochi_user_platform::capability::{
    consent::Choice,
    input_authority::{Observation, Transition as T},
};
fn event(serial: u64, control: u16, transition: T) -> Observation {
    Observation {
        serial,
        control,
        transition,
    }
}

#[test]
fn only_a_released_physical_shortcut_followed_by_a_new_enter_confirms_that_choice() {
    for (key, choice) in [(0x15, Choice::AllowOnce), (0x1e, Choice::AllowPersistently)] {
        let mut e = production::Evidence::default();
        e.arm(true);
        e.observe(event(1, key, T::PhysicalPress));
        assert!(!e.accepts(choice));
        e.observe(event(2, key, T::AllReleased));
        e.observe(event(3, 0x1c, T::PhysicalPress));
        assert!(e.accepts(choice));
        let other = if key == 0x15 {
            Choice::AllowPersistently
        } else {
            Choice::AllowOnce
        };
        assert!(!e.accepts(other));
        e.arm(true);
        assert!(!e.accepts(choice));
    }
}
#[test]
fn held_keys_repeat_synthetic_input_modifiers_and_bare_enter_never_approve() {
    for (released, events) in [
        (true, vec![(0x1c, T::PhysicalPress)]),
        (
            false,
            vec![
                (0x15, T::PhysicalPress),
                (0x15, T::AllReleased),
                (0x1c, T::PhysicalPress),
            ],
        ),
        (
            true,
            vec![
                (0x15, T::Synthetic),
                (0x15, T::AllReleased),
                (0x1c, T::PhysicalPress),
            ],
        ),
        (
            true,
            vec![
                (0x15, T::PhysicalPress),
                (0x15, T::Repeat),
                (0x15, T::AllReleased),
                (0x1c, T::PhysicalPress),
            ],
        ),
        (
            true,
            vec![(0x15, T::PhysicalPress), (0x1c, T::PhysicalPress)],
        ),
        (
            true,
            vec![
                (0x1d, T::PhysicalPress),
                (0x15, T::PhysicalPress),
                (0x15, T::AllReleased),
                (0x1c, T::PhysicalPress),
            ],
        ),
        (
            true,
            vec![
                (0x15, T::PhysicalPress),
                (0x15, T::AllReleased),
                (256, T::PhysicalPress),
                (256, T::AllReleased),
                (0x1c, T::PhysicalPress),
            ],
        ),
    ] {
        let mut e = production::Evidence::default();
        e.arm(released);
        for (i, (control, transition)) in events.into_iter().enumerate() {
            e.observe(event(i as u64 + 1, control, transition));
        }
        assert!(!e.accepts(Choice::AllowOnce));
        assert!(!e.accepts(Choice::AllowPersistently));
    }
}
#[test]
fn an_intervening_key_invalidates_a_confirmed_proposal() {
    let mut e = production::Evidence::default();
    e.arm(true);
    for observation in [
        event(1, 0x15, T::PhysicalPress),
        event(2, 0x15, T::AllReleased),
        event(3, 0x1c, T::PhysicalPress),
    ] {
        e.observe(observation);
    }
    assert!(e.accepts(Choice::AllowOnce));
    e.observe(event(4, 0x1c, T::AllReleased));
    e.observe(event(5, 0x2d, T::PhysicalPress));
    assert!(!e.accepts(Choice::AllowOnce));
}
