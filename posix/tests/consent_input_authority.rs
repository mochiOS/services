extern crate self as mochi_user_platform;
use std::cell::RefCell;
pub mod capability {
    pub use mochios_capability_protocol::{consent, input_authority};
    pub fn check_thread(sender: u64, name: &str) -> Result<u64, ()> {
        assert_eq!(name, "capabilities.manage");
        Ok(u64::from(sender == 41 || sender == 42))
    }
}
use capability::{
    consent::{Correlation, Ticket},
    input_authority as w,
};
#[path = "../../input/src/physical_input.rs"]
mod physical_input;
#[path = "../../input/src/consent_input.rs"]
mod production;

thread_local! { static SENT: RefCell<Vec<(u64,w::Event)>> = const { RefCell::new(Vec::new()) }; static FAIL: RefCell<bool> = const { RefCell::new(false) }; }
pub mod ipc {
    pub fn send(owner: u64, bytes: &[u8]) -> Result<u64, ()> {
        if super::FAIL.with_borrow(|value| *value) {
            return Err(());
        }
        super::SENT
            .with_borrow_mut(|events| events.push((owner, super::w::decode_event(bytes).unwrap())));
        Ok(bytes.len() as u64)
    }
}
fn correlation(id: u64) -> Correlation {
    Correlation {
        ticket: Ticket {
            id,
            challenge: [7; 32],
        },
        display: id,
    }
}
fn command(authority: &mut production::Authority, sender: u64, command: w::Command) -> w::Reply {
    w::decode_reply(&authority.control(sender, &w::encode_command(command).unwrap())).unwrap()
}
fn arm(authority: &mut production::Authority, generation: u64) -> w::Reply {
    command(
        authority,
        41,
        w::Command::Arm {
            generation,
            correlation: correlation(3),
        },
    )
}
fn events() -> Vec<w::Event> {
    SENT.with_borrow_mut(|sent| {
        sent.drain(..)
            .map(|(owner, event)| {
                assert_eq!(owner, 41);
                event
            })
            .collect()
    })
}

#[test]
fn physical_state_keeps_extended_keys_modifiers_and_pointer_buttons_until_actual_release() {
    let mut seat = physical_input::Seat::default();
    assert!(seat.all_released());
    assert_eq!(
        seat.keyboard(0x15, false).unwrap().transition,
        w::Transition::PhysicalPress
    );
    assert_eq!(
        seat.keyboard(0x15, false).unwrap().transition,
        w::Transition::Repeat
    );
    seat.keyboard(0xe0, false);
    seat.keyboard(0x1d, false);
    assert_eq!(
        seat.keyboard(0x95, false).unwrap().transition,
        w::Transition::Release
    );
    seat.keyboard(0xe0, false);
    assert_eq!(
        seat.keyboard(0x9d, false).unwrap().transition,
        w::Transition::AllReleased
    );
    seat.pointer(1);
    seat.keyboard(0x15, false);
    assert_eq!(
        seat.keyboard(0x95, false).unwrap().transition,
        w::Transition::Release
    );
    assert!(!seat.all_released());
    assert_eq!(
        seat.pointer(0)[0].unwrap().transition,
        w::Transition::AllReleased
    );
    assert!(seat.all_released());
}
#[test]
fn synthetic_releases_and_prefixes_never_change_physical_state_or_become_presence() {
    let mut seat = physical_input::Seat::default();
    seat.keyboard(0x15, false);
    assert_eq!(
        seat.keyboard(0x95, true).unwrap().transition,
        w::Transition::Synthetic
    );
    assert!(!seat.all_released());
    seat.keyboard(0xe0, true);
    let release = seat.keyboard(0x95, false).unwrap();
    assert_eq!(release.control, 0x15);
    assert_eq!(release.transition, w::Transition::AllReleased);
    assert!(seat.all_released());
    assert_eq!(
        seat.keyboard(0x15, true).unwrap().transition,
        w::Transition::Synthetic
    );
    assert!(seat.all_released());
    for byte in [0xe1, 0x1d, 0x45, 0xe1, 0x9d, 0xc5] {
        assert!(seat.keyboard(byte, false).is_none());
    }
    assert!(seat.all_released());
}
#[test]
fn pointer_report_does_not_invent_a_release_between_swapped_buttons() {
    let mut seat = physical_input::Seat::default();
    seat.pointer(1);
    let swapped = seat.pointer(2);
    assert_eq!(swapped[0].unwrap().transition, w::Transition::Release);
    assert_eq!(swapped[1].unwrap().transition, w::Transition::PhysicalPress);
    assert!(!seat.all_released());
    assert!(seat.pointer(2).iter().all(Option::is_none));
    assert_eq!(
        seat.pointer(0)[1].unwrap().transition,
        w::Transition::AllReleased
    );
}
#[test]
fn only_the_native_authorized_owner_can_register_arm_observe_or_cancel() {
    let mut authority = production::Authority::default();
    assert_eq!(command(&mut authority, 99, w::Command::Register).status, 13);
    let registration = command(&mut authority, 41, w::Command::Register);
    assert_eq!(registration.status, 0);
    assert!(registration.all_released);
    assert_eq!(command(&mut authority, 42, w::Command::Register).status, 13);
    let generation = registration.generation;
    assert_eq!(arm(&mut authority, generation + 1).status, 13);
    assert_eq!(arm(&mut authority, generation).status, 0);
    assert_eq!(arm(&mut authority, generation).status, 16);
    assert_eq!(command(&mut authority, 41, w::Command::Register).status, 16);
    assert_eq!(
        command(
            &mut authority,
            42,
            w::Command::Cancel {
                generation,
                correlation: correlation(3)
            }
        )
        .status,
        13
    );
    assert_eq!(
        command(
            &mut authority,
            41,
            w::Command::Cancel {
                generation,
                correlation: correlation(4)
            }
        )
        .status,
        2
    );
    authority.keyboard(0x15, false);
    let observed = events();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].generation, generation);
    assert_eq!(observed[0].correlation, correlation(3));
    assert_eq!(
        command(
            &mut authority,
            41,
            w::Command::Cancel {
                generation,
                correlation: correlation(3)
            }
        )
        .status,
        0
    );
    authority.keyboard(0x95, false);
    assert!(events().is_empty());
    let next = command(&mut authority, 41, w::Command::Register);
    assert!(next.generation > generation);
    assert_eq!(arm(&mut authority, generation).status, 13);
}
#[test]
fn snapshot_follows_display_arm_and_held_keys_need_real_release_then_new_press() {
    let mut authority = production::Authority::default();
    authority.keyboard(0x15, false);
    let generation = command(&mut authority, 41, w::Command::Register).generation;
    let snapshot = arm(&mut authority, generation);
    assert!(!snapshot.all_released);
    authority.keyboard(0x15, false); // typematic
    authority.keyboard(0x95, true); // injected release
    authority.keyboard(0x15, true); // injected y
    authority.keyboard(0x95, false);
    authority.keyboard(0x15, false);
    let observed = events();
    assert_eq!(
        observed
            .iter()
            .map(|e| e.observation.transition)
            .collect::<Vec<_>>(),
        [
            w::Transition::Repeat,
            w::Transition::Synthetic,
            w::Transition::Synthetic,
            w::Transition::AllReleased,
            w::Transition::PhysicalPress
        ]
    );
    assert_eq!(observed[0].observation.serial, snapshot.serial + 1);
    assert!(
        observed
            .windows(2)
            .all(|p| p[0].observation.serial < p[1].observation.serial)
    );
}
#[test]
fn lost_delivery_and_failed_owner_reply_revoke_stream_without_replaying_later_input() {
    let mut authority = production::Authority::default();
    let generation = command(&mut authority, 41, w::Command::Register).generation;
    arm(&mut authority, generation);
    FAIL.with_borrow_mut(|value| *value = true);
    authority.keyboard(0x15, false);
    FAIL.with_borrow_mut(|value| *value = false);
    authority.keyboard(0x95, false);
    assert!(events().is_empty());
    assert_eq!(
        command(
            &mut authority,
            41,
            w::Command::Status {
                generation,
                correlation: correlation(3)
            }
        )
        .status,
        2
    );
    arm(&mut authority, generation);
    authority.reply_failed(99);
    authority.keyboard(0x15, false);
    assert_eq!(events().len(), 1);
    authority.reply_failed(41);
    authority.keyboard(0x95, false);
    assert!(events().is_empty());
}
