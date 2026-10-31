extern crate alloc;
#[path = "../../compositor/src/presentation.rs"]
mod production;
use mochi_user_platform::capability::{
    consent::{Correlation, Ticket},
    presentation as w,
};
use production::*;
use std::{cell::Cell, rc::Rc};
fn context() -> w::Context {
    w::Context {
        session: 3,
        generation: 5,
        active: true,
    }
}
fn correlation(id: u64) -> Correlation {
    Correlation {
        ticket: Ticket {
            id,
            challenge: [9; 32],
        },
        display: id,
    }
}
fn image() -> w::Image {
    w::Image {
        process: 29,
        revision: 0,
        digest: [31; 32],
    }
}
fn observed() -> Observation {
    Observation {
        image: image(),
        surface: SurfaceKey {
            token: 19,
            client: 23,
            sender: 27,
        },
        content: 0,
        focus: 17,
        focused: true,
        visible: true,
        unobscured: true,
        ready: false,
    }
}
fn fixture() -> (Registry<()>, w::Receipt) {
    let mut r = Registry::default();
    r.update_context(context()).unwrap();
    let receipt = r
        .register(
            41,
            context(),
            correlation(7),
            w::Kind::SecureOverlay,
            (),
            image(),
        )
        .unwrap();
    (r, receipt)
}
#[test]
fn only_a_new_successfully_presented_full_frame_mints_evidence() {
    let (mut r, receipt) = fixture();
    let mut o = observed();
    r.bind(correlation(7), o).unwrap();
    assert!(!r.observe(|_, _| Some(o)));
    r.full_presented(|_, _| Some(o));
    assert_eq!(
        r.status(41, correlation(7), receipt.registration)
            .unwrap()
            .stage,
        w::Stage::Pending
    );
    o.content = 1;
    o.ready = true;
    assert!(r.observe(|_, _| Some(o)));
    // Queuing/committing, a failed present or a partial present does not call
    // full_presented. The registration remains pending through each poll.
    assert_eq!(
        r.status(41, correlation(7), receipt.registration)
            .unwrap()
            .stage,
        w::Stage::Pending
    );
    r.full_presented(|_, _| Some(o));
    let shown = r.status(41, correlation(7), receipt.registration).unwrap();
    assert_eq!(shown.stage, w::Stage::Presented);
    assert_eq!(shown.content_generation, 1);
    assert_eq!(shown.focus_generation, 17);
    o.content = 2;
    r.observe(|_, _| Some(o));
    assert_eq!(
        r.status(41, correlation(7), receipt.registration)
            .unwrap()
            .stage,
        w::Stage::Presented
    );
}
#[test]
fn native_owner_image_surface_focus_visibility_and_occlusion_changes_irreversibly_revoke() {
    for case in 0..12 {
        let (mut r, receipt) = fixture();
        let mut o = observed();
        r.bind(correlation(7), o).unwrap();
        o.content = 1;
        o.ready = true;
        r.full_presented(|_, _| Some(o));
        let good = o;
        match case {
            0 => o.image.process += 1,
            1 => o.image.revision += 1,
            2 => o.image.digest[0] ^= 1,
            3 => o.surface.token += 1,
            4 => o.surface.client += 1,
            5 => o.surface.sender += 1,
            6 => o.focus += 1,
            7 => o.focus = 0,
            8 => o.focused = false,
            9 => o.visible = false,
            10 => o.unobscured = false,
            _ => {
                r.observe(|_, _| None);
            }
        }
        r.observe(|_, _| Some(o));
        r.observe(|_, _| Some(good));
        r.full_presented(|_, _| Some(good));
        assert_eq!(
            r.status(41, correlation(7), receipt.registration)
                .unwrap()
                .stage,
            w::Stage::Revoked,
            "{case}"
        );
    }
}
#[test]
fn old_pixels_cannot_acknowledge_a_new_question_or_rebind_an_existing_registration() {
    let (mut r, receipt) = fixture();
    let mut o = observed();
    o.content = 4;
    o.ready = true;
    r.bind(correlation(7), o).unwrap();
    r.full_presented(|_, _| Some(o));
    assert_eq!(
        r.status(41, correlation(7), receipt.registration)
            .unwrap()
            .stage,
        w::Stage::Pending
    );
    assert_eq!(r.bind(correlation(7), o), Err(16));
    o.content = 3;
    r.observe(|_, _| Some(o));
    o.content = 5;
    r.full_presented(|_, _| Some(o));
    assert_eq!(
        r.status(41, correlation(7), receipt.registration)
            .unwrap()
            .stage,
        w::Stage::Revoked
    );
}
#[test]
fn context_changes_free_owned_references_and_never_reactivate_old_receipts() {
    struct Owner(Rc<Cell<usize>>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut r = Registry::default();
    r.update_context(context()).unwrap();
    let receipt = r
        .register(
            41,
            context(),
            correlation(7),
            w::Kind::Window,
            Owner(Rc::clone(&drops)),
            image(),
        )
        .unwrap();
    assert!(
        r.update_context(w::Context {
            generation: 4,
            ..context()
        })
        .is_err()
    );
    assert_eq!(drops.get(), 0);
    // Same-generation inactive publication remains available to revoke at
    // counter exhaustion; it can never reactivate that generation.
    r.update_context(w::Context {
        active: false,
        ..context()
    })
    .unwrap();
    assert_eq!(drops.get(), 1);
    assert!(r.status(41, correlation(7), receipt.registration).is_err());
    assert!(r.update_context(context()).is_err());
    r.update_context(w::Context {
        generation: 6,
        ..context()
    })
    .unwrap();
    assert!(
        r.register(
            41,
            context(),
            correlation(7),
            w::Kind::Window,
            Owner(Rc::clone(&drops)),
            image()
        )
        .is_err()
    );
    assert_eq!(drops.get(), 2);
}
#[test]
fn registrations_are_bounded_owner_scoped_and_non_reusable_after_cancellation() {
    let (mut r, receipt) = fixture();
    assert_eq!(r.status(42, correlation(7), receipt.registration), Err(13));
    assert_eq!(r.cancel(42, correlation(7), receipt.registration), Err(13));
    assert!(r.status(41, correlation(8), receipt.registration).is_err());
    assert!(
        r.register(41, context(), correlation(7), w::Kind::Window, (), image())
            .is_err()
    );
    for id in 8..8 + (MAX_REGISTRATIONS as u64) - 1 {
        r.register(41, context(), correlation(id), w::Kind::Window, (), image())
            .unwrap();
    }
    assert_eq!(
        r.register(
            41,
            context(),
            correlation(100),
            w::Kind::Window,
            (),
            image()
        ),
        Err(28)
    );
    r.cancel(41, correlation(7), receipt.registration).unwrap();
    assert!(r.status(41, correlation(7), receipt.registration).is_err());
    let next = r
        .register(
            41,
            context(),
            correlation(100),
            w::Kind::Window,
            (),
            image(),
        )
        .unwrap();
    assert!(next.registration > receipt.registration);
}
