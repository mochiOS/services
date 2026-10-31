#[path = "../../service-manager/src/consent_session.rs"]
mod production;
use mochi_user_platform as p;
#[test]
fn lifecycle_publications_never_reuse_an_epoch_even_after_a_failed_delivery() {
    let mut epoch = production::Epoch::default();
    let mut observed = Vec::new();
    for (session, active, fail) in [
        (1, true, false),
        (1, false, false),
        (1, true, true),
        (1, false, false),
        (2, true, false),
    ] {
        let result = epoch.publish(session, active, |context| {
            observed.push(context);
            if fail {
                Err(p::syscall::SysError::from_raw(-5))
            } else {
                Ok(())
            }
        });
        assert_eq!(result.is_err(), fail);
    }
    assert_eq!(
        observed
            .iter()
            .map(|c| (c.session, c.generation, c.active))
            .collect::<Vec<_>>(),
        [
            (1, 1, true),
            (1, 2, false),
            (1, 3, true),
            (1, 4, false),
            (2, 5, true)
        ]
    );
    assert!(
        epoch
            .publish(0, true, |_| panic!("invalid session must not be published"))
            .is_err()
    );
}
