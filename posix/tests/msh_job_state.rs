#[path = "../../../binaries/msh/src/job_state.rs"]
mod production;
use production::{Members, State};
#[test]
fn a_pipeline_is_stopped_only_after_every_live_member_stops() {
    let mut members = Members::new();
    members.push(11);
    members.push(12);
    members.push(13);
    assert!(members.update(11, State::Done));
    assert!(members.update(12, State::Stopped));
    assert_eq!(members.state(), State::Running);
    assert!(members.update(13, State::Stopped));
    assert_eq!(members.state(), State::Stopped);
    members.resume();
    assert_eq!(members.state(), State::Running);
    assert_eq!(
        members.entries().collect::<Vec<_>>(),
        [
            (11, State::Done),
            (12, State::Running),
            (13, State::Running)
        ]
    );
    assert!(!members.update(11, State::Running));
    assert!(!members.update(999, State::Done));
    members.update(12, State::Done);
    members.update(13, State::Done);
    assert_eq!(members.state(), State::Done);
}
