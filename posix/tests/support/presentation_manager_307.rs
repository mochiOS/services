//! Uses actual session publication and the retained native renderer process.
use mochi_user_platform as p;
use p::capability::{
    consent::{self, Correlation},
    presentation as w,
};
fn query(broker: u64) -> (Correlation, w::Receipt) {
    let mut bytes = [0; consent::FEEDBACK_BYTES + w::RECEIPT_BYTES];
    let message = p::ipc::call(broker, b"PS07", &mut bytes).unwrap();
    assert_eq!(message >> 32, broker);
    assert_eq!(message as u32 as usize, bytes.len());
    (
        consent::decode(&bytes[..consent::FEEDBACK_BYTES])
            .unwrap()
            .0,
        w::decode_receipt(&bytes[consent::FEEDBACK_BYTES..]).unwrap(),
    )
}
pub fn run(logger: u64, epoch: &mut crate::consent_session::Epoch, session: u64) {
    let token = p::service_ready::generate_token().unwrap();
    let target = p::service_ready::Target {
        endpoint: p::ipc::create().unwrap(),
        token,
    };
    let process = crate::service_launcher::spawn_presentation_probe(logger, target).unwrap();
    let mut deferred = alloc::collections::VecDeque::new();
    let endpoint =
        crate::readiness::wait_for_published_endpoint(token, process.watch_target(), &mut deferred)
            .unwrap();
    let _ = p::handle::close(endpoint);
    let broker = p::process::find_by_name("capability.service").unwrap();
    let compositor = p::process::find_by_name("compositor.service").unwrap() as u32;
    let started = p::time::monotonic_nanoseconds().unwrap();
    let (correlation, receipt) = loop {
        assert!(
            p::time::monotonic_nanoseconds().unwrap() - started < 30_000_000_000,
            "frame was not presented"
        );
        let current = query(broker);
        assert_eq!(current.1.status, 0);
        assert_eq!(current.1.renderer.process, process.process_id());
        assert_ne!(current.1.stage, w::Stage::Revoked);
        if current.1.stage == w::Stage::Presented {
            break current;
        }
        p::thread::sleep_milliseconds(25).unwrap();
    };
    assert!(
        receipt.surface != 0 && receipt.content_generation != 0 && receipt.focus_generation != 0
    );
    let foreign = p::presentation::command(
        compositor,
        w::Command::Bind {
            correlation,
            surface: receipt.surface,
        },
        None,
    )
    .unwrap_err();
    assert_eq!(foreign.raw(), -13);
    let foreign = p::presentation::session(compositor, receipt.context).unwrap_err();
    assert_eq!(foreign.raw(), -13);
    println!(
        "presentation-307: PASS actual ViewKit frame, measured process, fresh scanout and focus; foreign binding/session denied; awaiting Close"
    );
    let started = p::time::monotonic_nanoseconds().unwrap();
    loop {
        assert!(
            p::time::monotonic_nanoseconds().unwrap() - started < 120_000_000_000,
            "Close was not received"
        );
        let (_, current) = query(broker);
        assert_eq!(current.status, 0);
        if current.stage == w::Stage::Revoked {
            break;
        }
        p::thread::sleep_milliseconds(50).unwrap();
    }
    assert_eq!(query(broker).1.stage, w::Stage::Revoked);
    epoch.native(session, false).unwrap();
    assert_eq!(query(broker).1.status, 2);
    epoch.native(session, true).unwrap();
    assert_eq!(query(broker).1.status, 2);
    println!(
        "presentation-307: PASS removed surface revoked; session deactivation/reactivation cannot revive old evidence; no grant performed"
    );
    process.terminate();
}
