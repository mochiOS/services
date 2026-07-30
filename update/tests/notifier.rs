use mochios_certificate_database::DatabaseState;
use mochios_signature_protocol::{Opcode, UpdateNotification};
use update::notifier::{NotificationTransport, Notifier};

#[derive(Default)]
struct RecordingTransport {
    messages: Vec<Vec<u8>>,
}

impl NotificationTransport for RecordingTransport {
    type Error = ();

    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.messages.push(bytes.to_vec());
        Ok(())
    }
}

#[test]
fn emits_only_changed_snapshots_in_trust_then_revocation_order() {
    let before = DatabaseState::default();
    let mut after = before.clone();
    after.generation = 2;
    after.trust.snapshot_version = 7;
    after.revocations.snapshot_version = 9;
    let mut notifier = Notifier::new(RecordingTransport::default());

    notifier.notify_changes(&before, &after).unwrap();

    let transport = notifier.into_transport();
    let messages = transport
        .messages
        .iter()
        .map(|bytes| UpdateNotification::decode(bytes).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].opcode, Opcode::TrustUpdated);
    assert_eq!(messages[0].snapshot_version, 7);
    assert_eq!(messages[0].generation, 2);
    assert_eq!(messages[0].request_id, 1);
    assert_eq!(messages[1].opcode, Opcode::RevocationsUpdated);
    assert_eq!(messages[1].snapshot_version, 9);
    assert_eq!(messages[1].request_id, 2);
}

#[test]
fn last_checked_only_changes_do_not_emit_notifications() {
    let before = DatabaseState::default();
    let mut after = before.clone();
    after.generation = 1;
    after.trust.last_checked_at = 123;
    let mut notifier = Notifier::new(RecordingTransport::default());

    notifier.notify_changes(&before, &after).unwrap();

    assert!(notifier.into_transport().messages.is_empty());
}
