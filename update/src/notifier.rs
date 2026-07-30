use mochios_certificate_database::DatabaseState;
use mochios_signature_protocol::{UPDATE_NOTIFICATION_LEN, UpdateNotification};

pub trait NotificationTransport {
    type Error;

    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

pub struct Notifier<T> {
    transport: T,
    request_id: u64,
}

impl<T: NotificationTransport> Notifier<T> {
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            request_id: 0,
        }
    }

    pub fn notify_changes(
        &mut self,
        before: &DatabaseState,
        after: &DatabaseState,
    ) -> Result<(), T::Error> {
        if before.trust.snapshot_version != after.trust.snapshot_version {
            let request_id = self.next_request_id();
            self.send(UpdateNotification::trust(
                request_id,
                after.trust.snapshot_version,
                after.generation,
            ))?;
        }
        if before.revocations.snapshot_version != after.revocations.snapshot_version {
            let request_id = self.next_request_id();
            self.send(UpdateNotification::revocations(
                request_id,
                after.revocations.snapshot_version,
                after.generation,
            ))?;
        }
        Ok(())
    }

    fn next_request_id(&mut self) -> u64 {
        self.request_id = self.request_id.wrapping_add(1);
        if self.request_id == 0 {
            self.request_id = 1;
        }
        self.request_id
    }

    fn send(&mut self, notification: UpdateNotification) -> Result<(), T::Error> {
        let mut bytes = [0; UPDATE_NOTIFICATION_LEN];
        let Ok(length) = notification.encode(&mut bytes) else {
            return Ok(());
        };
        self.transport.send(&bytes[..length])
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

#[cfg(target_os = "mochios")]
pub struct SignatureTransport;

#[cfg(target_os = "mochios")]
impl NotificationTransport for SignatureTransport {
    type Error = mochi_user_platform::syscall::SysError;

    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let endpoint = mochi_user_platform::process::find_by_name("signature.service")?;
        if endpoint == 0 {
            return Err(mochi_user_platform::syscall::SysError::from_raw(
                mochi_user_platform::syscall::ENOENT as i64,
            ));
        }
        mochi_user_platform::ipc::send(endpoint, bytes).map(|_| ())
    }
}
