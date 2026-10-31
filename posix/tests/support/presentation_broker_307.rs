//! Native presentation probe; never grants, persists or launches anything.
use crate::{
    consent_peer,
    consent_presentation::Channel,
    trusted_images::{Role, TrustedImages},
};
use mochi_user_platform as p;
use p::capability::{
    consent::{self, Correlation, Feedback, Ticket},
    presentation as w,
};
pub const HELLO: u32 = u32::from_le_bytes(*b"PH07");
pub const STATUS: u32 = u32::from_le_bytes(*b"PS07");
pub const BYTES: usize = consent::FEEDBACK_BYTES + w::RECEIPT_BYTES;
pub(crate) struct Probe {
    correlation: Correlation,
    registration: u64,
}
impl Probe {
    pub fn begin(
        sender: u64,
        trusted: &TrustedImages,
        channel: &Channel,
    ) -> Result<(Self, [u8; BYTES]), p::syscall::SysError> {
        let renderer = consent_peer::capture(sender)?;
        if trusted.role(&renderer)? != Some(Role::GraphicalPrompt) {
            return Err(denied());
        }
        let mut challenge = [0; 32];
        p::random::fill(&mut challenge)?;
        let correlation = Correlation {
            ticket: Ticket {
                id: p::service_ready::generate_token()?,
                challenge,
            },
            display: p::service_ready::generate_token()?,
        };
        let receipt = channel.register(trusted, &renderer, correlation, w::Kind::SecureOverlay)?;
        assert_eq!(receipt.stage, w::Stage::Pending);
        let probe = Self {
            correlation,
            registration: receipt.registration,
        };
        Ok((probe, encode(correlation, receipt)))
    }
    pub fn status(
        &self,
        sender: u64,
        trusted: &TrustedImages,
        channel: &Channel,
    ) -> Result<[u8; BYTES], p::syscall::SysError> {
        let caller = consent_peer::capture(sender)?;
        if trusted.role(&caller)? != Some(Role::SessionOwner) {
            return Err(denied());
        }
        let receipt = channel
            .status(self.correlation, self.registration)
            .unwrap_or_else(|error| {
                w::Receipt::failure(
                    mochios_posix_protocol::status::normalize_failure(error.raw()).unsigned_abs()
                        as u32,
                )
            });
        Ok(encode(self.correlation, receipt))
    }
}
fn denied() -> p::syscall::SysError {
    p::syscall::SysError::from_raw(p::syscall::NativeError::AccessDenied.into_raw() as i64)
}
fn encode(correlation: Correlation, receipt: w::Receipt) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    // This is probe configuration, not an assertion of display or consent.
    consent::encode(
        correlation,
        Feedback::Presented,
        &mut bytes[..consent::FEEDBACK_BYTES],
    )
    .unwrap();
    bytes[consent::FEEDBACK_BYTES..].copy_from_slice(&w::encode_receipt(receipt).unwrap());
    bytes
}
