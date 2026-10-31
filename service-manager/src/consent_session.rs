//! Session lifecycle publications use an owner-managed, non-reusable epoch.
use mochi_user_platform as p;
use p::capability::presentation::Context;

#[derive(Default)]
pub(crate) struct Epoch {
    generation: u64,
    last_session: u64,
}
impl Epoch {
    pub fn publish(
        &mut self,
        session: u64,
        active: bool,
        mut send: impl FnMut(Context) -> Result<(), p::syscall::SysError>,
    ) -> Result<(), p::syscall::SysError> {
        if session == 0 {
            return Err(p::syscall::SysError::from_raw(
                p::syscall::NativeError::InvalidArgument.into_raw() as i64,
            ));
        }
        let Some(next) = self.generation.checked_add(1) else {
            // Revocation is still possible at the terminal generation;
            // activation can never wrap back into an earlier session lease.
            send(Context {
                session: self.last_session,
                generation: self.generation,
                active: false,
            })?;
            return Err(p::syscall::SysError::from_raw(
                p::syscall::NativeError::LimitExceeded.into_raw() as i64,
            ));
        };
        self.generation = next;
        self.last_session = session;
        send(Context {
            session,
            generation: next,
            active,
        })
    }
    pub fn native(&mut self, session: u64, active: bool) -> Result<(), p::syscall::SysError> {
        self.publish(session, active, |context| {
            let endpoint = p::process::find_by_name("capability.service")?;
            let destination = u32::try_from(endpoint).map_err(|_| {
                p::syscall::SysError::from_raw(
                    p::syscall::NativeError::InvalidArgument.into_raw() as i64
                )
            })?;
            p::presentation::session(destination, context)
        })
    }
}
