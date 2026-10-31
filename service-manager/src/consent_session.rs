//! Session lifecycle publications use an owner-managed, non-reusable epoch.
use mochi_user_platform as p;
use p::capability::presentation::Context;

#[derive(Default)]
pub(crate) struct Epoch {
    generation: u64,
    last_session: u64,
    domain: Option<LaunchDomain>,
}
pub(crate) struct LaunchDomain {
    session: u64,
    handle: u32,
}
impl Drop for LaunchDomain {
    fn drop(&mut self) {
        let _ = p::handle::close(self.handle);
    }
}
impl LaunchDomain {
    pub fn create(session: u64, endpoint: u32) -> Result<Self, p::syscall::SysError> {
        if session == 0 {
            return Err(p::syscall::SysError::from_raw(-22));
        }
        let client = mochios_posix_client::Client::new(
            mochios_posix_client::SyscallEndpointTransport::new(endpoint),
        );
        let domain = client
            .create_process_domain(&[])
            .map_err(|error| match error {
                mochios_posix_client::ClientError::Remote(status) => {
                    p::syscall::SysError::from_raw(i64::from(status))
                }
                mochios_posix_client::ClientError::Transport(error) => error,
                _ => p::syscall::SysError::from_raw(-5),
            })?;
        Ok(Self {
            session,
            handle: domain.handle,
        })
    }
    pub fn session(&self) -> u64 {
        self.session
    }
    pub fn attachment(&self) -> mochios_posix_client::ObjectHandleAttachment<u32> {
        mochios_posix_client::ObjectHandleAttachment {
            handle: self.handle,
            rights: mochios_posix_protocol::process_domain::TOKEN_RIGHTS,
        }
    }
}
impl Epoch {
    /// Retain the domain used before the manager resumed its session roots.
    pub fn prepare(
        &mut self,
        session: u64,
        source: &LaunchDomain,
    ) -> Result<(), p::syscall::SysError> {
        self.domain = None;
        if session == 0 || session != source.session {
            return Err(p::syscall::SysError::from_raw(-22));
        }
        self.domain = Some(LaunchDomain {
            session,
            handle: p::handle::duplicate(
                source.handle,
                mochios_posix_protocol::process_domain::TOKEN_RIGHTS,
            )?,
        });
        Ok(())
    }
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
        let domain = if active {
            Some(
                self.domain
                    .as_ref()
                    .filter(|domain| domain.session == session)
                    .ok_or_else(|| p::syscall::SysError::from_raw(-13))?
                    .handle,
            )
        } else {
            None
        };
        self.publish(session, active, |context| {
            let endpoint = p::process::find_by_name("capability.service")?;
            let destination = u32::try_from(endpoint).map_err(|_| {
                p::syscall::SysError::from_raw(
                    p::syscall::NativeError::InvalidArgument.into_raw() as i64
                )
            })?;
            p::presentation::session_with_domain(
                destination,
                context,
                domain
                    .filter(|_| context.active)
                    .map(|handle| p::ipc::IpcObjectHandle {
                        handle,
                        reserved: 0,
                        rights: p::handle::HANDLE_RIGHT_TRANSFER,
                    }),
            )
        })
    }
}
