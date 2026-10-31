//! Actual broker session adapter, with controlled native peers/domain replies.
extern crate self as mochi_user_platform;
pub use mochi_user_syscall as syscall;
pub mod capability {
    pub use mochios_capability_protocol::*;
}
use capability::presentation as w;
use std::{cell::RefCell, collections::BTreeMap};
#[path = "../../capability/src/consent.rs"]
mod consent;
#[path = "../../capability/src/consent_presentation.rs"]
mod production;
#[derive(Default)]
struct State {
    next: u32,
    objects: BTreeMap<u32, u64>,
    closed: Vec<u32>,
    events: Vec<&'static str>,
    owner_dead: bool,
    requester_changed: bool,
    fail_publication: bool,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
fn denied() -> syscall::SysError {
    syscall::SysError::from_raw(-13)
}
fn reference(endpoint: u64) -> u32 {
    STATE.with_borrow_mut(|s| {
        s.next += 1;
        let handle = 1000 + s.next;
        s.objects.insert(handle, endpoint);
        handle
    })
}
mod consent_peer {
    use super::*;
    pub struct ProcessReference(pub u32);
    impl Drop for ProcessReference {
        fn drop(&mut self) {
            let _ = handle::close(self.0);
        }
    }
    pub struct Peer {
        pub instance: consent::Instance,
        pub process: ProcessReference,
    }
    pub fn capture(endpoint: u64) -> Result<Peer, syscall::SysError> {
        if endpoint == 700 && STATE.with_borrow(|s| s.owner_dead) {
            return Err(denied());
        }
        Ok(Peer {
            instance: consent::Instance {
                endpoint,
                process: endpoint,
                thread: endpoint + 1,
                revision: 0,
                digest: if endpoint == 900 && STATE.with_borrow(|s| s.requester_changed) {
                    [2; 32]
                } else {
                    [1; 32]
                },
            },
            process: ProcessReference(reference(endpoint)),
        })
    }
}
mod trusted_images {
    use super::*;
    #[derive(PartialEq, Eq)]
    pub enum Role {
        Compositor,
        SessionOwner,
        GraphicalPrompt,
        TextDisplay,
    }
    pub struct TrustedImages;
    impl TrustedImages {
        pub fn role(&self, peer: &consent_peer::Peer) -> Result<Option<Role>, syscall::SysError> {
            Ok(match peer.instance.endpoint {
                700 => Some(Role::SessionOwner),
                800 => Some(Role::Compositor),
                _ => None,
            })
        }
    }
}
pub mod handle {
    use super::*;
    pub use mnu_abi::{HANDLE_RIGHT_TRANSFER, HANDLE_RIGHT_WAIT};
    pub fn close(value: u32) -> Result<(), syscall::SysError> {
        STATE.with_borrow_mut(|s| s.closed.push(value));
        Ok(())
    }
    pub fn same_object(left: u32, right: u32) -> Result<bool, syscall::SysError> {
        Ok(STATE.with_borrow(|s| {
            s.objects
                .get(&left)
                .zip(s.objects.get(&right))
                .is_some_and(|(a, b)| a == b)
        }))
    }
}
pub mod process {
    use super::*;
    pub fn find_by_name(name: &str) -> Result<u64, syscall::SysError> {
        assert_eq!(name, "compositor.service");
        Ok(800)
    }
    pub fn open_handle_for_endpoint(endpoint: u64, rights: u64) -> Result<u32, syscall::SysError> {
        assert_eq!(
            rights,
            handle::HANDLE_RIGHT_WAIT | handle::HANDLE_RIGHT_TRANSFER
        );
        Ok(reference(endpoint))
    }
}
pub mod ipc {
    pub use mnu_abi::IpcObjectHandle;
}
pub mod presentation {
    use super::*;
    pub fn session(destination: u32, _: w::Context) -> Result<(), syscall::SysError> {
        assert_eq!(destination, 800);
        STATE.with_borrow_mut(|s| {
            s.events.push("publication");
            if s.fail_publication {
                Err(denied())
            } else {
                Ok(())
            }
        })
    }
    pub fn command(
        _: u32,
        _: w::Command,
        _: Option<ipc::IpcObjectHandle>,
    ) -> Result<w::Receipt, syscall::SysError> {
        panic!("this test does not register a display")
    }
}
mod persistent_grant {
    use super::*;
    pub struct Client;
    impl Client {
        pub fn process_domain_contains(
            &self,
            domain: mochios_posix_client::ObjectHandleAttachment<u32>,
            process: mochios_posix_client::ObjectHandleAttachment<u32>,
        ) -> Result<bool, syscall::SysError> {
            assert_eq!(
                domain.rights,
                mochios_posix_protocol::process_domain::ATTACH_RIGHTS
            );
            assert_eq!(process.rights, handle::HANDLE_RIGHT_WAIT);
            STATE.with_borrow_mut(|s| {
                s.events.push("membership");
                if ![90, 92].contains(&domain.handle) {
                    return Err(denied());
                }
                Ok(s.objects.get(&process.handle) == Some(&900))
            })
        }
    }
    pub fn with_client<T>(
        operation: impl FnOnce(&Client) -> Result<T, syscall::SysError>,
    ) -> Result<T, syscall::SysError> {
        operation(&Client)
    }
}
fn context(generation: u64, active: bool) -> w::Context {
    w::Context {
        session: 7,
        generation,
        active,
    }
}
#[test]
fn measured_owner_and_requester_liveness_are_required_and_failed_publications_leave_no_usable_domain()
 {
    STATE.with_borrow_mut(|s| *s = State::default());
    let mut sessions = production::Sessions::default();
    let mut channel = None;
    let trusted = trusted_images::TrustedImages;
    let revoke = || STATE.with_borrow_mut(|s| s.events.push("revoke"));
    sessions
        .publish(
            700,
            context(1, true),
            Some(production::DomainReference(90)),
            &trusted,
            &mut channel,
            revoke,
        )
        .unwrap();
    STATE.with_borrow(|s| assert_eq!(s.events, ["revoke", "membership", "publication"]));
    let requester = consent_peer::capture(900).unwrap();
    assert_eq!(
        sessions
            .authenticate_member(channel.as_ref().unwrap(), &requester)
            .unwrap(),
        context(1, true)
    );
    assert!(
        sessions
            .authenticate_member(
                channel.as_ref().unwrap(),
                &consent_peer::capture(700).unwrap()
            )
            .is_err()
    );
    STATE.with_borrow_mut(|s| s.owner_dead = true);
    assert!(
        sessions
            .authenticate_member(channel.as_ref().unwrap(), &requester)
            .is_err()
    );
    STATE.with_borrow_mut(|s| {
        s.owner_dead = false;
        s.requester_changed = true;
    });
    assert!(
        sessions
            .authenticate_member(channel.as_ref().unwrap(), &requester)
            .is_err()
    );
    STATE.with_borrow_mut(|s| s.requester_changed = false);
    sessions
        .publish(700, context(2, false), None, &trusted, &mut channel, revoke)
        .unwrap();
    assert!(
        sessions
            .authenticate_member(channel.as_ref().unwrap(), &requester)
            .is_err()
    );
    assert!(
        sessions
            .publish(
                700,
                context(1, true),
                Some(production::DomainReference(91)),
                &trusted,
                &mut channel,
                revoke
            )
            .is_err()
    );
    STATE.with_borrow_mut(|s| s.fail_publication = true);
    assert!(
        sessions
            .publish(
                700,
                context(3, true),
                Some(production::DomainReference(92)),
                &trusted,
                &mut channel,
                revoke
            )
            .is_err()
    );
    assert!(
        sessions
            .authenticate_member(channel.as_ref().unwrap(), &requester)
            .is_err()
    );
    STATE.with_borrow(|s| {
        for domain in [90, 91, 92] {
            assert_eq!(
                s.closed.iter().filter(|handle| **handle == domain).count(),
                1
            );
        }
    });
}
