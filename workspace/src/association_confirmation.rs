//! An app proposes a change; an OS-owned Files process confirms the retained
//! operation. Neither the app nor a completion payload can replace that target.
use super::*;
const MAX_PENDING: usize = 16;
const _: () = assert!(1 + 2 * MAX_PENDING <= mnu_abi::HANDLE_WAIT_MANY_MAX_ITEMS);
pub(super) struct Pending {
    sender: u64,
    request_id: u64,
    process: u64,
    image: platform::syscall::ProcessImageInfo,
    presenter: u64,
    token: [u8; 16],
    change: Association,
    application: Option<InstalledApplication>,
    previous: Vec<Association>,
    deadline: u64,
    requester_handle: platform::execution_peer::ProcessReference,
    presenter_handle: OwnedObjectHandle,
}
fn trusted_system_ui(context: &platform::syscall::ThreadSecurityContext, package: &[u8]) -> bool {
    context.provenance == 1
        && context.subject_key_id == [0; 32]
        && context
            .developer_id
            .get(..context.developer_id_len as usize)
            == Some(b"org.mochios.system")
        && context.package_id.get(..context.package_id_len as usize) == Some(package)
}
fn declares(associations: &[Association], change: &Association) -> bool {
    let supports = |extension: bool| {
        associations
            .iter()
            .filter(|a| {
                if extension {
                    a.extension == change.extension
                } else {
                    a.content_type == change.content_type
                }
            })
            .fold(0, |roles, a| roles | a.roles)
            & change.roles
            == change.roles
    };
    (change.extension.is_empty() || supports(true))
        && (change.content_type.is_empty() || supports(false))
}
impl WorkspaceService {
    pub(super) fn expire_associations(&mut self) {
        let now = platform::time::monotonic_nanoseconds().unwrap_or(0);
        let mut index = 0;
        while index < self.pending_associations.len() {
            let pending = &self.pending_associations[index];
            let current = panel_requester_image(pending.sender).ok() == Some(pending.image);
            let presenter_alive = platform::process::handle_status(pending.presenter_handle.raw())
                .is_ok_and(|status| status.state != mnu_abi::PROCESS_STATE_EXITED);
            if current && presenter_alive && now < pending.deadline {
                index += 1;
                continue;
            }
            let pending = self.pending_associations.remove(index);
            let _ = set_process_modal(
                COMPOSITOR_END_PROCESS_MODAL,
                pending.process,
                pending.presenter,
            );
            if current {
                self.reply_status(pending.sender, pending.request_id, -125, 0);
            }
        }
    }
    pub(super) fn association_wait_items(
        &self,
        receiver: u32,
        items: &mut [mochi_user_syscall::HandleWaitItem; mnu_abi::HANDLE_WAIT_MANY_MAX_ITEMS],
    ) -> (usize, u64) {
        items[0] = mochi_user_syscall::HandleWaitItem {
            handle: receiver,
            interests: mnu_abi::HANDLE_SIGNAL_READABLE,
            ..Default::default()
        };
        let mut count = 1;
        let mut deadline = mnu_abi::HANDLE_WAIT_INFINITE;
        for pending in &self.pending_associations {
            deadline = deadline.min(pending.deadline);
            for handle in [pending.requester_handle.0, pending.presenter_handle.raw()] {
                items[count] = mochi_user_syscall::HandleWaitItem {
                    handle,
                    interests: mnu_abi::HANDLE_SIGNAL_TERMINATED,
                    ..Default::default()
                };
                count += 1;
            }
        }
        (count, deadline)
    }
    pub(super) fn request_association(
        &mut self,
        sender: u64,
        request: protocol::Message<'_>,
        remove: bool,
    ) {
        let result: Result<(), u64> = (|| {
            let change = if remove {
                let (extension, content_type, roles) =
                    decode_association_key(request.payload).ok_or(22u64)?;
                Association {
                    extension,
                    content_type,
                    roles,
                    bundle_id: String::new(),
                }
            } else {
                decode_association_request(request.payload).ok_or(22u64)?
            };
            let peer = platform::execution_peer::capture(sender).map_err(error::native_errno)?;
            let package = peer
                .context
                .package_id
                .get(..peer.context.package_id_len as usize)
                .ok_or(13u64)?;
            let system_ui = [b"org.mochios.settings".as_slice(), b"org.mochios.files"]
                .iter()
                .any(|package| trusted_system_ui(&peer.context, package));
            if remove {
                if !system_ui
                    && !self.associations.iter().any(|a| {
                        a.extension == change.extension
                            && a.content_type == change.content_type
                            && a.roles == change.roles
                            && a.bundle_id.as_bytes() == package
                    })
                {
                    return Err(13);
                }
            } else if !system_ui && change.bundle_id.as_bytes() != package {
                return Err(13);
            }
            let application = if remove {
                None
            } else {
                let app = installed_applications()
                    .into_iter()
                    .find(|app| app.bundle_id == change.bundle_id)
                    .ok_or(2u64)?;
                if !declares(&app.associations, &change) {
                    return Err(22);
                }
                Some(app)
            };
            if self.pending_associations.len() >= MAX_PENDING
                || self
                    .pending_associations
                    .iter()
                    .any(|p| p.process == peer.context.process_id)
            {
                return Err(28);
            }
            let kind = if change.content_type.is_empty() {
                format!(".{} files", change.extension)
            } else {
                change.content_type.clone()
            };
            let description = if let Some(app) = application.as_ref() {
                format!(
                    "Use {:?} ({}) as the default application for {}?",
                    app.name, app.bundle_id, kind
                )
            } else {
                format!("Reset the default application for {}?", kind)
            };
            let mut token = [0; 16];
            platform::random::fill(&mut token).map_err(error::native_errno)?;
            let deadline = platform::time::monotonic_nanoseconds()
                .map_err(error::native_errno)?
                .saturating_add(15 * 60 * 1_000_000_000);
            let mut payload =
                vec![0; protocol::association_confirmation::PREFIX + description.len()];
            let length =
                protocol::association_confirmation::encode(token, &description, &mut payload)
                    .map_err(|_| 22u64)?;
            let argument = format!(
                "--system-association-confirmation={}:{}",
                self.endpoint,
                hex_encode(&payload[..length])
            );
            let presenter = launch_executable(FILES_ENTRY_PATH, &[argument])?;
            let presenter_handle = OwnedObjectHandle(
                platform::process::open_handle_for_process_id(
                    presenter,
                    mnu_abi::HANDLE_RIGHT_WAIT,
                )
                .map_err(error::native_errno)?,
            );
            let _ = set_process_modal(
                COMPOSITOR_BEGIN_PROCESS_MODAL,
                peer.context.process_id,
                presenter,
            );
            let previous = self
                .associations
                .iter()
                .filter(|a| {
                    a.extension == change.extension
                        && a.content_type == change.content_type
                        && a.roles == change.roles
                })
                .cloned()
                .collect();
            self.pending_associations.push(Pending {
                sender,
                request_id: request.request_id,
                process: peer.context.process_id,
                image: peer.image,
                presenter,
                token,
                change,
                application,
                previous,
                deadline,
                requester_handle: peer.process,
                presenter_handle,
            });
            Ok(())
        })();
        if let Err(status) = result {
            self.reply_status(sender, request.request_id, -(status as i32), 0);
        }
    }

    pub(super) fn confirm_association(&mut self, sender: u64, request: protocol::Message<'_>) {
        if request.payload.len() != 24 || request.payload[17..] != [0; 7] || request.payload[16] > 1
        {
            self.reply_status(sender, request.request_id, -22, 0);
            return;
        }
        let Ok(peer) = platform::execution_peer::capture(sender) else {
            self.reply_status(sender, request.request_id, -13, 0);
            return;
        };
        let Some(index) = self.pending_associations.iter().position(|p| {
            p.token == request.payload[..16] && p.presenter == peer.context.process_id
        }) else {
            self.reply_status(sender, request.request_id, -13, 0);
            return;
        };
        if !trusted_system_ui(&peer.context, b"org.mochios.files") {
            self.reply_status(sender, request.request_id, -13, 0);
            return;
        }
        let pending = self.pending_associations.remove(index);
        let result = (|| {
            if request.payload[16] == 0 {
                return Err(125u64);
            }
            if !self.session.permits(&self.posix, pending.sender)
                || panel_requester_image(pending.sender).ok() != Some(pending.image)
            {
                return Err(13);
            }
            if let Some(app) = pending.application.as_ref() {
                if installed_applications()
                    .iter()
                    .find(|a| a.bundle_id == app.bundle_id)
                    != Some(app)
                {
                    return Err(11);
                }
            }
            let current: Vec<_> = self
                .associations
                .iter()
                .filter(|a| {
                    a.extension == pending.change.extension
                        && a.content_type == pending.change.content_type
                        && a.roles == pending.change.roles
                })
                .cloned()
                .collect();
            if current != pending.previous {
                return Err(11);
            }
            let mut associations = self.associations.clone();
            associations.retain(|a| {
                a.extension != pending.change.extension
                    || a.content_type != pending.change.content_type
                    || a.roles != pending.change.roles
            });
            if !pending.change.bundle_id.is_empty() {
                associations.push(pending.change);
            }
            persist_associations(&self.association_path, &associations).map_err(errno)?;
            self.associations = associations;
            Ok(())
        })();
        let _ = set_process_modal(
            COMPOSITOR_END_PROCESS_MODAL,
            pending.process,
            pending.presenter,
        );
        self.reply_status(
            pending.sender,
            pending.request_id,
            result.err().map_or(0, |status| -(status as i32)),
            0,
        );
        self.reply_status(sender, request.request_id, 0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_valid_extension_cannot_authorize_an_undeclared_type_or_role() {
        let association = Association {
            extension: "txt".into(),
            content_type: String::new(),
            roles: protocol::ASSOCIATION_ROLE_VIEW,
            bundle_id: "org.example.editor".into(),
        };
        let declarations = [association.clone()];
        let mut request = association;
        assert!(declares(&declarations, &request));
        request.content_type = "application/x-undeclared".into();
        assert!(!declares(&declarations, &request));
        request.content_type.clear();
        request.roles |= protocol::ASSOCIATION_ROLE_EDIT;
        assert!(!declares(&declarations, &request));
    }
    #[test]
    fn confirmation_requires_the_builtin_presenter_not_a_matching_bundle_string() {
        let mut context = platform::syscall::ThreadSecurityContext::default();
        let package = b"org.mochios.files";
        let developer = b"org.mochios.system";
        context.package_id[..package.len()].copy_from_slice(package);
        context.package_id_len = package.len() as u16;
        context.developer_id[..developer.len()].copy_from_slice(developer);
        context.developer_id_len = developer.len() as u16;
        context.provenance = 1;
        assert!(trusted_system_ui(&context, package));
        context.subject_key_id[0] = 1;
        assert!(!trusted_system_ui(&context, package));
        context.subject_key_id = [0; 32];
        context.provenance = 2;
        assert!(!trusted_system_ui(&context, package));
        context.provenance = 1;
        context.developer_id_len = 1;
        assert!(!trusted_system_ui(&context, package));
        context.developer_id_len = u16::MAX;
        assert!(!trusted_system_ui(&context, package));
    }
}
