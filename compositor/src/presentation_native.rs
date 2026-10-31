//! Native adapter for compositor-owned presentation state. The authority is
//! owned by the compositor event loop; renderers cannot mint registrations.
use crate::{
    client::Client,
    presentation::{Observation, Registry, SurfaceKey},
    received_buffer::ReceivedHandles,
    surface::{Surface, SurfaceRole, surface_extent},
};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use mochi_user_platform as p;
use p::capability::presentation as w;
use p::execution_peer::{MeasuredPeer, ProcessReference};

// Updated only by compositor focus changes. Zero permanently poisons an
// exhausted generation; returning to the same surface cannot restore a lease.
static FOCUS_GENERATION: AtomicU64 = AtomicU64::new(1);
pub(crate) fn focus_changed() {
    let _ = FOCUS_GENERATION.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        if old == 0 {
            None
        } else {
            Some(old.checked_add(1).unwrap_or(0))
        }
    });
}
fn image(info: p::syscall::ProcessImageInfo) -> Result<w::Image, u32> {
    if info.process_id == 0 || info.digest_kind != p::syscall::PROCESS_IMAGE_DIGEST_SHA256 {
        return Err(13);
    }
    Ok(w::Image {
        process: info.process_id,
        revision: info.image_revision,
        digest: info.digest,
    })
}
fn native(_: p::syscall::SysError) -> u32 {
    13
}
struct Renderer {
    process: ProcessReference,
    image: w::Image,
    kind: w::Kind,
}
#[derive(Default)]
pub(crate) struct Authority {
    owner: Option<MeasuredPeer>,
    registry: Registry<Renderer>,
}
impl Authority {
    fn owner(&self, sender: u64) -> Result<MeasuredPeer, u32> {
        if p::capability::check_thread(sender, "capabilities.manage") != Ok(1) {
            return Err(13);
        }
        let current = p::execution_peer::capture(sender).map_err(native)?;
        if let Some(owner) = &self.owner {
            if owner.endpoint != current.endpoint
                || owner.image != current.image
                || owner.context.thread_id != current.context.thread_id
                || !p::handle::same_object(owner.process.0, current.process.0).map_err(native)?
            {
                return Err(13);
            }
        }
        Ok(current)
    }
    pub fn session(
        &mut self,
        sender: u64,
        bytes: &[u8],
        handles: &ReceivedHandles,
    ) -> Result<(), u32> {
        if handles.0.count != 0 || !handles.0.is_user_delivery() {
            return Err(22);
        }
        let context = w::decode_session(bytes).map_err(|_| 22u32)?;
        let owner = self.owner(sender)?;
        self.registry.update_context(context)?;
        if self.owner.is_none() {
            self.owner = Some(owner);
        }
        Ok(())
    }
    pub fn control(
        &mut self,
        sender: u64,
        bytes: &[u8],
        handles: &mut ReceivedHandles,
        clients: &[Client],
        surfaces: &[Surface],
        keyboard_focus: Option<usize>,
        width: u32,
        height: u32,
    ) -> Vec<u8> {
        let result = (|| {
            if !handles.0.is_user_delivery() {
                return Err(22);
            }
            let command = w::decode_command(bytes).map_err(|_| 22u32)?;
            if let w::Command::Bind {
                correlation,
                surface,
            } = command
            {
                if handles.0.count != 0 {
                    return Err(22);
                }
                let (renderer, expected, kind) = self.registry.expected(correlation)?;
                let client = clients
                    .iter()
                    .find(|client| client.live && client.sender == sender)
                    .ok_or(13u32)?;
                let selected = surfaces
                    .iter()
                    .find(|s| s.live && s.token == surface && s.owner == client.id)
                    .ok_or(13u32)?;
                if !role_matches(kind, selected.role) {
                    return Err(13);
                }
                let key = SurfaceKey {
                    token: surface,
                    client: client.id.0,
                    sender,
                };
                let observed = observation(
                    renderer,
                    key,
                    clients,
                    surfaces,
                    keyboard_focus,
                    width,
                    height,
                )
                .ok_or(13u32)?;
                if observed.image != expected {
                    return Err(13);
                }
                return self.registry.bind(correlation, observed);
            }
            self.owner(sender)?;
            if self.owner.is_none() {
                return Err(13);
            }
            match command {
                w::Command::Register {
                    context,
                    correlation,
                    kind,
                } => {
                    if handles.0.count != 1
                        || handles.0.handles[0].handle == 0
                        || handles.0.handles[0].reserved != 0
                        || handles.0.handles[0].rights != p::handle::HANDLE_RIGHT_WAIT
                    {
                        return Err(22);
                    }
                    let process = ProcessReference(handles.0.handles[0].handle);
                    handles.0.handles[0] = Default::default();
                    handles.0.count = 0;
                    let captured = image(p::process::image_info(Some(process.0)).map_err(native)?)?;
                    let renderer = Renderer {
                        process,
                        image: captured,
                        kind,
                    };
                    self.registry
                        .register(sender, context, correlation, kind, renderer, captured)
                }
                w::Command::Status {
                    correlation,
                    registration,
                } => {
                    if handles.0.count != 0 {
                        return Err(22);
                    }
                    self.observe(clients, surfaces, keyboard_focus, width, height);
                    self.registry.status(sender, correlation, registration)
                }
                w::Command::Cancel {
                    correlation,
                    registration,
                } => {
                    if handles.0.count != 0 {
                        return Err(22);
                    }
                    self.registry.cancel(sender, correlation, registration)
                }
                w::Command::Bind { .. } => unreachable!(),
            }
        })();
        w::encode_receipt(result.unwrap_or_else(w::Receipt::failure))
            .expect("validated compositor receipt")
            .to_vec()
    }
    pub fn observe(
        &mut self,
        clients: &[Client],
        surfaces: &[Surface],
        focus: Option<usize>,
        width: u32,
        height: u32,
    ) -> bool {
        self.registry.observe(|renderer, key| {
            observation(renderer, key, clients, surfaces, focus, width, height)
        })
    }
    pub fn full_presented(
        &mut self,
        clients: &[Client],
        surfaces: &[Surface],
        focus: Option<usize>,
        width: u32,
        height: u32,
    ) {
        self.registry.full_presented(|renderer, key| {
            observation(renderer, key, clients, surfaces, focus, width, height)
        });
    }
}
fn role_matches(kind: w::Kind, role: SurfaceRole) -> bool {
    matches!(
        (kind, role),
        (w::Kind::SecureOverlay, SurfaceRole::SecureOverlay)
            | (w::Kind::Window, SurfaceRole::Toplevel)
    )
}
fn observation(
    renderer: &Renderer,
    key: SurfaceKey,
    clients: &[Client],
    surfaces: &[Surface],
    focus: Option<usize>,
    width: u32,
    height: u32,
) -> Option<Observation> {
    let client = clients
        .iter()
        .find(|c| c.live && c.id.0 == key.client && c.sender == key.sender)?;
    let (index, selected) = surfaces
        .iter()
        .enumerate()
        .find(|(_, s)| s.live && s.token == key.token && s.owner == client.id)?;
    if selected.is_decoration || !role_matches(renderer.kind, selected.role) {
        return None;
    }
    let peer = p::execution_peer::capture(key.sender).ok()?;
    if !p::handle::same_object(peer.process.0, renderer.process.0).ok()? {
        return None;
    }
    let current = image(peer.image).ok()?;
    if current != renderer.image || selected.owner_process != current.process {
        return None;
    }
    let (w, h) = surface_extent(selected);
    let left = i64::from(selected.x);
    let top = i64::from(selected.y);
    let right = left.checked_add(i64::from(w))?;
    let bottom = top.checked_add(i64::from(h))?;
    let visible = selected.visible
        && w != 0
        && h != 0
        && left >= 0
        && top >= 0
        && right <= i64::from(width)
        && bottom <= i64::from(height);
    let above = |other: &Surface| {
        (other.role.stack_layer(), other.z) > (selected.role.stack_layer(), selected.z)
    };
    let unobscured = !surfaces.iter().enumerate().any(|(other_index, other)| {
        if other_index == index || !other.live || !other.visible || !above(other) {
            return false;
        }
        let (ow, oh) = surface_extent(other);
        let ol = i64::from(other.x);
        let ot = i64::from(other.y);
        ol < right && ol + i64::from(ow) > left && ot < bottom && ot + i64::from(oh) > top
    });
    Some(Observation {
        image: current,
        surface: key,
        content: selected.content_generation,
        focus: FOCUS_GENERATION.load(Ordering::Acquire),
        focused: focus == Some(index),
        visible,
        unobscured,
        ready: selected.content_generation != 0
            && (selected.current_buffer.is_some()
                || !selected.current.is_empty()
                || selected.gpu.is_some()),
    })
}
