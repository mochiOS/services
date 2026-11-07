//! Temporary keyboard ownership for privileged shell panels. The saved target
//! is a surface token, never a reusable surface-table index.
use crate::client::ClientId;
use crate::input::{restore_keyboard_focus, update_keyboard_focus};
use crate::protocol::errno_status;
use crate::state::ModalSession;
use crate::surface::{Surface, SurfaceHandle, SurfaceRights, SurfaceRole, surface_index_for};

#[derive(Clone, Copy)]
pub(crate) struct Capture {
    previous: Option<SurfaceHandle>,
}

pub(crate) fn shell_shortcuts_blocked(surfaces: &[Surface]) -> bool {
    surfaces.iter().any(|surface| {
        surface.live
            && surface.visible
            && surface.stack_layer() >= SurfaceRole::SystemModal.stack_layer()
    })
}

pub(crate) fn release(surfaces: &[Surface], focus: &mut Option<usize>, index: usize) {
    let Some(capture) = surfaces[index].keyboard_capture.take() else {
        return;
    };
    if *focus != Some(index) {
        return;
    }
    let previous = capture.previous.and_then(|handle| {
        surfaces.iter().position(|surface| {
            surface.live && surface.visible && !surface.is_decoration && surface.handle == handle
        })
    });
    let blocked = shell_shortcuts_blocked(surfaces);
    let next = if blocked { None } else { previous };
    update_keyboard_focus(surfaces, focus, next);
    if blocked || (capture.previous.is_some() && previous.is_none()) {
        restore_keyboard_focus(surfaces, focus);
    }
}

pub(crate) fn set(
    surfaces: &[Surface],
    focus: &mut Option<usize>,
    sessions: &[ModalSession],
    client: ClientId,
    handle: SurfaceHandle,
    captured: bool,
) -> Result<(), u32> {
    let denied = errno_status(mochi_user_syscall::EACCES);
    let index =
        surface_index_for(surfaces, client, handle, SurfaceRights::FOCUS_CONTROL).ok_or(denied)?;
    let surface = &surfaces[index];
    if surface.role != SurfaceRole::Panel || surface.is_decoration {
        return Err(denied);
    }
    if !captured {
        release(surfaces, focus, index);
        return Ok(());
    }
    if !surface.visible
        || shell_shortcuts_blocked(surfaces)
        || sessions.iter().any(|session| {
            session.owner_process == surface.owner_process
                || focus
                    .and_then(|index| surfaces.get(index))
                    .is_some_and(|current| current.owner_process == session.owner_process)
        })
    {
        return Err(denied);
    }
    if *focus == Some(index) && surface.keyboard_capture.get().is_some() {
        return Ok(());
    }
    if focus
        .and_then(|index| surfaces.get(index))
        .is_some_and(|current| current.role == SurfaceRole::Panel)
    {
        return Err(denied);
    }
    let previous = focus
        .and_then(|index| surfaces.get(index))
        .map(|surface| surface.handle);
    update_keyboard_focus(surfaces, focus, Some(index));
    surface.keyboard_capture.set(Some(Capture { previous }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(role: SurfaceRole, token: u64, process: u64) -> Surface {
        let mut surface = Surface::empty();
        surface.live = true;
        surface.role = role;
        surface.owner = ClientId(process);
        surface.owner_process = process;
        surface.handle = SurfaceHandle(token);
        surface.token = token;
        surface.z = token as u32;
        surface.rights = role
            .privileged_overlay_rights()
            .unwrap_or(SurfaceRights::GENERAL_CLIENT);
        surface
    }

    fn acquire(surfaces: &[Surface], focus: &mut Option<usize>) -> Result<(), u32> {
        set(surfaces, focus, &[], ClientId(2), SurfaceHandle(20), true)
    }

    #[test]
    fn capture_and_release_restore_the_exact_previous_window() {
        let surfaces = [
            surface(SurfaceRole::Toplevel, 10, 1),
            surface(SurfaceRole::Panel, 20, 2),
            surface(SurfaceRole::Toplevel, 30, 3),
        ];
        let mut focus = Some(0);
        assert_eq!(acquire(&surfaces, &mut focus), Ok(()));
        assert_eq!(focus, Some(1));
        assert_eq!(acquire(&surfaces, &mut focus), Ok(()));
        release(&surfaces, &mut focus, 1);
        assert_eq!(focus, Some(0));
        release(&surfaces, &mut focus, 1);
        assert_eq!(focus, Some(0));
    }

    #[test]
    fn capture_requires_the_owned_visible_panel_and_its_granted_right() {
        let mut surfaces = [surface(SurfaceRole::Panel, 20, 2)];
        let mut focus = None;
        assert!(
            set(
                &surfaces,
                &mut focus,
                &[],
                ClientId(3),
                SurfaceHandle(20),
                true
            )
            .is_err()
        );
        assert!(
            set(
                &surfaces,
                &mut focus,
                &[],
                ClientId(2),
                SurfaceHandle(21),
                true
            )
            .is_err()
        );
        surfaces[0].rights = SurfaceRights::GENERAL_CLIENT;
        assert!(acquire(&surfaces, &mut focus).is_err());
        surfaces[0].rights = SurfaceRole::Panel.privileged_overlay_rights().unwrap();
        surfaces[0].role = SurfaceRole::Toplevel;
        assert!(acquire(&surfaces, &mut focus).is_err());
        surfaces[0].role = SurfaceRole::Panel;
        surfaces[0].visible = false;
        assert!(acquire(&surfaces, &mut focus).is_err());
        assert_eq!(focus, None);
        assert!(surfaces[0].keyboard_capture.get().is_none());
        assert!(SurfaceRole::Panel.general_client_rights().is_err());
        assert!(!SurfaceRights::GENERAL_CLIENT.contains(SurfaceRights::FOCUS_CONTROL));
    }

    #[test]
    fn secure_and_modal_surfaces_block_shell_shortcuts_and_capture() {
        for role in [
            SurfaceRole::SecureOverlay,
            SurfaceRole::SystemModal,
            SurfaceRole::Toplevel,
        ] {
            let mut surfaces = [surface(role, 10, 1), surface(SurfaceRole::Panel, 20, 2)];
            surfaces[0].protected_presentation = role == SurfaceRole::Toplevel;
            let mut focus = Some(0);
            assert!(shell_shortcuts_blocked(&surfaces));
            assert!(acquire(&surfaces, &mut focus).is_err());
            assert_eq!(focus, Some(0));
            surfaces[0].visible = false;
            assert!(!shell_shortcuts_blocked(&surfaces));
            focus = None;
            assert_eq!(acquire(&surfaces, &mut focus), Ok(()));
        }
    }

    #[test]
    fn delayed_release_after_preemption_cannot_steal_the_new_focus() {
        let surfaces = [
            surface(SurfaceRole::Toplevel, 10, 1),
            surface(SurfaceRole::Panel, 20, 2),
            surface(SurfaceRole::Toplevel, 30, 3),
        ];
        let mut focus = Some(0);
        acquire(&surfaces, &mut focus).unwrap();
        update_keyboard_focus(&surfaces, &mut focus, Some(2));
        assert!(surfaces[1].keyboard_capture.get().is_none());
        release(&surfaces, &mut focus, 1);
        assert_eq!(focus, Some(2));
    }

    #[test]
    fn reused_surface_slots_and_closed_previous_windows_do_not_restore_stale_focus() {
        let mut surfaces = [
            surface(SurfaceRole::Toplevel, 10, 1),
            surface(SurfaceRole::Panel, 20, 2),
            surface(SurfaceRole::Toplevel, 30, 3),
        ];
        let mut focus = Some(0);
        acquire(&surfaces, &mut focus).unwrap();
        surfaces[0] = surface(SurfaceRole::Toplevel, 11, 4);
        release(&surfaces, &mut focus, 1);
        assert_eq!(focus, Some(2));
        focus = Some(0);
        acquire(&surfaces, &mut focus).unwrap();
        surfaces[0].live = false;
        release(&surfaces, &mut focus, 1);
        assert_eq!(focus, Some(2));
    }

    #[test]
    fn capture_does_not_bypass_process_modality_or_nest_another_panel() {
        let surfaces = [
            surface(SurfaceRole::Toplevel, 10, 1),
            surface(SurfaceRole::Panel, 20, 2),
            surface(SurfaceRole::Panel, 30, 3),
        ];
        for owner in [1, 2] {
            let mut focus = Some(0);
            let sessions = [ModalSession {
                owner_process: owner,
                modal_process: 4,
            }];
            assert!(
                set(
                    &surfaces,
                    &mut focus,
                    &sessions,
                    ClientId(2),
                    SurfaceHandle(20),
                    true
                )
                .is_err()
            );
            assert_eq!(focus, Some(0));
        }
        let mut focus = Some(2);
        assert!(acquire(&surfaces, &mut focus).is_err());
        assert_eq!(focus, Some(2));
    }

    #[test]
    fn release_preserves_an_unfocused_desktop_and_defers_to_new_protected_content() {
        let mut surfaces = [
            surface(SurfaceRole::Toplevel, 10, 1),
            surface(SurfaceRole::Panel, 20, 2),
        ];
        let mut focus = None;
        acquire(&surfaces, &mut focus).unwrap();
        release(&surfaces, &mut focus, 1);
        assert_eq!(focus, None);
        focus = Some(0);
        acquire(&surfaces, &mut focus).unwrap();
        surfaces[0].protected_presentation = true;
        release(&surfaces, &mut focus, 1);
        assert_eq!(focus, Some(0));
    }

    #[test]
    fn destroying_a_capturing_panel_restores_the_previous_window() {
        let mut surfaces = [
            surface(SurfaceRole::Toplevel, 10, 1),
            surface(SurfaceRole::Panel, 20, 2),
        ];
        let mut focus = Some(0);
        acquire(&surfaces, &mut focus).unwrap();
        crate::surface::destroy_surface_tree(
            &mut surfaces,
            &mut [],
            1,
            &mut None,
            &mut focus,
        );
        assert_eq!(focus, Some(0));
        assert!(!surfaces[1].live);
    }
}
