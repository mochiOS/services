//! Exercise the real request admission path, not a duplicate validator.
use super::*;
use crate::window::WindowId;

struct Fixture {
    clients: [Client; 1],
    surfaces: [Surface; 1],
    windows: [Window; 1],
    serials: [PointerSerial; 2],
    grab: Option<PointerGrab>,
}
impl Fixture {
    fn new() -> Self {
        let mut surface = Surface::empty();
        surface.live = true;
        surface.visible = true;
        surface.owner = ClientId(1);
        surface.handle = SurfaceHandle(11);
        surface.token = 11;
        surface.window = WindowId(7);
        surface.role = SurfaceRole::Toplevel;
        surface.rights = SurfaceRights::GENERAL_CLIENT;
        surface.width = 640;
        surface.height = 480;
        let mut window = Window::empty();
        window.live = true;
        window.id = WindowId(7);
        window.token = 99;
        window.content = surface.handle;
        Self {
            clients: [Client::default()],
            surfaces: [surface],
            windows: [window],
            serials: [PointerSerial::default(); 2],
            grab: None,
        }
    }
    fn call(&mut self, owner: u64, request: &[u8]) -> u32 {
        let mut next_z = 0;
        let mut pointer_focus = None;
        let mut keyboard_focus = None;
        let mut present = false;
        let reply = handle_request(
            &mut self.clients,
            &mut self.surfaces,
            &mut self.windows,
            &mut next_z,
            &mut self.serials,
            &mut pointer_focus,
            &mut keyboard_focus,
            &mut self.grab,
            100,
            100,
            ClientId(owner),
            owner,
            request,
            &mut present,
            1920,
            1080,
        );
        read_u32(&reply, 0).unwrap()
    }
    fn press(&mut self) {
        self.serials[0] = PointerSerial {
            serial: 73,
            window: WindowId(7),
            decoration: SurfaceHandle(11),
            used: false,
        };
    }
}
fn config() -> [u8; 32] {
    let mut bytes = [0; 32];
    put_u32(&mut bytes, 0, OP_SET_DECORATION);
    put_u64(&mut bytes, 4, 11);
    put_u32(&mut bytes, 12, 1);
    put_u32(&mut bytes, 16, 44);
    put_u32(&mut bytes, 20, 0x12345600);
    put_u32(&mut bytes, 24, 1024);
    put_u32(&mut bytes, 28, 3);
    bytes
}
fn gesture(op: u32, serial: u64, edge: u32) -> [u8; 28] {
    let mut bytes = [0; 28];
    put_u32(&mut bytes, 0, op);
    put_u64(&mut bytes, 4, 11);
    put_u64(&mut bytes, 12, serial);
    put_u32(&mut bytes, 20, edge);
    bytes
}
#[test]
fn decoration_configuration_is_owned_and_has_platform_minima() {
    let mut f = Fixture::new();
    let mut c = config();
    assert_ne!(f.call(2, &c), 0);
    assert!(!f.windows[0].integrated);
    put_u32(&mut c, 16, 1);
    put_u32(&mut c, 24, 2048);
    assert_eq!(f.call(1, &c), 0);
    assert!(f.windows[0].integrated);
    assert_eq!(
        f.windows[0].titlebar_height,
        metrics::physical_pixels(metrics::TITLE_BAR_HEIGHT, 2048)
    );
    assert_eq!(
        f.windows[0].controls_width,
        metrics::physical_pixels(metrics::CONTROLS_WIDTH, 2048)
    );
    assert_eq!(f.windows[0].insets.top, 0);
    assert_eq!(f.windows[0].titlebar_background & 255, 255);
}
#[test]
fn move_requires_a_live_owned_one_use_primary_press() {
    let mut f = Fixture::new();
    let request = gesture(OP_DECOR_BEGIN_MOVE, 73, 0);
    assert_ne!(f.call(1, &request), 0);
    assert!(f.grab.is_none());
    f.press();
    assert_ne!(f.call(2, &request), 0);
    assert!(f.grab.is_none());
    assert_eq!(f.call(1, &request), 0);
    assert!(f.grab.is_some());
    f.grab = None;
    assert_ne!(f.call(1, &request), 0);
    assert!(f.grab.is_none());
}
#[test]
fn an_expired_or_wrong_surface_press_does_not_authorize_a_move() {
    let mut f = Fixture::new();
    f.press();
    let request = gesture(OP_DECOR_BEGIN_MOVE, 73, 0);
    f.serials[0].used = true;
    assert_ne!(f.call(1, &request), 0);
    f.press();
    f.serials[0].decoration = SurfaceHandle(12);
    assert_ne!(f.call(1, &request), 0);
    f.press();
    f.serials[0].window = WindowId(8);
    assert_ne!(f.call(1, &request), 0);
}
#[test]
fn resize_obeys_window_constraints_and_rejects_invalid_edges() {
    let mut f = Fixture::new();
    f.press();
    f.windows[0].resizable = false;
    assert_ne!(f.call(1, &gesture(OP_DECOR_BEGIN_RESIZE, 73, 2)), 0);
    f.windows[0].resizable = true;
    assert_ne!(f.call(1, &gesture(OP_DECOR_BEGIN_RESIZE, 73, 3)), 0);
    assert_eq!(f.call(1, &gesture(OP_DECOR_BEGIN_RESIZE, 73, 10)), 0);
    assert_eq!(f.grab.unwrap().resize_edges, 10);
}
#[test]
fn system_mode_and_bad_configuration_values_remain_separate() {
    let mut f = Fixture::new();
    let mut c = config();
    put_u32(&mut c, 12, 2);
    assert_ne!(f.call(1, &c), 0);
    let mut c = config();
    put_u32(&mut c, 24, 0);
    assert_ne!(f.call(1, &c), 0);
    let mut c = config();
    put_u32(&mut c, 12, 0);
    assert_eq!(f.call(1, &c), 0);
    assert!(!f.windows[0].integrated);
    assert_eq!(f.windows[0].insets.top, 44);
}
