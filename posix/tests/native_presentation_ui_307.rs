//! Actual ViewKit renderer for the native compositor receipt probe.
use mochi_user_platform as p;
use p::capability::{
    consent::{self, Correlation, Feedback},
    presentation as w,
};
use std::sync::OnceLock;
use viewkit::prelude::*;
static BINDING: OnceLock<Correlation> = OnceLock::new();
pub fn run() -> Result<(), viewkit::ViewKitError> {
    let broker = p::process::find_by_name("capability.service").unwrap();
    let mut bytes = [0; consent::FEEDBACK_BYTES + w::RECEIPT_BYTES];
    let message = p::ipc::call(broker, b"PH07", &mut bytes).unwrap();
    assert_eq!(message >> 32, broker);
    assert_eq!(message as u32 as usize, bytes.len());
    let (correlation, feedback) = consent::decode(&bytes[..consent::FEEDBACK_BYTES]).unwrap();
    assert_eq!(feedback, Feedback::Presented);
    assert_eq!(
        w::decode_receipt(&bytes[consent::FEEDBACK_BYTES..])
            .unwrap()
            .stage,
        w::Stage::Pending
    );
    BINDING.set(correlation).unwrap();
    let target = p::service_ready::take_bootstrap_target().unwrap();
    let endpoint = p::ipc::create_handle().unwrap();
    p::service_ready::notify_handle(
        target,
        0,
        endpoint,
        p::handle::HANDLE_RIGHT_SEND
            | p::handle::HANDLE_RIGHT_DUPLICATE
            | p::handle::HANDLE_RIGHT_TRANSFER,
    )
    .unwrap();
    let result = viewkit::run::<ProbeApp>();
    let _ = p::handle::close(endpoint);
    result
}
struct ProbeApp;
impl App for ProbeApp {
    type Body = Box<dyn View + 'static>;
    fn new() -> Self {
        Self
    }
    fn window(&self) -> WindowOptions {
        WindowOptions::new("Protected presentation probe")
            .compact()
            .resizable(false)
            .secure_overlay(true)
    }
    fn protected_presentation_for_window(
        &self,
        _: viewkit::app::WindowId,
    ) -> Option<viewkit::platform::ProtectedPresentation> {
        let binding = *BINDING.get()?;
        Some(viewkit::platform::ProtectedPresentation {
            ticket: binding.ticket.id,
            challenge: binding.ticket.challenge,
            display: binding.display,
        })
    }
    fn body(&self, _: &ViewContext) -> Self::Body {
        Box::new(ZStack::new().alignment(ZStackAlignment::Center)
            .child(Rectangle::new().color(RectangleColor::Custom(Theme::current().shell.scrim)))
            .child(Dialog::new().content(VStack::new().alignment(StackAlignment::Center)
                .gap(StackGap::Large)
                .child(Text::styled("Protected presentation",TextRole::TitleMedium))
                .child(Text::new("Compositor verifies this frame.\nThis test never grants permissions.").alignment(TextAlignment::Center))
                .child(Button::new("Close").on_click(viewkit::request_exit)))))
    }
    fn first_frame_presented(&mut self) {
        println!("presentation-307: ViewKit submitted first frame; awaiting compositor evidence");
    }
}
