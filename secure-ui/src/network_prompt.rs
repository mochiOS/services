use std::sync::OnceLock;
use std::sync::atomic::{AtomicI8, Ordering};

use viewkit::prelude::*;

const APP_PREFIX: &str = "--network-application=";
static APPLICATION: OnceLock<String> = OnceLock::new();
static DECISION: AtomicI8 = AtomicI8::new(0);

pub(crate) fn from_arguments() -> Option<String> {
    std::env::args()
        .find_map(|argument| argument.strip_prefix(APP_PREFIX).map(str::to_owned))
        .filter(|application| !application.is_empty())
}

pub(crate) fn run(application: String) -> Result<(), ViewKitError> {
    if decide(application)? {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

pub(crate) fn decide(application: String) -> Result<bool, ViewKitError> {
    let _ = APPLICATION.set(application);
    DECISION.store(0, Ordering::Release);
    viewkit::run::<NetworkPromptApp>()?;
    Ok(DECISION.load(Ordering::Acquire) > 0)
}

struct NetworkPromptApp;

impl App for NetworkPromptApp {
    type Body = Box<dyn View + 'static>;

    fn new() -> Self {
        Self
    }

    fn window(&self) -> WindowOptions {
        WindowOptions::new("Network Access")
            .size(520.0, 330.0)
            .resizable(false)
            .secure_overlay(true)
            .fullscreen(false)
    }

    fn body(&self, _context: &ViewContext) -> Self::Body {
        let application = APPLICATION
            .get()
            .cloned()
            .unwrap_or_else(|| "This application".to_owned());
        Box::new(
            ZStack::new()
                .alignment(ZStackAlignment::Center)
                .child(
                    Rectangle::new()
                        .color(RectangleColor::Custom(Theme::current().shell.scrim)),
                )
                .child(
                    Dialog::new()
                        .accessibility_label("Network access permission")
                        .content(
                            VStack::new()
                                .alignment(StackAlignment::Center)
                                .distribution(StackDistribution::Center)
                                .gap(StackGap::Large)
                                .child(Icon::new(IconName::ExternalLink).size(44.0))
                                .child(Text::styled(
                                    format!("Allow {application} to access the network?"),
                                    TextRole::TitleMedium,
                                )
                                    .alignment(TextAlignment::Center))
                                .child(Text::styled(
                                    "The application can connect to public Internet services. Access to this device and private local networks remains blocked.",
                                    TextRole::Body,
                                )
                                    .alignment(TextAlignment::Center)
                                    .tone(TextTone::Secondary))
                                .child(HStack::new()
                                    .alignment(StackAlignment::Center)
                                    .distribution(StackDistribution::Center)
                                    .gap(StackGap::Medium)
                                    .child(Button::new("Don't Allow").style(ButtonStyle::Standard).size(ButtonSize::Medium).on_click(|| finish(false)).width(132.0))
                                    .child(Button::new("Allow").style(ButtonStyle::Accent).size(ButtonSize::Medium).on_click(|| finish(true)).width(132.0)))
                        )
                        .frame(520.0, 330.0)
                )
        )
    }
}

fn finish(allowed: bool) {
    DECISION.store(if allowed { 1 } else { -1 }, Ordering::Release);
    viewkit::request_exit();
}
