use std::sync::OnceLock;
use std::sync::atomic::{AtomicI8, Ordering};

use mochios_permission_prompt_protocol::StorageAction;
use viewkit::prelude::*;

static CONFIGURATION: OnceLock<PromptConfiguration> = OnceLock::new();
static DECISION: AtomicI8 = AtomicI8::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PromptConfiguration {
    pub(crate) application: String,
    pub(crate) action: StorageAction,
    pub(crate) target: String,
}

pub(crate) fn decide(configuration: PromptConfiguration) -> Result<bool, ViewKitError> {
    let _ = CONFIGURATION.set(configuration);
    DECISION.store(0, Ordering::Release);
    viewkit::run::<StoragePromptApp>()?;
    Ok(DECISION.load(Ordering::Acquire) > 0)
}

struct StoragePromptApp;

impl App for StoragePromptApp {
    type Body = Box<dyn View + 'static>;

    fn new() -> Self {
        Self
    }

    fn window(&self) -> WindowOptions {
        WindowOptions::new("Storage Confirmation")
            .size(540.0, 360.0)
            .resizable(false)
            .secure_overlay(true)
            .fullscreen(false)
    }

    fn body(&self, _context: &ViewContext) -> Self::Body {
        let Some(configuration) = CONFIGURATION.get().cloned() else {
            return Box::new(Text::new("Invalid storage request."));
        };
        let (title, message, action_label, action_style) = match configuration.action {
            StorageAction::Use => (
                format!("Allow {} to use this partition?", configuration.application),
                "The selected partition may be modified while mochiOS is installed.",
                "Allow",
                ButtonStyle::Accent,
            ),
            StorageAction::Create => (
                format!("Allow {} to create a partition?", configuration.application),
                "A new partition will be added to the selected disk.",
                "Allow",
                ButtonStyle::Accent,
            ),
            StorageAction::Delete => (
                "Delete this partition?".to_owned(),
                "The data stored on this partition will become inaccessible. This cannot be undone from Installer.app.",
                "Delete partition",
                ButtonStyle::Danger,
            ),
        };
        let prompt = Card::new()
            .content(
                Padding::all(32.0).content(
                    VStack::new()
                        .alignment(StackAlignment::Center)
                        .distribution(StackDistribution::Center)
                        .gap(StackGap::Large)
                        .child(Icon::new(IconName::HardDrive).size(44.0))
                        .child(
                            Text::new(title)
                                .font_size(20.0)
                                .line_height(28.0)
                                .weight(600)
                                .alignment(TextAlignment::Center),
                        )
                        .child(
                            Text::new(configuration.target.clone())
                                .font_size(12.0)
                                .line_height(20.0)
                                .weight(600)
                                .alignment(TextAlignment::Center),
                        )
                        .child(
                            Text::new(message)
                                .font_size(13.0)
                                .line_height(20.0)
                                .alignment(TextAlignment::Center)
                                .color(Theme::current().colors.text_secondary),
                        )
                        .child(
                            HStack::new()
                                .alignment(StackAlignment::Center)
                                .distribution(StackDistribution::Center)
                                .gap(StackGap::Medium)
                                .child(
                                    Button::new("Cancel")
                                        .style(ButtonStyle::Standard)
                                        .radius(CornerRadius::Full)
                                        .on_click(|| finish(false))
                                        .frame(132.0, 38.0),
                                )
                                .child(
                                    Button::new(action_label)
                                        .style(action_style)
                                        .radius(CornerRadius::Full)
                                        .on_click(|| finish(true))
                                        .frame(148.0, 38.0),
                                ),
                        ),
                ),
            )
            .frame(540.0, 360.0);
        Box::new(
            ZStack::new()
                .alignment(ZStackAlignment::Center)
                .child(Rectangle::new().color(RectangleColor::Custom(Color::rgba(0, 0, 0, 36))))
                .child(prompt),
        )
    }
}

fn finish(allowed: bool) {
    DECISION.store(if allowed { 1 } else { -1 }, Ordering::Release);
    viewkit::request_exit();
}
