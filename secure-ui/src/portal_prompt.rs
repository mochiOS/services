use std::sync::OnceLock;

use mochios_linux_portal_protocol::Access;
use viewkit::prelude::*;

const TARGET_PREFIX: &str = "--portal-target=";
const APP_PREFIX: &str = "--portal-application=";
const PATH_PREFIX: &str = "--portal-path=";
const ACCESS_PREFIX: &str = "--portal-access=";
static CONFIGURATION: OnceLock<PromptConfiguration> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PromptConfiguration {
    endpoint: u64,
    token: u64,
    application: String,
    path: String,
    writable: bool,
}

impl PromptConfiguration {
    pub(crate) fn from_arguments() -> Option<Self> {
        let mut endpoint = None;
        let mut token = None;
        let mut application = None;
        let mut path = None;
        let mut writable = None;
        for argument in std::env::args() {
            if let Some(value) = argument.strip_prefix(TARGET_PREFIX) {
                let (raw_endpoint, raw_token) = value.split_once(':')?;
                endpoint = raw_endpoint.parse().ok();
                token = raw_token.parse().ok();
            } else if let Some(value) = argument.strip_prefix(APP_PREFIX) {
                application = Some(value.to_owned());
            } else if let Some(value) = argument.strip_prefix(PATH_PREFIX) {
                path = Some(value.to_owned());
            } else if let Some(value) = argument.strip_prefix(ACCESS_PREFIX) {
                writable = match value {
                    "read" => Some(false),
                    "read-write" => Some(true),
                    _ => None,
                };
            }
        }
        let configuration = Self {
            endpoint: endpoint.filter(|value| *value != 0)?,
            token: token.filter(|value| *value != 0)?,
            application: application.filter(|value| !value.is_empty())?,
            path: path.filter(|value| mochios_linux_portal_protocol::valid_portal_path(value))?,
            writable: writable?,
        };
        Some(configuration)
    }

    fn access(&self) -> Access {
        if self.writable {
            Access::READ_WRITE
        } else {
            Access::READ
        }
    }
}

pub(crate) fn run(configuration: PromptConfiguration) -> Result<(), ViewKitError> {
    let _ = CONFIGURATION.set(configuration);
    viewkit::run::<PortalPromptApp>()
}

struct PortalPromptApp;

impl App for PortalPromptApp {
    type Body = Box<dyn View + 'static>;

    fn new() -> Self {
        Self
    }

    fn window(&self) -> WindowOptions {
        WindowOptions::new("File Access")
            .size(520.0, 330.0)
            .resizable(false)
            .secure_overlay(true)
    }

    fn body(&self, _context: &ViewContext) -> Self::Body {
        let Some(configuration) = CONFIGURATION.get().cloned() else {
            return Box::new(Text::new("Invalid permission request."));
        };
        let deny = configuration.clone();
        let allow = configuration.clone();
        let action = if configuration.access().writable() {
            "read and modify files in"
        } else {
            "read files in"
        };
        Box::new(
            Background::new()
                .background(Rectangle::new().color(RectangleColor::Surface))
                .content(Padding::all(32.0).content(
                    VStack::new()
                        .alignment(StackAlignment::Center)
                        .distribution(StackDistribution::Center)
                        .gap(StackGap::Large)
                        .child(Icon::new(IconName::FolderOpen).size(44.0))
                        .child(
                            Text::new(format!("Allow {} to access this folder?", configuration.application))
                                .font_size(20.0)
                                .line_height(28.0)
                                .weight(600)
                                .alignment(TextAlignment::Center),
                        )
                        .child(
                            Text::new(format!("This application wants to {action}:\n{}", configuration.path))
                                .font_size(13.0)
                                .line_height(20.0)
                                .alignment(TextAlignment::Center)
                                .color(Theme::DEFAULT.colors.text_secondary),
                        )
                        .child(
                            HStack::new()
                                .alignment(StackAlignment::Center)
                                .distribution(StackDistribution::Center)
                                .gap(StackGap::Medium)
                                .child(
                                    Button::new("Don't Allow")
                                        .style(ButtonStyle::Standard)
                                        .on_click(move || finish(&deny, false))
                                        .frame(132.0, 38.0),
                                )
                                .child(
                                    Button::new("Allow")
                                        .style(ButtonStyle::Accent)
                                        .on_click(move || finish(&allow, true))
                                        .frame(132.0, 38.0),
                                ),
                        ),
                )),
        )
    }
}

fn finish(configuration: &PromptConfiguration, allowed: bool) {
    let status = if allowed { 0 } else { -(mochi_user_syscall::EACCES as i32) };
    let message = mochi_user_platform::service_ready::notification(configuration.token, status);
    let _ = mochi_user_platform::ipc::send(configuration.endpoint, &message);
    viewkit::request_exit();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_mode_matches_prompt_semantics() {
        let read = PromptConfiguration {
            endpoint: 1,
            token: 2,
            application: "Editor".to_owned(),
            path: "/home/alice/Develop".to_owned(),
            writable: false,
        };
        assert_eq!(read.access(), Access::READ);
        assert_eq!(PromptConfiguration { writable: true, ..read }.access(), Access::READ_WRITE);
    }
}
