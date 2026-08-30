use std::sync::OnceLock;

use viewkit::prelude::*;

const ARGUMENT_PREFIX: &str = "--iommu-warning=";
static TECHNOLOGY: OnceLock<Technology> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Technology {
    IntelVtd,
    AmdVi,
}

impl Technology {
    const fn name(self) -> &'static str {
        match self {
            Self::IntelVtd => "VT-d",
            Self::AmdVi => "AMD-Vi",
        }
    }
}

pub(crate) fn from_arguments() -> Option<Technology> {
    std::env::args().find_map(|argument| match argument.strip_prefix(ARGUMENT_PREFIX)? {
        "intel" => Some(Technology::IntelVtd),
        "amd" => Some(Technology::AmdVi),
        _ => None,
    })
}

pub(crate) fn run(technology: Technology) -> Result<(), ViewKitError> {
    let _ = TECHNOLOGY.set(technology);
    viewkit::run::<VirtualizationWarningApp>()
}

struct VirtualizationWarningApp;

impl App for VirtualizationWarningApp {
    type Body = Box<dyn View + 'static>;

    fn new() -> Self {
        Self
    }

    fn window(&self) -> WindowOptions {
        WindowOptions::new("Hardware acceleration unavailable")
            .size(520.0, 300.0)
            .resizable(false)
            .secure_overlay(true)
            .fullscreen(false)
    }

    fn body(&self, _context: &ViewContext) -> Self::Body {
        let technology = TECHNOLOGY.get().copied().unwrap_or(Technology::IntelVtd);
        let name = technology.name();
        Box::new(Card::new().content(
            Padding::all(32.0).content(
                VStack::new()
                    .alignment(StackAlignment::Center)
                    .distribution(StackDistribution::Center)
                    .gap(StackGap::Large)
                    .child(Icon::new(IconName::Settings).size(44.0))
                    .child(
                        Text::new(format!("{name} is unavailable."))
                            .font_size(21.0)
                            .line_height(29.0)
                            .weight(600)
                            .alignment(TextAlignment::Center),
                    )
                    .child(
                        Text::new(format!(
                            "Hardware acceleration has been disabled because {name} is not available on this CPU or in firmware."
                        ))
                        .font_size(13.0)
                        .line_height(20.0)
                        .alignment(TextAlignment::Center)
                        .color(Theme::current().colors.text_secondary),
                    )
                    .child(
                        Button::new("OK")
                            .style(ButtonStyle::Accent)
                            .radius(CornerRadius::Full)
                            .on_click(viewkit::request_exit)
                            .frame(120.0, 38.0),
                    ),
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technology_names_are_user_facing() {
        assert_eq!(Technology::IntelVtd.name(), "VT-d");
        assert_eq!(Technology::AmdVi.name(), "AMD-Vi");
    }
}
