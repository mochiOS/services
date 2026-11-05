//! ViewKit presentation of the common broker-owned execution question.
//! Selecting a button is a proposal only. The capability broker, not this
//! view, validates scanout/focus, physical input and the final one-shot grant.
use mochi_user_platform::capability::consent::{Choice, Correlation, prompt};
use std::rc::Rc;
use viewkit::prelude::*;

pub struct Presentation {
    bytes: Vec<u8>,
}

impl Presentation {
    /// The caller must authenticate the broker transport before constructing
    /// this view. Neither command-line labels nor stdin supply this payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, mochi_user_platform::capability::consent::Error> {
        prompt::decode(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn binding(&self) -> viewkit::platform::ProtectedPresentation {
        let correlation = prompt::decode(&self.bytes).unwrap().correlation;
        viewkit::platform::ProtectedPresentation {
            ticket: correlation.ticket.id,
            challenge: correlation.ticket.challenge,
            display: correlation.display,
        }
    }

    /// Use this binding with App::protected_presentation_for_window. A
    /// rendered view alone must not be reported as protected scanout.
    pub fn content(&self, propose: impl Fn(Correlation, Choice) + 'static) -> Box<dyn View> {
        let offer = prompt::decode(&self.bytes).unwrap();
        let propose = Rc::new(propose);
        let mut requirements = VStack::new().gap(StackGap::Small);
        for name in offer.capabilities() {
            requirements = requirements.child(Text::styled(name.to_owned(), TextRole::Body));
        }
        let mut actions = HStack::new().gap(StackGap::Medium);
        for choice in [
            Choice::Deny,
            Choice::AllowOnce,
            Choice::AllowForProcess,
            Choice::AllowPersistently,
        ] {
            let Some(label) = offer.label(choice) else {
                continue;
            };
            let propose = propose.clone();
            let correlation = offer.correlation;
            actions = actions.child(
                Button::new(label)
                    .style(if choice == Choice::Deny {
                        ButtonStyle::Standard
                    } else {
                        ButtonStyle::Accent
                    })
                    .on_click(move || propose(correlation, choice)),
            );
        }
        let digest = offer
            .source_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Box::new(
            Dialog::new()
                .accessibility_label("Application capability permission")
                .on_dismiss(move || propose(offer.correlation, Choice::Deny))
                .content(
                    VStack::new()
                        .alignment(StackAlignment::Center)
                        .distribution(StackDistribution::Center)
                        .gap(StackGap::Large)
                        .child(Text::styled(
                            format!("Allow {} to use these capabilities?", offer.package),
                            TextRole::TitleMedium,
                        ))
                        .child(requirements)
                        .child(
                            Text::styled(format!("Source SHA-256: {digest}"), TextRole::Body)
                                .tone(TextTone::Secondary),
                        )
                        .child(actions),
                ),
        )
    }
}
