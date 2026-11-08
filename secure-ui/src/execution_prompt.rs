//! ViewKit presentation of the common broker-owned execution question.
//! Selecting a button is a proposal only. The capability broker, not this
//! view, validates scanout/focus, physical input and the final one-shot grant.
use mochi_user_platform::capability::{
    administrator,
    consent::{Choice, Correlation, prompt, question},
};
use std::rc::Rc;
use viewkit::prelude::*;
use zeroize::Zeroizing;

pub struct Presentation {
    bytes: Vec<u8>,
    username: TextFieldInteractionState,
    password: TextFieldInteractionState,
}

impl Presentation {
    /// The caller must authenticate the broker transport before constructing
    /// this view. Neither command-line labels nor stdin supply this payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, mochi_user_platform::capability::consent::Error> {
        let question = question::decode(bytes)?;
        let username = TextFieldInteractionState::new();
        let password = TextFieldInteractionState::new();
        if let Some(admin) = question.administrator {
            username.set_value(admin.username);
            password.set_focused(!admin.username.is_empty());
            username.set_focused(admin.username.is_empty());
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            username,
            password,
        })
    }

    pub fn binding(&self) -> viewkit::platform::ProtectedPresentation {
        let correlation = question::decode(&self.bytes).unwrap().offer.correlation;
        viewkit::platform::ProtectedPresentation {
            ticket: correlation.ticket.id,
            challenge: correlation.ticket.challenge,
            display: correlation.display,
        }
    }

    /// Use this binding with App::protected_presentation_for_window. A
    /// rendered view alone must not be reported as protected scanout.
    pub fn content(
        &self,
        propose: impl Fn(Correlation, Choice) + 'static,
        authenticate: impl Fn(&[u8]) -> bool + 'static,
    ) -> Box<dyn View> {
        let question = question::decode(&self.bytes).unwrap();
        let offer = question.offer;
        if let Some(admin) = question.administrator {
            let username = self.username.clone();
            let password = self.password.clone();
            let submit = Rc::new(move || {
                let name = username.value();
                // Borrow the field without clearing until arming/physical input
                // synchronization has succeeded; EAGAIN does not lose typing.
                let value = Zeroizing::new(password.value());
                let mut bytes = Zeroizing::new([0; administrator::MAX_CREDENTIAL_BYTES]);
                if let Ok(length) = administrator::encode_credentials(
                    administrator::Credentials {
                        correlation: offer.correlation,
                        name: &name,
                        password: value.as_bytes(),
                    },
                    &mut bytes[..],
                ) {
                    if authenticate(&bytes[..length]) {
                        password.clear();
                    }
                }
            });
            let on_enter = Rc::clone(&submit);
            let correlation = offer.correlation;
            let propose = Rc::new(propose);
            let cancel = Rc::clone(&propose);
            return Box::new(
                Dialog::new()
                    .accessibility_label("Administrator authentication")
                    .on_dismiss(move || cancel(correlation, Choice::Deny))
                    .content(
                        VStack::new()
                            .gap(StackGap::Large)
                            .child(Text::styled(
                                "Administrator authentication",
                                TextRole::TitleMedium,
                            ))
                            .child(Text::body(admin.description.to_owned()))
                            .child(
                                Text::body(format!("Application: {}", offer.package))
                                    .tone(TextTone::Secondary),
                            )
                            .child(
                                TextField::with_interaction(self.username.clone())
                                    .placeholder("Administrator account"),
                            )
                            .child(
                                TextField::with_interaction(self.password.clone())
                                    .placeholder("Password")
                                    .secure(true)
                                    .on_submit(move || on_enter()),
                            )
                            .child(
                                HStack::new()
                                    .gap(StackGap::Medium)
                                    .child(
                                        Button::new("Cancel")
                                            .on_click(move || propose(correlation, Choice::Deny)),
                                    )
                                    .child(
                                        Button::new("Authenticate")
                                            .style(ButtonStyle::Accent)
                                            .on_click(move || submit()),
                                    ),
                            ),
                    ),
            );
        }
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

impl Drop for Presentation {
    fn drop(&mut self) {
        self.password.clear();
    }
}
