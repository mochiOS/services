//! Device-wide privacy choices, presented only by the authenticated secure UI.
use mochios_device_consent::{
    ConsentRecord, ConsentStore, DataCategory, DocumentReceipt, documents::Documents,
};
use std::{
    path::Path,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};
use viewkit::prelude::*;

const LEGAL_ROOT: &str = "/system/resources/legal";
const TITLES: [&str; 7] = [
    "Terms of Use",
    "Privacy Policy",
    "Open Source Licenses",
    "Usage & Diagnostics",
    "Crash Reports",
    "Update Results",
    "Privacy Summary",
];

#[derive(Clone, Debug, PartialEq)]
struct Draft {
    page: usize,
    record: ConsentRecord,
    choices: [Option<bool>; 3],
}
impl Draft {
    fn new(record: ConsentRecord) -> Self {
        Self {
            page: 0,
            record,
            choices: [None; 3],
        }
    }
    fn advance(&mut self, docs: &Documents, now: u64) -> Result<(), &'static str> {
        if now < 1_577_836_800 {
            return Err("Set the correct date and time before saving privacy choices.");
        }
        match self.page {
            0 => self.record.terms = Some(docs.receipt("terms.txt", now)),
            1 => self.record.privacy = Some(docs.receipt("privacy.txt", now)),
            2 => {
                self.record.open_source_licenses = Some(DocumentReceipt::new(
                    &docs.catalog.document_version,
                    &docs.license_bytes(),
                    now,
                ))
            }
            3..=5 => {
                let category = DataCategory::ALL[self.page - 3];
                let choice = self.choices[category.index()]
                    .ok_or("Choose Allow or Don't Allow to continue.")?;
                if docs.policy(category).version != category.policy_version() {
                    return Err("The installed privacy policy does not match this OS version.");
                }
                self.record
                    .set_permission(category, choice, category.policy_version(), now);
            }
            _ => return Err("Privacy choices are already complete."),
        }
        self.page += 1;
        Ok(())
    }
}

pub(crate) struct PrivacySetup {
    documents: Rc<Result<Documents, String>>,
    draft: State<Draft>,
    details: State<bool>,
    status: State<String>,
    pub(crate) finished: State<bool>,
}
impl PrivacySetup {
    pub(crate) fn needed() -> bool {
        let Ok(record) = ConsentStore::system().load() else {
            return true;
        };
        let Ok(docs) = Documents::load(Path::new(LEGAL_ROOT)) else {
            return true;
        };
        !record.complete()
            || !docs.legal_matches(&record)
            || DataCategory::ALL.into_iter().any(|c| {
                record
                    .permission(c)
                    .is_none_or(|p| p.policy_version != c.policy_version())
            })
    }
    pub(crate) fn new() -> Self {
        Self {
            documents: Rc::new(Documents::load(Path::new(LEGAL_ROOT)).map_err(|_| "Privacy documents could not be loaded. No new data sharing permission will be saved.".to_owned())),
            draft: State::new(Draft::new(ConsentStore::system().load().unwrap_or_default())), details: State::new(false), status: State::new(String::new()), finished: State::new(!Self::needed()),
        }
    }
    pub(crate) fn body(&self) -> Box<dyn View + 'static> {
        let draft = self.draft.get();
        let page = draft.page;
        let mut content = VStack::new()
            .alignment(StackAlignment::Stretch)
            .gap(StackGap::Medium)
            .child(Text::styled(TITLES[page], TextRole::TitleMedium));
        if let Ok(docs) = self.documents.as_ref() {
            let body = match page {
                0 => docs.text("terms.txt").to_owned(),
                1 => docs.text("privacy.txt").to_owned(),
                2 => docs
                    .catalog
                    .licenses
                    .iter()
                    .map(|l| {
                        format!(
                            "{} — {}\n{}\n{}",
                            l.name,
                            l.license,
                            docs.text(&l.copyright_file),
                            docs.text(&l.body_file)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n"),
                3..=5 => {
                    let category = DataCategory::ALL[page - 3];
                    let disclosure = docs.disclosure(category, "en");
                    let mut body = docs.text(&disclosure.summary_file).to_owned();
                    if self.details.get() {
                        for field in &disclosure.fields {
                            body.push_str(&format!(
                                "\n\n{}\n{}",
                                field.title,
                                docs.text(&field.file)
                            ));
                        }
                    }
                    body
                }
                _ => DataCategory::ALL
                    .into_iter()
                    .map(|c| {
                        format!(
                            "{}: {}",
                            TITLES[3 + c.index()],
                            if draft.choices[c.index()] == Some(true) {
                                "Allow"
                            } else {
                                "Don't Allow"
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n"),
            };
            content =
                content.child(Scroll::vertical(Text::body(body).width(500.0)).frame(520.0, 220.0));
            if (3..=5).contains(&page) {
                let category = DataCategory::ALL[page - 3];
                let details = self.details.clone();
                content = content.child(Text::caption(
                    "Optional. Declining does not prevent you from using mochiOS.",
                ));
                if category == DataCategory::CrashReports {
                    content = content.child(Text::caption("Crash uploading is not connected in this version. This choice does not send local crash reports."));
                }
                content = content.child(
                    Button::new(if self.details.get() {
                        "Hide Details"
                    } else {
                        "Show Details"
                    })
                    .style(ButtonStyle::Ghost)
                    .on_click(move || details.set(!details.get())),
                );
                let mut choices = HStack::new().gap(StackGap::Medium);
                for (label, value) in [("Allow", true), ("Don't Allow", false)] {
                    let state = self.draft.clone();
                    choices = choices.child(
                        Button::new(label)
                            .style(if draft.choices[category.index()] == Some(value) {
                                ButtonStyle::Accent
                            } else {
                                ButtonStyle::Standard
                            })
                            .size(ButtonSize::Large)
                            .on_click(move || {
                                let mut d = state.get();
                                d.choices[category.index()] = Some(value);
                                state.set(d);
                            })
                            .width(240.0),
                    );
                }
                content = content.child(choices);
            }
            let state = self.draft.clone();
            let documents = self.documents.clone();
            let status = self.status.clone();
            let details = self.details.clone();
            let finished = self.finished.clone();
            let enabled = !(3..=5).contains(&page) || draft.choices[page - 3].is_some();
            content = content.child(Button::new(match page {0 => "Agree and Continue", 1 | 2 => "Confirm and Continue", 6 => "Save Choices", _ => "Continue"}).style(ButtonStyle::Accent).size(ButtonSize::Large).enabled(enabled).on_click(move || {
                let Ok(docs) = documents.as_ref() else { return; };
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|v| v.as_secs()).unwrap_or(0);
                let mut draft = state.get();
                if draft.page == 6 {
                    match ConsentStore::system().save(&draft.record) {
                        Ok(()) => { mochi_user_platform::logln!("secure-ui: device privacy choices saved"); finished.set(true); }
                        Err(_) => status.set("Privacy choices could not be saved. Try again or continue without changing data sharing.".into()),
                    }
                } else {
                    match draft.advance(docs, now) { Ok(()) => {state.set(draft); details.set(false); status.set(String::new());}, Err(message) => status.set(message.into()) }
                }
            }));
            if page > 0 {
                let state = self.draft.clone();
                let details = self.details.clone();
                content = content.child(Button::new("Back").style(ButtonStyle::Ghost).on_click(
                    move || {
                        let mut d = state.get();
                        d.page -= 1;
                        state.set(d);
                        details.set(false);
                    },
                ));
            }
        } else if let Err(error) = self.documents.as_ref() {
            content = content.child(Text::body(error.clone()));
        }
        let finished = self.finished.clone();
        content = content.child(Text::caption(self.status.get())).child(
            Button::new("Not Now")
                .style(ButtonStyle::Ghost)
                .on_click(move || finished.set(true)),
        );
        Box::new(Dialog::new().content(content))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn docs() -> Documents {
        Documents::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../applications/installer/legal"),
        )
        .unwrap()
    }
    #[test]
    fn selecting_a_choice_does_not_commit_or_advance() {
        let mut d = Draft::new(ConsentRecord::default());
        let docs = docs();
        for _ in 0..3 {
            d.advance(&docs, 1_800_000_000).unwrap();
        }
        assert!(d.advance(&docs, 1_800_000_000).is_err());
        d.choices[0] = Some(true);
        assert_eq!(d.page, 3);
        assert!(d.record.usage_diagnostics.is_none());
        d.advance(&docs, 1_800_000_000).unwrap();
        assert!(
            d.record
                .permission(DataCategory::UsageDiagnostics)
                .unwrap()
                .agreed()
        );
        assert!(d.record.update_results.is_none());
    }
    #[test]
    fn independent_choices_and_exact_legal_receipts_survive_back_navigation() {
        let docs = docs();
        let mut d = Draft::new(ConsentRecord::default());
        for _ in 0..3 {
            d.advance(&docs, 1_800_000_000).unwrap();
        }
        for (i, value) in [true, false, false].into_iter().enumerate() {
            d.choices[i] = Some(value);
            d.advance(&docs, 1_800_000_000).unwrap();
        }
        assert!(docs.legal_matches(&d.record));
        assert!(d.record.complete());
        assert!(
            d.record
                .allows(DataCategory::UsageDiagnostics, "placeholder-2")
        );
        assert!(
            !d.record
                .allows(DataCategory::UpdateResults, "placeholder-2")
        );
        d.page = 3;
        d.choices[0] = Some(false);
        d.advance(&docs, 1_800_000_001).unwrap();
        assert!(
            !d.record
                .allows(DataCategory::UsageDiagnostics, "placeholder-2")
        );
        assert!(
            !d.record
                .permission(DataCategory::UpdateResults)
                .unwrap()
                .agreed()
        );
    }
    #[test]
    fn reviewing_choices_keeps_revisions_monotonic_even_in_the_same_second() {
        let docs = docs();
        let mut initial = Draft::new(ConsentRecord::default());
        for _ in 0..3 {
            initial.advance(&docs, 1_800_000_000).unwrap();
        }
        for i in 0..3 {
            initial.choices[i] = Some(true);
            initial.advance(&docs, 1_800_000_000).unwrap();
        }
        let before = initial
            .record
            .permission(DataCategory::UsageDiagnostics)
            .unwrap()
            .revision;
        let mut changed = Draft::new(initial.record);
        for _ in 0..3 {
            changed.advance(&docs, 1_800_000_000).unwrap();
        }
        changed.choices[0] = Some(false);
        changed.advance(&docs, 1_800_000_000).unwrap();
        assert!(
            changed
                .record
                .permission(DataCategory::UsageDiagnostics)
                .unwrap()
                .revision
                > before
        );
        assert!(
            !changed
                .record
                .allows(DataCategory::UsageDiagnostics, "placeholder-2")
        );
    }
    #[test]
    fn invalid_clock_cannot_create_receipts() {
        let mut d = Draft::new(ConsentRecord::default());
        assert!(d.advance(&docs(), 0).is_err());
        assert!(d.record.terms.is_none());
    }
}
