//! Text acceptance needs the authority's actual shortcut then a new Enter.
//! Renderer key events, text/paste and buffered PTY bytes never enter here.
use mochi_user_platform::capability::{
    consent::Choice,
    input_authority::{Observation, Transition},
};
#[derive(Default)]
pub(crate) struct Evidence {
    selected: Option<Choice>,
    confirmed: Option<Choice>,
    released: bool,
}
impl Evidence {
    pub fn arm(&mut self, released: bool) {
        *self = Self {
            released,
            ..Self::default()
        };
    }
    pub fn observe(&mut self, event: Observation) {
        match event.transition {
            Transition::AllReleased => self.released = true,
            Transition::PhysicalPress => {
                self.confirmed = None;
                if self.released {
                    match event.control {
                        0x15 => self.selected = Some(Choice::AllowOnce),
                        0x1e => self.selected = Some(Choice::AllowPersistently),
                        0x1c | 0x9c => self.confirmed = self.selected.take(),
                        _ => self.selected = None,
                    }
                } else {
                    self.selected = None;
                }
                self.released = false;
            }
            Transition::Release => {}
            Transition::Repeat | Transition::Synthetic => {
                self.selected = None;
                self.confirmed = None;
            }
        }
    }
    pub fn accepts(&self, choice: Choice) -> bool {
        self.confirmed == Some(choice)
    }
}
