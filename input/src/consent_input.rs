//! A single authority-owned consent stream, independent of public subscribers.
use super::physical_input::Seat;
use mochi_user_platform as p;
use p::capability::{consent::Correlation, input_authority as wire};

#[derive(Default)]
pub(crate) struct Authority {
    seat: Seat,
    owner: Option<u64>,
    generation: u64,
    active: Option<Correlation>,
}
impl Authority {
    fn snapshot(&self) -> wire::Reply {
        wire::Reply {
            status: 0,
            generation: self.generation,
            serial: self.seat.serial(),
            all_released: self.seat.all_released(),
        }
    }
    pub fn control(&mut self, sender: u64, bytes: &[u8]) -> [u8; wire::REPLY_BYTES] {
        let result = (|| {
            // This Boolean is a kernel capability result, never request data.
            if sender == 0 || p::capability::check_thread(sender, "capabilities.manage") != Ok(1) {
                return Err(13);
            }
            let command = wire::decode_command(bytes).map_err(|_| 22u32)?;
            if !self.seat.available() {
                return Err(75);
            }
            if self.owner.is_some_and(|owner| owner != sender) {
                return Err(13);
            }
            match command {
                wire::Command::Register => {
                    if self.active.is_some() {
                        return Err(16);
                    }
                    self.generation = self.generation.checked_add(1).ok_or(75u32)?;
                    self.owner = Some(sender);
                }
                wire::Command::Arm {
                    generation,
                    correlation,
                } => {
                    if self.owner != Some(sender) || generation != self.generation {
                        return Err(13);
                    }
                    if self.active.is_some() {
                        return Err(16);
                    }
                    self.active = Some(correlation);
                }
                wire::Command::Cancel {
                    generation,
                    correlation,
                }
                | wire::Command::Status {
                    generation,
                    correlation,
                } => {
                    if self.owner != Some(sender) || generation != self.generation {
                        return Err(13);
                    }
                    if self.active != Some(correlation) {
                        return Err(2);
                    }
                    if matches!(command, wire::Command::Cancel { .. }) {
                        self.active = None;
                    }
                }
            }
            Ok(self.snapshot())
        })();
        wire::encode_reply(result.unwrap_or_else(wire::Reply::failure))
            .expect("validated authority reply")
    }
    pub fn reply_failed(&mut self, sender: u64) {
        if self.owner == Some(sender) {
            self.active = None;
        }
    }
    fn publish(&mut self, observation: Option<wire::Observation>) {
        if !self.seat.available() {
            self.active = None;
            return;
        }
        let (Some(correlation), Some(owner), Some(observation)) =
            (self.active, self.owner, observation)
        else {
            return;
        };
        let event = wire::Event {
            generation: self.generation,
            correlation,
            observation,
        };
        // Never retry stale evidence or silently resume after a lost event.
        // A final Status must still match before a consumer commits approval.
        if wire::encode_event(event).map_or(true, |bytes| p::ipc::send(owner, &bytes).is_err()) {
            self.active = None;
        }
    }
    pub fn keyboard(&mut self, byte: u8, synthetic: bool) {
        let observation = self.seat.keyboard(byte, synthetic);
        self.publish(observation);
    }
    pub fn pointer(&mut self, buttons: u8) {
        for observation in self.seat.pointer(buttons) {
            self.publish(observation);
        }
    }
}
