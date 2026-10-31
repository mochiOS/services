//! Seat state comes only from admitted driver packets/device observations.
//! Synthetic bytes have a separate decoder and never release physical keys.
use mochi_user_platform::capability::input_authority::{Observation, Transition};

#[derive(Default)]
struct Prefix {
    extended: bool,
    pause_bytes: u8,
}
#[derive(Default)]
pub(crate) struct Seat {
    keys: [u64; 4],
    buttons: u8,
    physical: Prefix,
    synthetic: Prefix,
    serial: u64,
    exhausted: bool,
}
impl Seat {
    pub fn available(&self) -> bool {
        !self.exhausted
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    pub fn all_released(&self) -> bool {
        self.available() && self.buttons == 0 && self.keys == [0; 4]
    }
    fn observation(&mut self, transition: Transition, control: u16) -> Option<Observation> {
        let Some(serial) = self.serial.checked_add(1).filter(|_| !self.exhausted) else {
            self.exhausted = true;
            return None;
        };
        self.serial = serial;
        Some(Observation {
            serial,
            transition,
            control,
        })
    }
    pub fn keyboard(&mut self, byte: u8, synthetic: bool) -> Option<Observation> {
        let prefix = if synthetic {
            &mut self.synthetic
        } else {
            &mut self.physical
        };
        if prefix.pause_bytes != 0 {
            prefix.pause_bytes -= 1;
            return None;
        }
        if byte == 0xe1 {
            prefix.pause_bytes = 5;
            prefix.extended = false;
            return None;
        }
        if byte == 0xe0 {
            prefix.extended = true;
            return None;
        }
        let code = (byte & 0x7f) as usize + if prefix.extended { 128 } else { 0 };
        prefix.extended = false;
        if byte & 0x7f == 0 {
            return None;
        }
        let transition = if synthetic {
            Transition::Synthetic
        } else {
            let bit = 1u64 << (code % 64);
            let held = self.keys[code / 64] & bit != 0;
            if byte & 0x80 == 0 {
                self.keys[code / 64] |= bit;
                if held {
                    Transition::Repeat
                } else {
                    Transition::PhysicalPress
                }
            } else {
                self.keys[code / 64] &= !bit;
                if self.all_released() {
                    Transition::AllReleased
                } else {
                    Transition::Release
                }
            }
        };
        self.observation(transition, code as u16)
    }
    pub fn pointer(&mut self, buttons: u8) -> [Option<Observation>; 3] {
        let buttons = buttons & 7;
        let old = self.buttons;
        self.buttons = buttons;
        // Observe the entire report before emitting releases: swapping buttons
        // in one packet must not invent an intervening all-released snapshot.
        core::array::from_fn(|index| {
            let bit = 1 << index;
            if (old ^ buttons) & bit == 0 {
                return None;
            }
            let transition = if buttons & bit != 0 {
                Transition::PhysicalPress
            } else if self.all_released() {
                Transition::AllReleased
            } else {
                Transition::Release
            };
            self.observation(transition, 256 + index as u16)
        })
    }
}
