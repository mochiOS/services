//! Legacy PCI ownership is a userspace policy. The kernel only enforces
//! generic MMIO/port ranges supplied with verified image authorization.
use alloc::{format, string::String, vec::Vec};
use mochi_user_platform as platform;
use platform::syscall::{SysError, SyscallNumber};
use std::sync::{Mutex, OnceLock};

struct Device {
    address: u32,
    capability: &'static str,
    bars: [u32; 6],
    masks: [u32; 6],
    grants: Vec<String>,
}
static DEVICES: OnceLock<Mutex<Vec<Device>>> = OnceLock::new();
fn invalid() -> SysError {
    SysError::from_raw(-22)
}
fn denied() -> SysError {
    SysError::from_raw(-13)
}

fn read(address: u32, offset: u16) -> Result<u32, SysError> {
    platform::syscall::call3(
        SyscallNumber::PortOut,
        0xcf8,
        u64::from(0x8000_0000 | address | u32::from(offset)),
        4,
    )?;
    platform::syscall::call2(SyscallNumber::PortIn, 0xcfc, 4).map(|value| value as u32)
}
fn write(address: u32, offset: u16, value: u32) -> Result<(), SysError> {
    platform::syscall::call3(
        SyscallNumber::PortOut,
        0xcf8,
        u64::from(0x8000_0000 | address | u32::from(offset)),
        4,
    )?;
    platform::syscall::call3(SyscallNumber::PortOut, 0xcfc, u64::from(value), 4).map(|_| ())
}
fn owned_by_mboot() -> bool {
    // mBoot's hardware domain owns physical configuration. Never probe it
    // from the System domain, whose devices use the mediated transport.
    let leaf = unsafe { core::arch::x86_64::__cpuid(0x4000_0000) };
    let mut vendor = [0; 12];
    vendor[..4].copy_from_slice(&leaf.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf.ecx.to_le_bytes());
    vendor[8..].copy_from_slice(&leaf.edx.to_le_bytes());
    vendor == *b"MochiOSmBoot"
}
fn class(address: u32, id: u32) -> Result<Option<&'static str>, SysError> {
    let class = read(address, 8)? >> 8;
    Ok(if class >> 16 == 3 {
        Some("device.gpu")
    } else if class >> 16 == 2 {
        Some("device.net")
    } else if class >> 8 == 0x0c03 {
        Some("usb.access")
    } else if id as u16 == 0x1af4 && matches!((id >> 16) as u16, 0x1003 | 0x1043) {
        Some("serial.access")
    } else {
        None
    })
}
fn probe(address: u32, capability: &'static str) -> Result<Device, SysError> {
    let mut device = Device {
        address,
        capability,
        bars: [0; 6],
        masks: [0; 6],
        grants: Vec::new(),
    };
    let command = read(address, 4)? as u16;
    // This is done once, before any driver is launched, under exclusive
    // configuration ownership. Do not write status W1C bits back to hardware.
    write(address, 4, u32::from(command & !7))?;
    let result = (|| {
        let mut index = 0;
        while index < 6 {
            let offset = 0x10 + index as u16 * 4;
            let low = read(address, offset)?;
            device.bars[index] = low;
            let wide = low & 7 == 4;
            if wide && index == 5 {
                return Err(invalid());
            }
            let high = if wide { read(address, offset + 4)? } else { 0 };
            if wide {
                device.bars[index + 1] = high;
            }
            if low == 0 && high == 0 {
                index += if wide { 2 } else { 1 };
                continue;
            }
            // Always restore both words even if a read fails.
            write(address, offset, u32::MAX)?;
            let mask_low = read(address, offset);
            let restore_low = write(address, offset, low);
            let mask_low = mask_low?;
            restore_low?;
            device.masks[index] = mask_low;
            let mask_high = if wide {
                write(address, offset + 4, u32::MAX)?;
                let mask = read(address, offset + 4);
                let restore = write(address, offset + 4, high);
                let mask = mask?;
                restore?;
                device.masks[index + 1] = mask;
                mask
            } else {
                0
            };
            let io = low & 1 != 0;
            if !io && !matches!(low & 6, 0 | 4) {
                index += 1;
                continue;
            }
            let base = u64::from(low & if io { !3 } else { !15 }) | (u64::from(high) << 32);
            let mask =
                u64::from(mask_low & if io { !3 } else { !15 }) | (u64::from(mask_high) << 32);
            let size = if wide {
                (!mask).wrapping_add(1)
            } else {
                u64::from((!(mask as u32)).wrapping_add(1))
            };
            if base != 0 && mask != 0 && size.is_power_of_two() && base & (size - 1) == 0 {
                let end = base.checked_add(size).ok_or_else(invalid)?;
                if io {
                    if end <= 65536 {
                        device.grants.push(format!("io.port@{base}:{size}"));
                    }
                } else {
                    let start = base & !4095;
                    let end = end.checked_add(4095).ok_or_else(invalid)? & !4095;
                    device
                        .grants
                        .push(format!("memory.phys.map@{start}:{}", end - start));
                }
            }
            index += if wide { 2 } else { 1 };
        }
        Ok(())
    })();
    let restore = write(address, 4, u32::from(command));
    result?;
    restore?;
    Ok(device)
}
pub(crate) fn initialize() -> Result<(), SysError> {
    let mut devices = Vec::new();
    if !owned_by_mboot() {
        for bus in 0..256u32 {
            for slot in 0..32u32 {
                let first = (bus << 16) | (slot << 11);
                let id = read(first, 0)?;
                if id as u16 == 0xffff {
                    continue;
                }
                let functions = if read(first, 0x0c)? & 0x0080_0000 != 0 {
                    8
                } else {
                    1
                };
                for function in 0..functions {
                    let address = first | (function << 8);
                    let id = read(address, 0)?;
                    if id as u16 == 0xffff || read(address, 0x0c)? & 0x007f_0000 != 0 {
                        continue;
                    }
                    if let Some(capability) = class(address, id)? {
                        devices
                            .try_reserve(1)
                            .map_err(|_| SysError::from_raw(-12))?;
                        devices.push(probe(address, capability)?);
                    }
                }
            }
        }
    }
    DEVICES.set(Mutex::new(devices)).map_err(|_| invalid())
}
pub(crate) fn grants(capabilities: &[String]) -> Result<Vec<String>, SysError> {
    let devices = DEVICES
        .get()
        .ok_or_else(invalid)?
        .lock()
        .map_err(|_| invalid())?;
    let mut result = capabilities.to_vec();
    for device in devices
        .iter()
        .filter(|device| capabilities.iter().any(|cap| cap == device.capability))
    {
        result.extend(device.grants.iter().cloned());
    }
    Ok(result)
}
pub(crate) fn request(sender: u64, bytes: &[u8]) -> Result<u32, SysError> {
    use platform::pci;
    if bytes.len() != 20 {
        return Err(invalid());
    }
    let word = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let (operation, address, offset, value) = (word(4), word(8), word(12), word(16));
    if address & !0x00ff_ff00 != 0 || offset >= 256 || offset & 3 != 0 {
        return Err(invalid());
    }
    let devices = DEVICES
        .get()
        .ok_or_else(invalid)?
        .lock()
        .map_err(|_| invalid())?;
    if operation == 3 && address == 0 && offset == 0 && value == 0 {
        let available = devices.iter().any(|device| {
            !device.grants.is_empty()
                && platform::capability::check_thread(sender, device.capability) == Ok(1)
                && device
                    .grants
                    .iter()
                    .all(|grant| platform::capability::check_thread(sender, grant) == Ok(1))
        });
        return Ok(u32::from(available));
    }
    let Some(device) = devices.iter().find(|device| device.address == address) else {
        return if operation == pci::READ {
            Ok(u32::MAX)
        } else {
            Err(denied())
        };
    };
    // A class name alone cannot access configuration. The exact assigned
    // resource authority must still belong to the authenticated sender image.
    let assigned = !device.grants.is_empty()
        && platform::capability::check_thread(sender, device.capability)? == 1
        && device
            .grants
            .iter()
            .all(|grant| platform::capability::check_thread(sender, grant) == Ok(1));
    if !assigned {
        return if operation == pci::READ {
            Ok(u32::MAX)
        } else {
            Err(denied())
        };
    }
    match operation {
        pci::READ => read(address, offset as u16),
        pci::BAR_MASK if (0x10..0x28).contains(&offset) => {
            Ok(device.masks[((offset - 0x10) / 4) as usize])
        }
        pci::WRITE
            if (0x10..0x28).contains(&offset)
                && value == device.bars[((offset - 0x10) / 4) as usize] =>
        {
            Ok(0)
        }
        pci::WRITE if offset == 4 => {
            let current = read(address, 4)?;
            if (value ^ current) & 0xfff8 != 0 {
                return Err(denied());
            }
            if value & 4 != 0 && platform::capability::check_thread(sender, "dma.allocate")? != 1 {
                return Err(denied());
            }
            write(address, 4, value & 0xffff)?;
            Ok(0)
        }
        _ => Err(denied()),
    }
}
