use mochi_user_platform as platform;
use plugkit::PciConfig;
use plugkit::virtio::{
    CapabilityRegion, PciAddress, PciBar, PciConfigIo, PciTransportAccess, VirtioError,
    VirtioPciCapabilities, VirtioResult, find_pci_device,
};

use super::super::model::{VIRTIO_CONSOLE_DEVICE_ID, VIRTIO_VENDOR_ID};

const PCI_CONFIG_ADDRESS: u16 = 0x0cf8;
const PCI_CONFIG_DATA: u16 = 0x0cfc;
const MMIO_VIRTUAL_BASE: u64 = 0x0000_6300_0000_0000;
const MMIO_BAR_SPACING: u64 = 0x0200_0000;
const MAX_MAPPED_BAR_SIZE: u64 = 0x0100_0000;

struct PciPorts;

impl PciPorts {
    fn address(address: PciAddress, offset: u16) -> VirtioResult<u32> {
        if offset >= 256 || offset & 3 != 0 {
            return Err(VirtioError::AccessFailed);
        }
        Ok(0x8000_0000
            | (u32::from(address.bus) << 16)
            | (u32::from(address.device) << 11)
            | (u32::from(address.function) << 8)
            | u32::from(offset))
    }

    fn read(port: u16) -> VirtioResult<u32> {
        platform::syscall::call2(platform::syscall::SyscallNumber::PortIn, u64::from(port), 4)
            .map(|value| value as u32)
            .map_err(|_| VirtioError::AccessFailed)
    }

    fn write(port: u16, value: u32) -> VirtioResult<()> {
        platform::syscall::call3(
            platform::syscall::SyscallNumber::PortOut,
            u64::from(port),
            u64::from(value),
            4,
        )
        .map(|_| ())
        .map_err(|_| VirtioError::AccessFailed)
    }
}

impl PciConfigIo for PciPorts {
    fn read_u32(&mut self, address: PciAddress, offset: u16) -> VirtioResult<u32> {
        Self::write(PCI_CONFIG_ADDRESS, Self::address(address, offset)?)?;
        Self::read(PCI_CONFIG_DATA)
    }

    fn write_u32(&mut self, address: PciAddress, offset: u16, value: u32) -> VirtioResult<()> {
        Self::write(PCI_CONFIG_ADDRESS, Self::address(address, offset)?)?;
        Self::write(PCI_CONFIG_DATA, value)
    }
}

#[derive(Clone, Copy)]
struct Mapping {
    virtual_start: u64,
    register_base: u64,
    mapped_size: u64,
    register_size: u64,
}

pub(super) struct MappedBars {
    mappings: [Option<Mapping>; 6],
}

impl MappedBars {
    fn map(bars: &[PciBar], capabilities: VirtioPciCapabilities) -> VirtioResult<Self> {
        let mut mappings = [None; 6];
        for region in required_regions(capabilities).into_iter().flatten() {
            let index = usize::from(region.bar);
            if index >= mappings.len() {
                return Err(VirtioError::InvalidBar);
            }
            if mappings[index].is_some() {
                continue;
            }
            let bar = bars
                .iter()
                .find(|bar| bar.index == region.bar)
                .ok_or(VirtioError::InvalidBar)?;
            if bar.is_io || bar.size == 0 || bar.size > MAX_MAPPED_BAR_SIZE {
                return Err(VirtioError::InvalidBar);
            }
            let physical = bar.address & !0xfff;
            let page_offset = bar.address - physical;
            let mapped_size = align_page(
                bar.size
                    .checked_add(page_offset)
                    .ok_or(VirtioError::RegionOverflow)?,
            )?;
            let virtual_start = MMIO_VIRTUAL_BASE
                .checked_add(u64::from(region.bar) * MMIO_BAR_SPACING)
                .ok_or(VirtioError::RegionOverflow)?;
            platform::memory::map_physical_range(virtual_start, physical, mapped_size)
                .map_err(|_| VirtioError::AccessFailed)?;
            mappings[index] = Some(Mapping {
                virtual_start,
                register_base: virtual_start + page_offset,
                mapped_size,
                register_size: bar.size,
            });
        }
        Ok(Self { mappings })
    }

    fn pointer(&self, bar: u8, offset: u32, size: u64) -> VirtioResult<*mut u8> {
        let mapping = self
            .mappings
            .get(usize::from(bar))
            .and_then(|mapping| *mapping)
            .ok_or(VirtioError::InvalidBar)?;
        let end = u64::from(offset)
            .checked_add(size)
            .ok_or(VirtioError::RegionOverflow)?;
        if end > mapping.register_size {
            return Err(VirtioError::RegisterOutOfBounds);
        }
        Ok((mapping.register_base + u64::from(offset)) as *mut u8)
    }
}

impl PciTransportAccess for MappedBars {
    fn read_u8(&mut self, bar: u8, offset: u32) -> VirtioResult<u8> {
        // SAFETY: pointer validates the mapped BAR and complete register range.
        Ok(unsafe { core::ptr::read_volatile(self.pointer(bar, offset, 1)?) })
    }

    fn read_u16(&mut self, bar: u8, offset: u32) -> VirtioResult<u16> {
        // SAFETY: VirtIO PCI capability u16 registers are naturally aligned.
        Ok(u16::from_le(unsafe {
            core::ptr::read_volatile(self.pointer(bar, offset, 2)?.cast())
        }))
    }

    fn read_u32(&mut self, bar: u8, offset: u32) -> VirtioResult<u32> {
        // SAFETY: VirtIO PCI capability u32 registers are naturally aligned.
        Ok(u32::from_le(unsafe {
            core::ptr::read_volatile(self.pointer(bar, offset, 4)?.cast())
        }))
    }

    fn write_u8(&mut self, bar: u8, offset: u32, value: u8) -> VirtioResult<()> {
        // SAFETY: pointer validates the mapped BAR and complete register range.
        unsafe { core::ptr::write_volatile(self.pointer(bar, offset, 1)?, value) };
        Ok(())
    }

    fn write_u16(&mut self, bar: u8, offset: u32, value: u16) -> VirtioResult<()> {
        // SAFETY: VirtIO PCI capability u16 registers are naturally aligned.
        unsafe { core::ptr::write_volatile(self.pointer(bar, offset, 2)?.cast(), value.to_le()) };
        Ok(())
    }

    fn write_u32(&mut self, bar: u8, offset: u32, value: u32) -> VirtioResult<()> {
        // SAFETY: VirtIO PCI capability u32 registers are naturally aligned.
        unsafe { core::ptr::write_volatile(self.pointer(bar, offset, 4)?.cast(), value.to_le()) };
        Ok(())
    }
}

impl Drop for MappedBars {
    fn drop(&mut self) {
        for mapping in self.mappings.into_iter().flatten() {
            let _ = platform::memory::munmap(mapping.virtual_start, mapping.mapped_size);
        }
    }
}

pub(super) fn connect() -> VirtioResult<(VirtioPciCapabilities, MappedBars)> {
    let mut ports = PciPorts;
    let device = find_pci_device(&mut ports, VIRTIO_VENDOR_ID, VIRTIO_CONSOLE_DEVICE_ID)?
        .ok_or(VirtioError::QueueUnavailable)?;
    let bars = device.probe_bars(&mut ports)?;
    let config: PciConfig = device.read_config(&mut ports)?;
    let capabilities = VirtioPciCapabilities::parse(&config, &bars)?;
    let mapped = MappedBars::map(&bars, capabilities)?;
    device.enable_memory_and_bus_master(&mut ports)?;
    Ok((capabilities, mapped))
}

fn required_regions(capabilities: VirtioPciCapabilities) -> [Option<CapabilityRegion>; 4] {
    [
        Some(capabilities.common),
        Some(capabilities.notify),
        Some(capabilities.isr),
        capabilities.device,
    ]
}

fn align_page(value: u64) -> VirtioResult<u64> {
    value
        .checked_add(0xfff)
        .map(|value| value & !0xfff)
        .ok_or(VirtioError::RegionOverflow)
}
