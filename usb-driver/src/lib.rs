#![no_std]

extern crate alloc;

use alloc::format;
use core::ptr::{read_volatile, write_volatile};
use mochi_user_platform as platform;
use mochi_user_syscall as syscall;
use plugkit::prelude::*;

const PCI_CFG_ADDR: u16 = 0xCF8;
const PCI_CFG_DATA: u16 = 0xCFC;

const XHCI_PROG_IF: u8 = 0x30;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x2;
const MAP_ANONYMOUS: u64 = 0x20;

const XHCI_CAP_CAPLENGTH: usize = 0x00;
const XHCI_CAP_HCIVERSION: usize = 0x02;
const XHCI_CAP_HCSPARAMS1: usize = 0x04;
const XHCI_CAP_HCCPARAMS1: usize = 0x10;
const XHCI_CAP_DBOFF: usize = 0x14;
const XHCI_CAP_RTSOFF: usize = 0x18;

const XHCI_OP_USBCMD: usize = 0x00;
const XHCI_OP_USBSTS: usize = 0x04;
const XHCI_OP_PAGESIZE: usize = 0x08;
const XHCI_OP_CONFIG: usize = 0x38;
const XHCI_OP_PORTSC_BASE: usize = 0x400;
const XHCI_OP_PORTSC_STRIDE: usize = 0x10;

#[derive(Clone, Copy)]
struct PciLocation {
    bus: u8,
    device: u8,
    function: u8,
}

#[derive(Clone, Copy)]
struct XhciBar {
    phys_base: u64,
    size: u64,
}

struct MmioRegion {
    virt_base: usize,
    len: usize,
}

impl MmioRegion {
    fn map(phys_base: u64, len: u64) -> Result<Self, syscall::SysError> {
        let page_base = phys_base & !0xfff;
        let page_offset = (phys_base & 0xfff) as usize;
        let span = page_offset
            .checked_add(len as usize)
            .ok_or_else(|| syscall::SysError::from_raw(syscall::EINVAL as i64))?;
        let map_len = ((span + 0xfff) & !0xfff) as u64;
        let virt_base = platform::memory::mmap(
            0,
            map_len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            0,
        )?;
        platform::memory::map_physical_range(virt_base, page_base, map_len)?;
        Ok(Self {
            virt_base: virt_base as usize + page_offset,
            len: len as usize,
        })
    }

    fn read_u8(&self, offset: usize) -> u8 {
        debug_assert!(offset < self.len);
        // SAFETY: MMIO region was explicitly mapped read/write for this process.
        unsafe { read_volatile((self.virt_base + offset) as *const u8) }
    }

    fn read_u16(&self, offset: usize) -> u16 {
        debug_assert!(offset + 2 <= self.len);
        // SAFETY: MMIO region was explicitly mapped read/write for this process.
        unsafe { read_volatile((self.virt_base + offset) as *const u16) }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        debug_assert!(offset + 4 <= self.len);
        // SAFETY: MMIO region was explicitly mapped read/write for this process.
        unsafe { read_volatile((self.virt_base + offset) as *const u32) }
    }

    #[allow(dead_code)]
    fn write_u32(&self, offset: usize, value: u32) {
        debug_assert!(offset + 4 <= self.len);
        // SAFETY: MMIO region was explicitly mapped read/write for this process.
        unsafe { write_volatile((self.virt_base + offset) as *mut u32, value) }
    }
}

fn port_in(port: u16, width: u64) -> Result<u64, syscall::SysError> {
    syscall::call2(syscall::SyscallNumber::PortIn, port as u64, width)
}

fn port_out(port: u16, value: u64, width: u64) -> Result<u64, syscall::SysError> {
    syscall::call3(syscall::SyscallNumber::PortOut, port as u64, value, width)
}

fn pci_config_address(loc: PciLocation, offset: u8) -> u32 {
    0x8000_0000
        | ((loc.bus as u32) << 16)
        | ((loc.device as u32) << 11)
        | ((loc.function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

fn pci_read_u32(loc: PciLocation, offset: u8) -> Option<u32> {
    let addr = pci_config_address(loc, offset);
    port_out(PCI_CFG_ADDR, addr as u64, 4).ok()?;
    let value = port_in(PCI_CFG_DATA, 4).ok()?;
    Some(value as u32)
}

fn pci_write_u32(loc: PciLocation, offset: u8, value: u32) -> bool {
    let addr = pci_config_address(loc, offset);
    port_out(PCI_CFG_ADDR, addr as u64, 4).is_ok()
        && port_out(PCI_CFG_DATA, value as u64, 4).is_ok()
}

fn pci_read_u16(loc: PciLocation, offset: u8) -> Option<u16> {
    let aligned = offset & !0x3;
    let shift = ((offset & 0x2) as u32) * 8;
    pci_read_u32(loc, aligned).map(|v| ((v >> shift) & 0xFFFF) as u16)
}

fn pci_write_u16(loc: PciLocation, offset: u8, value: u16) -> bool {
    let aligned = offset & !0x3;
    let shift = ((offset & 0x2) as u32) * 8;
    let Some(mut current) = pci_read_u32(loc, aligned) else {
        return false;
    };
    current &= !(0xFFFFu32 << shift);
    current |= (value as u32) << shift;
    pci_write_u32(loc, aligned, current)
}

fn pci_read_u8(loc: PciLocation, offset: u8) -> Option<u8> {
    let aligned = offset & !0x3;
    let shift = ((offset & 0x3) as u32) * 8;
    pci_read_u32(loc, aligned).map(|v| ((v >> shift) & 0xFF) as u8)
}

fn pci_command_enable_memory_and_bus_master(loc: PciLocation) {
    if let Some(command) = pci_read_u16(loc, 0x04) {
        let updated = command | 0x0006;
        let _ = pci_write_u16(loc, 0x04, updated);
    }
}

fn probe_mem_bar(loc: PciLocation, bar_idx: u8) -> Option<XhciBar> {
    if bar_idx >= 6 {
        return None;
    }
    let offset = 0x10 + bar_idx * 4;
    let original_low = pci_read_u32(loc, offset)?;
    if (original_low & 0x1) != 0 {
        return None;
    }

    let bar_type = (original_low >> 1) & 0x3;
    let is_64 = bar_type == 0x2;
    let original_high = if is_64 {
        if bar_idx + 1 >= 6 {
            return None;
        }
        pci_read_u32(loc, offset + 4)?
    } else {
        0
    };

    if !pci_write_u32(loc, offset, 0xffff_ffff) {
        return None;
    }
    if is_64 && !pci_write_u32(loc, offset + 4, 0xffff_ffff) {
        let _ = pci_write_u32(loc, offset, original_low);
        return None;
    }

    let mask_low = pci_read_u32(loc, offset)?;
    let mask_high = if is_64 {
        pci_read_u32(loc, offset + 4)?
    } else {
        0
    };

    let _ = pci_write_u32(loc, offset, original_low);
    if is_64 {
        let _ = pci_write_u32(loc, offset + 4, original_high);
    }

    let base = if is_64 {
        ((original_high as u64) << 32) | ((original_low & 0xffff_fff0) as u64)
    } else {
        (original_low & 0xffff_fff0) as u64
    };
    if base == 0 {
        return None;
    }

    let mask = if is_64 {
        ((mask_high as u64) << 32) | ((mask_low & 0xffff_fff0) as u64)
    } else {
        (mask_low & 0xffff_fff0) as u64
    };
    let size_mask = mask & !0xf;
    if size_mask == 0 {
        return None;
    }
    let size = (!size_mask).wrapping_add(1);
    if size == 0 {
        return None;
    }

    Some(XhciBar {
        phys_base: base,
        size,
    })
}

fn find_xhci_bar(loc: PciLocation) -> Option<XhciBar> {
    let mut bar_idx = 0u8;
    while bar_idx < 6 {
        let offset = 0x10 + bar_idx * 4;
        let value = pci_read_u32(loc, offset)?;
        if (value & 0x1) == 0 && let Some(bar) = probe_mem_bar(loc, bar_idx) {
            return Some(bar);
        }
        let bar_type = (value >> 1) & 0x3;
        bar_idx += if bar_type == 0x2 { 2 } else { 1 };
    }
    None
}

fn xhci_port_speed_name(speed_id: u32) -> &'static str {
    match speed_id {
        0 => "unknown",
        1 => "full",
        2 => "low",
        3 => "high",
        4 => "super",
        5 => "super+",
        _ => "reserved",
    }
}

fn enumerate_xhci_controller(loc: PciLocation, bar: XhciBar, vendor: u16, device: u16) {
    pci_command_enable_memory_and_bus_master(loc);

    let map_len = core::cmp::min(bar.size, 0x10000);
    let mmio = match MmioRegion::map(bar.phys_base, map_len) {
        Ok(region) => region,
        Err(_) => {
            platform::println!(
                "usb-driver: failed to map xHCI MMIO bar phys=0x{:016x} size=0x{:x}",
                bar.phys_base,
                bar.size
            );
            return;
        }
    };

    let cap_length = mmio.read_u8(XHCI_CAP_CAPLENGTH) as usize;
    let hci_version = mmio.read_u16(XHCI_CAP_HCIVERSION);
    let hcsparams1 = mmio.read_u32(XHCI_CAP_HCSPARAMS1);
    let hccparams1 = mmio.read_u32(XHCI_CAP_HCCPARAMS1);
    let dboff = mmio.read_u32(XHCI_CAP_DBOFF) & !0x3;
    let rtsoff = mmio.read_u32(XHCI_CAP_RTSOFF) & !0x1f;
    let max_slots = hcsparams1 & 0xff;
    let max_intrs = (hcsparams1 >> 8) & 0x7ff;
    let max_ports = (hcsparams1 >> 24) & 0xff;

    let usbcmd = mmio.read_u32(cap_length + XHCI_OP_USBCMD);
    let usbsts = mmio.read_u32(cap_length + XHCI_OP_USBSTS);
    let pagesize = mmio.read_u32(cap_length + XHCI_OP_PAGESIZE);
    let config = mmio.read_u32(cap_length + XHCI_OP_CONFIG);

    platform::println!(
        "usb-driver: PCI USB controller bus={:02x} dev={:02x} func={} vendor=0x{:04x} device=0x{:04x} class=0x0c subclass=0x03 prog_if=0x{:02x} header=0x{:02x}",
        loc.bus,
        loc.device,
        loc.function,
        vendor,
        device,
        XHCI_PROG_IF,
        pci_read_u8(loc, 0x0E).unwrap_or(0),
    );
    platform::println!(
        "usb-driver: xhci controller bus={:02x} dev={:02x} func={} vendor=0x{:04x} device=0x{:04x} mmio_base=0x{:016x} mmio_size=0x{:x}",
        loc.bus,
        loc.device,
        loc.function,
        vendor,
        device,
        bar.phys_base,
        bar.size
    );
    platform::println!(
        "usb-driver: xhci caplen=0x{:02x} hci=0x{:04x} slots={} intrs={} ports={} hcc=0x{:08x} dboff=0x{:x} rtsoff=0x{:x}",
        cap_length,
        hci_version,
        max_slots,
        max_intrs,
        max_ports,
        hccparams1,
        dboff,
        rtsoff
    );
    platform::println!(
        "usb-driver: xhci usbcmd=0x{:08x} usbsts=0x{:08x} pagesize=0x{:08x} config=0x{:08x}",
        usbcmd,
        usbsts,
        pagesize,
        config
    );

    for port_index in 0..max_ports as usize {
        let offset = cap_length + XHCI_OP_PORTSC_BASE + port_index * XHCI_OP_PORTSC_STRIDE;
        if offset + 4 > mmio.len {
            break;
        }
        let portsc = mmio.read_u32(offset);
        let connected = (portsc & 0x1) != 0;
        let enabled = (portsc & 0x2) != 0;
        let over_current = (portsc & 0x8) != 0;
        let reset = (portsc & 0x10) != 0;
        let power = (portsc & 0x200) != 0;
        let speed_id = (portsc >> 10) & 0xf;
        platform::println!(
            "usb-driver: port{} connected={} enabled={} power={} reset={} over_current={} speed={} status=0x{:08x}",
            port_index + 1,
            connected as u8,
            enabled as u8,
            power as u8,
            reset as u8,
            over_current as u8,
            xhci_port_speed_name(speed_id),
            portsc
        );
    }
}

fn pci_scan() {
    let mut found = 0usize;
    for bus in 0u8..=255 {
        for device in 0u8..32 {
            for function in 0u8..8 {
                let loc = PciLocation { bus, device, function };
                let Some(vendor_device) = pci_read_u32(loc, 0x00) else {
                    continue;
                };
                let vendor = (vendor_device & 0xFFFF) as u16;
                if vendor == 0xFFFF {
                    continue;
                }
                let device_id = (vendor_device >> 16) as u16;
                let Some(class_reg) = pci_read_u32(loc, 0x08) else {
                    continue;
                };
                let class = (class_reg >> 24) as u8;
                let subclass = (class_reg >> 16) as u8;
                let prog_if = (class_reg >> 8) as u8;
                if class != 0x0C || subclass != 0x03 || prog_if != XHCI_PROG_IF {
                    continue;
                }

                let Some(bar) = find_xhci_bar(loc) else {
                    platform::println!(
                        "usb-driver: xhci controller without MMIO BAR bus={:02x} dev={:02x} func={}",
                        bus,
                        device,
                        function
                    );
                    continue;
                };

                let mut spec = DeviceSpec::new(
                    format!("/pci/{:02x}:{:02x}.{}", bus, device, function),
                    "usb-controller",
                    DeviceBus::Pci,
                    DeviceClass::Usb,
                );
                spec.vendor_id = Some(vendor as u32);
                spec.device_id = Some(device_id as u32);
                spec.revision = pci_read_u8(loc, 0x08);
                spec.properties
                    .insert("pci.bus".into(), DeviceProperty::U32(bus as u32));
                spec.properties
                    .insert("pci.device".into(), DeviceProperty::U32(device as u32));
                spec.properties
                    .insert("pci.function".into(), DeviceProperty::U32(function as u32));
                spec.properties
                    .insert("pci.mmio_base".into(), DeviceProperty::U64(bar.phys_base));
                spec.properties
                    .insert("pci.mmio_size".into(), DeviceProperty::U64(bar.size));
                spec.properties
                    .insert("pci.prog_if".into(), DeviceProperty::U32(prog_if as u32));

                let dev = register_device(spec);
                let _ = UsbDriver::start(dev, PlugKitResources::empty());
                found += 1;
            }
        }
    }

    if found == 0 {
        platform::println!("usb-driver: no xHCI USB controller found");
    }
}

struct UsbDriver;

impl PlugKitDriver for UsbDriver {
    fn probe(device: &PlugKitDevice) -> ProbeResult {
        if device.bus() == DeviceBus::Pci && device.class() == DeviceClass::Usb {
            ProbeResult::Match { score: 100 }
        } else {
            ProbeResult::Reject
        }
    }

    fn start(device: PlugKitDevice, _resources: PlugKitResources) -> PlugKitResult<()> {
        let bus = match device.property("pci.bus")? {
            Some(DeviceProperty::U32(v)) => v as u8,
            _ => return Err(PlugKitError::InvalidHandle),
        };
        let dev = match device.property("pci.device")? {
            Some(DeviceProperty::U32(v)) => v as u8,
            _ => return Err(PlugKitError::InvalidHandle),
        };
        let func = match device.property("pci.function")? {
            Some(DeviceProperty::U32(v)) => v as u8,
            _ => return Err(PlugKitError::InvalidHandle),
        };
        let mmio_base = match device.property("pci.mmio_base")? {
            Some(DeviceProperty::U64(v)) => v,
            Some(DeviceProperty::U32(v)) => v as u64,
            _ => return Err(PlugKitError::InvalidHandle),
        };
        let mmio_size = match device.property("pci.mmio_size")? {
            Some(DeviceProperty::U64(v)) => v,
            Some(DeviceProperty::U32(v)) => v as u64,
            _ => return Err(PlugKitError::InvalidHandle),
        };
        let vendor = device.vendor_id().unwrap_or_default() as u16;
        let device_id = device.device_id().unwrap_or_default() as u16;
        enumerate_xhci_controller(
            PciLocation {
                bus,
                device: dev,
                function: func,
            },
            XhciBar {
                phys_base: mmio_base,
                size: mmio_size,
            },
            vendor,
            device_id,
        );
        Ok(())
    }

    fn stop(_device: PlugKitDevice) -> PlugKitResult<()> {
        Ok(())
    }
}

pub fn run() -> ! {
    platform::println!("usb-driver: start");
    pci_scan();
    platform::println!("usb-driver: enumeration complete");
    platform::process::exit(0)
}
