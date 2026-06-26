#![no_std]

extern crate alloc;

use alloc::format;
use mochi_user_platform as platform;
use mochi_user_syscall as syscall;
use plugkit::prelude::*;

const PCI_CFG_ADDR: u16 = 0xCF8;
const PCI_CFG_DATA: u16 = 0xCFC;

const UHCI_USBCMD: u16 = 0x00;
const UHCI_USBSTS: u16 = 0x02;
const UHCI_PORTSC1: u16 = 0x10;
const UHCI_PORTSC2: u16 = 0x12;

#[derive(Clone, Copy)]
struct PciLocation {
    bus: u8,
    device: u8,
    function: u8,
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

fn read_bar_io_base(loc: PciLocation) -> Option<u16> {
    let mut bar_idx = 0u8;
    while bar_idx < 6 {
        let offset = 0x10 + bar_idx * 4;
        let bar = pci_read_u32(loc, offset)?;
        if (bar & 0x1) != 0 {
            return Some((bar & 0xFFFC) as u16);
        }
        bar_idx += 1;
    }
    None
}

fn enable_controller(loc: PciLocation) {
    if let Some(command) = pci_read_u16(loc, 0x04) {
        let updated = command | 0x0005;
        let _ = pci_write_u16(loc, 0x04, updated);
    }
}

fn port_status(io_base: u16, port_offset: u16) -> u16 {
    let port = io_base.wrapping_add(port_offset);
    port_in(port, 2).ok().map(|v| v as u16).unwrap_or(0)
}

fn uhci_log_port(io_base: u16, index: usize, offset: u16) {
    let status = port_status(io_base, offset);
    let connected = (status & 0x0001) != 0;
    let enabled = (status & 0x0004) != 0;
    let low_speed = (status & 0x0100) != 0;
    platform::println!(
        "usb-driver: port{} connected={} enabled={} low_speed={} status=0x{:04x}",
        index,
        connected as u8,
        enabled as u8,
        low_speed as u8,
        status
    );
}

fn enumerate_uhci_controller(loc: PciLocation, io_base: u16, vendor: u16, device: u16) {
    platform::println!(
        "usb-driver: controller bus={:02x} dev={:02x} func={} vendor=0x{:04x} device=0x{:04x} io_base=0x{:04x}",
        loc.bus,
        loc.device,
        loc.function,
        vendor,
        device,
        io_base
    );

    enable_controller(loc);
    let usbcmd = port_in(io_base.wrapping_add(UHCI_USBCMD), 2).ok().unwrap_or(0) as u16;
    let usbsts = port_in(io_base.wrapping_add(UHCI_USBSTS), 2).ok().unwrap_or(0) as u16;
    platform::println!(
        "usb-driver: usbcmd=0x{:04x} usbsts=0x{:04x}",
        usbcmd,
        usbsts
    );

    uhci_log_port(io_base, 1, UHCI_PORTSC1);
    uhci_log_port(io_base, 2, UHCI_PORTSC2);
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
                if class != 0x0C || subclass != 0x03 {
                    continue;
                }

                let header_type = pci_read_u8(loc, 0x0E).unwrap_or(0);
                platform::println!(
                    "usb-driver: PCI USB controller bus={:02x} dev={:02x} func={} vendor=0x{:04x} device=0x{:04x} class=0x{:02x} subclass=0x{:02x} prog_if=0x{:02x} header=0x{:02x}",
                    bus,
                    device,
                    function,
                    vendor,
                    device_id,
                    class,
                    subclass,
                    prog_if,
                    header_type,
                );

                let mut spec = DeviceSpec::new(
                    format!("/pci/{:02x}:{:02x}.{}", bus, device, function),
                    "usb-controller",
                    DeviceBus::Pci,
                    DeviceClass::Usb,
                );
                spec.vendor_id = Some(vendor as u32);
                spec.device_id = Some(device_id as u32);
                spec.revision = pci_read_u8(loc, 0x08);
                spec.properties.insert("pci.bus".into(), DeviceProperty::U32(bus as u32));
                spec.properties
                    .insert("pci.device".into(), DeviceProperty::U32(device as u32));
                spec.properties
                    .insert("pci.function".into(), DeviceProperty::U32(function as u32));

                if let Some(io_base) = read_bar_io_base(loc) {
                    spec.properties
                        .insert("pci.io_base".into(), DeviceProperty::U32(io_base as u32));
                    let dev = register_device(spec);
                    let _ = UsbDriver::start(dev, PlugKitResources::empty());
                    found += 1;
                } else {
                    platform::println!(
                        "usb-driver: controller has no I/O BAR; skipping controller-specific init"
                    );
                }
            }
        }
    }

    if found == 0 {
        platform::println!("usb-driver: no PCI USB controller found");
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
        let io_base = match device.property("pci.io_base")? {
            Some(DeviceProperty::U32(v)) => v as u16,
            _ => return Err(PlugKitError::InvalidHandle),
        };
        let vendor = device.vendor_id().unwrap_or_default() as u16;
        let device_id = device.device_id().unwrap_or_default() as u16;
        enumerate_uhci_controller(
            PciLocation {
                bus,
                device: dev,
                function: func,
            },
            io_base,
            vendor,
            device_id,
        );
        Ok(())
    }

    fn stop(_device: PlugKitDevice) -> PlugKitResult<()> {
        Ok(())
    }
}

driver!(UsbDriver);

pub fn run() -> ! {
    platform::println!("usb-driver: start");
    pci_scan();
    platform::println!("usb-driver: enumeration complete");
    platform::process::exit(0)
}
