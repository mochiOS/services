const QEMU_USB_DRIVER_ID: &str = "org.mochios.usb.qemu";
const I8042_DRIVER_ID: &str = "org.mochios.ps2.i8042";
const VIRTIO_NET_DRIVER_ID: &str = "org.mochios.network.virtio-net";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DriverSearchRoot {
    Usb,
    Ps2,
    Network,
}

impl DriverSearchRoot {
    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::Usb => "/bin/drivers/usb",
            Self::Ps2 => "/bin/drivers/ps2",
            Self::Network => "/bin/drivers/network",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MatchResult {
    Matched,
    PackageIdMismatch,
    DriverClassMismatch,
    MatchBusMismatch,
    MatchClassMismatch,
}

impl MatchResult {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::PackageIdMismatch => "package-id",
            Self::DriverClassMismatch => "driver-class",
            Self::MatchBusMismatch => "match-bus",
            Self::MatchClassMismatch => "match-class",
        }
    }
}

pub(crate) fn matches(
    root: DriverSearchRoot,
    package_id: &str,
    driver_class: Option<&str>,
    match_bus: Option<&str>,
    match_class: Option<&str>,
) -> MatchResult {
    let (expected_package_id, expected_driver_class, expected_bus, expected_class) = match root {
        DriverSearchRoot::Usb => (QEMU_USB_DRIVER_ID, "usb", "pci", "usb"),
        DriverSearchRoot::Ps2 => (I8042_DRIVER_ID, "input", "platform", "i8042"),
        DriverSearchRoot::Network => (VIRTIO_NET_DRIVER_ID, "network", "pci", "network"),
    };

    if package_id != expected_package_id {
        return MatchResult::PackageIdMismatch;
    }
    if driver_class != Some(expected_driver_class) {
        return MatchResult::DriverClassMismatch;
    }
    if match_bus != Some(expected_bus) {
        return MatchResult::MatchBusMismatch;
    }
    if match_class != Some(expected_class) {
        return MatchResult::MatchClassMismatch;
    }
    MatchResult::Matched
}
