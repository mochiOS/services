//! Capture only kernel-authenticated capabilities at request admission.
use mochi_user_platform as platform;
use mochios_filesystem_protocol::namespace_policy::{self as wire, NamespacePolicy};

pub fn capture(sender: u64) -> NamespacePolicy {
    let mut policy = NamespacePolicy::denied();
    let before = platform::ipc::endpoint_execution_identity(sender).ok();
    if platform::capability::check_thread(sender, "fs.read.all") == Ok(1) {
        policy.read = wire::ALL;
    }
    if platform::capability::check_thread(sender, "fs.write.all") == Ok(1) {
        policy.write = wire::ALL;
    }
    for (suffix, bit) in [
        ("all", wire::ALL),
        ("user", wire::USER),
        ("user.documents", wire::DOCUMENTS),
        ("user.downloads", wire::DOWNLOADS),
        ("user.desktop", wire::DESKTOP),
        ("user.pictures", wire::PICTURES),
        ("user.music", wire::MUSIC),
        ("user.videos", wire::VIDEOS),
        ("tmp", wire::TMP),
        ("removable", wire::REMOVABLE),
        ("applications", wire::APPLICATIONS),
    ] {
        if policy.read & wire::ALL == 0
            && platform::capability::check_thread(sender, &format!("fs.read.{suffix}")) == Ok(1)
        {
            policy.read |= bit;
        }
        if policy.write & wire::ALL == 0
            && platform::capability::check_thread(sender, &format!("fs.write.{suffix}")) == Ok(1)
        {
            policy.write |= bit;
        }
    }
    if before.is_some() && before == platform::ipc::endpoint_execution_identity(sender).ok() {
        policy
    } else {
        NamespacePolicy::denied()
    }
}
