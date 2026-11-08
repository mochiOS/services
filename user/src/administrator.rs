//! Application identity/capability is not human administrator identity.
use mochi_user_platform as platform;
use mochios_posix_client::{Client, ObjectHandleAttachment, SyscallEndpointTransport};

/// Upgrade the legacy world-writable account-settings directory before
/// publishing user.service readiness. Untrusted legacy autologin files are
/// replaced, so an already-open writer cannot alter the trusted replacement.
pub fn protect_settings() -> std::io::Result<()> {
    use std::{
        fs,
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };
    const DIRECTORY: &str = "/var/config/account";
    const SETTINGS: &str = "/var/config/account/settings.conf";
    fs::create_dir_all(DIRECTORY)?;
    let directory = fs::symlink_metadata(DIRECTORY)?;
    if !directory.is_dir() || directory.uid() != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "untrusted account settings directory",
        ));
    }
    fs::set_permissions(DIRECTORY, fs::Permissions::from_mode(0o755))?;
    match fs::symlink_metadata(SETTINGS) {
        Ok(metadata)
            if metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 =>
        {
            Ok(())
        }
        Ok(_) => {
            fs::remove_file(SETTINGS)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(SETTINGS)?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.write_all(b"auto_login=false\nauto_login_user=\n")?;
            file.sync_all()
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Preserve the current UID-0 administrator policy. A root service can act
/// only with its separately granted account-management capability; a signed
/// Settings/useradd image launched by an ordinary user is not an administrator.
pub fn permits(client: &Client<SyscallEndpointTransport>, sender: u64) -> bool {
    let result = (|| {
        let peer = platform::execution_peer::capture(sender).ok()?;
        let process = platform::execution_peer::ProcessReference(
            platform::process::open_handle_for_endpoint(
                sender,
                platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_TRANSFER,
            )
            .ok()?,
        );
        if !platform::handle::same_object(peer.process.0, process.0).ok()? {
            return None;
        }
        let session = client
            .process_session_info(ObjectHandleAttachment {
                handle: process.0,
                rights: platform::handle::HANDLE_RIGHT_WAIT,
            })
            .ok()?;
        let current = platform::execution_peer::capture(sender).ok()?;
        if session.real_uid != 0
            || session.effective_uid != 0
            || current.context != peer.context
            || current.image != peer.image
            || !platform::handle::same_object(current.process.0, peer.process.0).ok()?
        {
            return None;
        }
        Some(())
    })();
    result.is_some()
}
