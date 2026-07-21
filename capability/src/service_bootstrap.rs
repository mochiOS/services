use alloc::format;
use alloc::string::ToString;

use mochi_user_platform as platform;

use crate::app_spawn::encode_spawn_args;
use crate::package_index::{PackageIndex, package_manifest_by_id, service_binary_path};
use crate::resolver::{binary_caps, encode_nul_list};

const DRIVERS_PACKAGE_ID: &str = "org.mochios.drivers";
const SIGNATURE_PACKAGE_ID: &str = "org.mochios.signature";
const PACKAGE_PACKAGE_ID: &str = "org.mochios.package";

fn stderr_line(message: &str) {
    let _ = platform::io::stderr(message.as_bytes());
    let _ = platform::io::stderr(b"\n");
}

fn register_delegate_with_retry(kind: u64, pid: u64) -> Result<(), mochi_user_syscall::SysError> {
    let mut last_err = None;
    for _ in 0..32 {
        match platform::service::register_delegate(kind, pid) {
            Ok(_) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                if err.errno().unwrap_or(0) != mochi_user_syscall::ESRCH {
                    return Err(err);
                }
                platform::thread::yield_now();
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ESRCH as i64)
    }))
}

fn spawn_service_by_package(
    index: &PackageIndex,
    package_id: &str,
) -> Result<u64, mochi_user_syscall::SysError> {
    if index.duplicate {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let manifest = package_manifest_by_id(index, package_id)?;
    let service_path = service_binary_path(&manifest)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let caps = binary_caps(&manifest, service_path)?;
    platform::println!(
        "capability.service: parsed {} caps={}",
        service_path,
        caps.len()
    );
    let caps_nul = encode_nul_list(&caps);
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    let args = [logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    platform::service::spawn_manifest(
        service_path,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

pub(crate) fn start_required_services(package_index: &PackageIndex) {
    match spawn_service_by_package(package_index, SIGNATURE_PACKAGE_ID) {
        Ok(pid) => {
            platform::println!("capability.service: signature.service spawned pid={}", pid);
        }
        Err(err) => {
            stderr_line(&format!(
                "capability.service: signature.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            ));
            platform::println!(
                "capability.service: signature.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
    match spawn_service_by_package(package_index, PACKAGE_PACKAGE_ID) {
        Ok(pid) => {
            platform::println!("capability.service: package.service spawned pid={}", pid);
        }
        Err(err) => {
            stderr_line(&format!(
                "capability.service: package.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            ));
            platform::println!(
                "capability.service: package.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
    match spawn_service_by_package(package_index, DRIVERS_PACKAGE_ID) {
        Ok(pid) => {
            platform::println!("capability.service: drivers.service spawned pid={}", pid);
            match register_delegate_with_retry(platform::service::DELEGATE_DRIVER_SPAWN, pid) {
                Ok(_) => {
                    platform::println!(
                        "capability.service: registered drivers.service as driver delegate"
                    );
                }
                Err(err) => {
                    stderr_line(&format!(
                        "capability.service: delegate registration failed errno={}",
                        err.errno().unwrap_or(0)
                    ));
                    platform::println!(
                        "capability.service: delegate registration failed errno={}",
                        err.errno().unwrap_or(0)
                    );
                    platform::process::exit(1);
                }
            }
        }
        Err(err) => {
            stderr_line(&format!(
                "capability.service: drivers.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            ));
            platform::println!(
                "capability.service: drivers.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
}
