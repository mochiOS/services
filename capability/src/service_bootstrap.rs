use alloc::format;
use alloc::string::ToString;

use mochi_user_platform as platform;

use crate::app_spawn::encode_spawn_args;
use crate::package_index::{PackageIndex, package_manifest_by_id, service_binary_path};
use crate::resolver::{binary_caps, encode_nul_list};

const SERVICE_MANAGER_PACKAGE_ID: &str = "org.mochios.service-manager";
const SIGNATURE_PACKAGE_ID: &str = "org.mochios.signature";
const PACKAGE_PACKAGE_ID: &str = "org.mochios.package";

fn stderr_line(message: &str) {
    let _ = platform::io::stderr(message.as_bytes());
    let _ = platform::io::stderr(b"\n");
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
    let manifest = package_manifest_by_id(index, package_id).map_err(|error| {
        stderr_line(&format!(
            "capability.service: package lookup failed id={} errno={}",
            package_id,
            error.errno().unwrap_or(0)
        ));
        error
    })?;
    let service_path = service_binary_path(&manifest).ok_or_else(|| {
        stderr_line(&format!(
            "capability.service: service binary missing id={}",
            package_id
        ));
        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
    })?;
    let caps = binary_caps(&manifest, service_path).map_err(|error| {
        stderr_line(&format!(
            "capability.service: capability resolution failed path={} errno={}",
            service_path,
            error.errno().unwrap_or(0)
        ));
        error
    })?;
    platform::logln!(
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
    .map_err(|error| {
        stderr_line(&format!(
            "capability.service: kernel spawn failed path={} errno={}",
            service_path,
            error.errno().unwrap_or(0)
        ));
        error
    })
}

pub(crate) fn start_required_services(package_index: &PackageIndex) {
    match spawn_service_by_package(package_index, SIGNATURE_PACKAGE_ID) {
        Ok(pid) => {
            platform::logln!("capability.service: signature.service spawned pid={}", pid);
        }
        Err(err) => {
            stderr_line(&format!(
                "capability.service: signature.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            ));
            platform::logln!(
                "capability.service: signature.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
    match spawn_service_by_package(package_index, PACKAGE_PACKAGE_ID) {
        Ok(pid) => {
            platform::logln!("capability.service: package.service spawned pid={}", pid);
        }
        Err(err) => {
            stderr_line(&format!(
                "capability.service: package.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            ));
            platform::logln!(
                "capability.service: package.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
    match spawn_service_by_package(package_index, SERVICE_MANAGER_PACKAGE_ID) {
        Ok(pid) => {
            platform::logln!(
                "capability.service: service-manager.service spawned pid={}",
                pid
            );
        }
        Err(err) => {
            stderr_line(&format!(
                "capability.service: service-manager.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            ));
            platform::logln!(
                "capability.service: service-manager.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
}
