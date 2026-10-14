use alloc::format;
use alloc::string::ToString;

use mochi_user_platform as platform;

use crate::package_index::{PackageIndex, package_manifest_by_id, service_binary_path};
use crate::resolver::{application_identity, authorize_spawn_image, binary_caps};

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
    let (manifest, manifest_path) = package_manifest_by_id(index, package_id).map_err(|error| {
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
    let caps = binary_caps(
        &manifest,
        &manifest_path,
        service_path,
        crate::bootstrap_file::read_file,
    )
    .map_err(|error| {
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
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    let identity =
        application_identity(&manifest, &manifest_path, crate::bootstrap_file::read_file)?;
    let args = alloc::vec![logger_endpoint.to_string()];
    crate::native_bootstrap::spawn(service_path, &args, |image| {
        authorize_spawn_image(
            0,
            service_path,
            &identity,
            caps,
            platform::service::ExecutionClass::Privileged,
            image,
        )
    })
    .map_err(|error| {
        stderr_line(&format!(
            "capability.service: native launch failed path={} errno={}",
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
