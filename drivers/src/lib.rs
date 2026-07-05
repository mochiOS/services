#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use mochi_user_platform as platform;

const DRIVER_BUNDLE_ROOTS: &[&str] = &["/bin/drivers/usb", "/bin/drivers/ps2"];
const INPUT_SERVICE_PATH: &str = "/system/services/input.service";
const INPUT_PACKAGE_MANIFEST_PATH: &str = "/system/packages/input/manifest.toml";
const DISPLAY_SERVICE_PATH: &str = "/system/services/display.driver";
const DISPLAY_PACKAGE_MANIFEST_PATH: &str = "/system/packages/display/manifest.toml";
const COMPOSITOR_SERVICE_PATH: &str = "/system/services/compositor.service";
const COMPOSITOR_PACKAGE_MANIFEST_PATH: &str = "/system/packages/compositor/manifest.toml";
const TTY_SERVICE_PATH: &str = "/system/services/tty.service";
const TTY_PACKAGE_MANIFEST_PATH: &str = "/system/packages/tty/manifest.toml";
const I8042_DRIVER_ID: &str = "org.mochios.ps2.i8042";
const CAPABILITY_SERVICE_NAME: &str = "capability.service";
const RESOLVE_CAPS_OPCODE: u32 = 0x4341_5053;

fn read_dir_names(path: &str) -> Vec<String> {
    match platform::file::read_dir_names(path) {
        Ok(names) => names,
        Err(err) => {
            platform::println!(
                "drivers.service: open dir failed {} errno={}",
                path,
                err.errno().unwrap_or(0)
            );
            Vec::new()
        }
    }
}

fn encode_spawn_args(items: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.resize(512, 0);
    let mut cursor = 0usize;
    for item in items {
        let bytes = item.as_bytes();
        if cursor + bytes.len() + 2 > out.len() {
            break;
        }
        out[cursor..cursor + bytes.len()].copy_from_slice(bytes);
        cursor += bytes.len();
        out[cursor] = 0;
        cursor += 1;
    }
    out
}

fn sys_error(errno: u64) -> mochi_user_syscall::SysError {
    mochi_user_syscall::SysError::from_raw(-(errno as i64))
}

fn resolve_capabilities(entry_path: &str) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    let service_tid = match platform::process::find_by_name(CAPABILITY_SERVICE_NAME) {
        Ok(tid) => tid,
        Err(err) => {
            platform::println!(
                "drivers.service: capability.service lookup failed errno={}",
                err.errno().unwrap_or(0)
            );
            return Err(err);
        }
    };
    if service_tid == 0 {
        platform::println!("drivers.service: capability.service not found");
        return Err(sys_error(mochi_user_syscall::ENOENT));
    }
    let mut request = Vec::with_capacity(4 + entry_path.len());
    request.extend_from_slice(&RESOLVE_CAPS_OPCODE.to_le_bytes());
    request.extend_from_slice(entry_path.as_bytes());
    let mut reply = [0u8; 1024];
    let msg = match platform::ipc::call(service_tid, &request, &mut reply) {
        Ok(msg) => msg,
        Err(err) => {
            platform::println!(
                "drivers.service: capability request failed {} errno={}",
                entry_path,
                err.errno().unwrap_or(0)
            );
            return Err(err);
        }
    };
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 || len > reply.len() {
        platform::println!(
            "drivers.service: capability reply invalid {} len={}",
            entry_path,
            len
        );
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    let status = u64::from_le_bytes(
        reply[..8]
            .try_into()
            .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?,
    );
    if status != 0 {
        platform::println!(
            "drivers.service: capability denied {} errno={}",
            entry_path,
            status
        );
        return Err(sys_error(status));
    }
    Ok(reply[8..len].to_vec())
}

fn spawn_bundle(
    entry_path: &str,
    args: Option<&[u8]>,
    logger_endpoint: u64,
) -> Result<u64, mochi_user_syscall::SysError> {
    let caps_nul = resolve_capabilities(entry_path)?;
    let mut spawn_args = Vec::new();
    if let Some(args) = args {
        let text = core::str::from_utf8(args).map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
        for part in text.split('\0') {
            if !part.is_empty() {
                spawn_args.push(part.to_string());
            }
        }
    }
    if logger_endpoint != 0 {
        spawn_args.push(logger_endpoint.to_string());
    }
    let args_nul = encode_spawn_args(&spawn_args);
    platform::service::spawn_manifest(
        entry_path,
        platform::service::ROLE_DRIVER,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

fn spawn_input_service(logger_endpoint: u64) -> Result<u64, mochi_user_syscall::SysError> {
    let _manifest = platform::package::read_manifest(INPUT_PACKAGE_MANIFEST_PATH)
        .ok_or_else(|| sys_error(mochi_user_syscall::ENOENT))?;
    let args = vec![logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = resolve_capabilities(INPUT_SERVICE_PATH)?;
    platform::service::spawn_manifest(
        INPUT_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

fn spawn_named_service(
    service_path: &str,
    manifest_path: &str,
    logger_endpoint: u64,
) -> Result<u64, mochi_user_syscall::SysError> {
    let _manifest = platform::package::read_manifest(manifest_path)
        .ok_or_else(|| sys_error(mochi_user_syscall::ENOENT))?;
    let args = vec![logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = resolve_capabilities(service_path)?;
    platform::service::spawn_manifest(
        service_path,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

fn spawn_tty_service(logger_endpoint: u64) -> Result<u64, mochi_user_syscall::SysError> {
    let _manifest = platform::package::read_manifest(TTY_PACKAGE_MANIFEST_PATH)
        .ok_or_else(|| sys_error(mochi_user_syscall::ENOENT))?;
    let args = vec![logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = resolve_capabilities(TTY_SERVICE_PATH)?;
    platform::service::spawn_manifest(
        TTY_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

fn bundle_manifest_path(bundle_root: &str) -> String {
    alloc::format!(
        "/system/packages{}/manifest.toml",
        bundle_root.trim_start_matches("/bin")
    )
}

fn maybe_spawn_bundle(bundle_root: &str, logger_endpoint: u64) {
    let package_manifest_path = bundle_manifest_path(bundle_root);
    let Some(manifest) = platform::package::read_manifest(&package_manifest_path) else {
        platform::println!("drivers.service: missing {}", package_manifest_path);
        return;
    };
    let entry_path = alloc::format!("{}/entry.elf", bundle_root);
    let Some(binary) = manifest.binary(&entry_path) else {
        platform::println!(
            "drivers.service: missing binary entry {} in {}",
            entry_path,
            package_manifest_path
        );
        return;
    };

    platform::println!(
        "drivers.service: bundle {} {} api={} class={} match={}/{}",
        manifest.package_id,
        manifest.package_name,
        binary.api_version.unwrap_or(0),
        binary.driver_class.as_deref().unwrap_or(""),
        binary.match_bus.as_deref().unwrap_or(""),
        binary.match_class.as_deref().unwrap_or("")
    );

    let _ = manifest.package_id == I8042_DRIVER_ID;
    match spawn_bundle(&entry_path, None, logger_endpoint) {
        Ok(pid) => {
            platform::println!("drivers.service: spawned driver pid={}", pid);
        }
        Err(err) => {
            platform::println!(
                "drivers.service: spawn failed {} errno={}",
                entry_path,
                err.errno().unwrap_or(0)
            );
        }
    }
}

pub fn run(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    platform::println!("drivers.service: start");
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    match spawn_input_service(logger_endpoint) {
        Ok(pid) => platform::println!("drivers.service: input.service spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: input.service spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }
    match spawn_named_service(
        DISPLAY_SERVICE_PATH,
        DISPLAY_PACKAGE_MANIFEST_PATH,
        logger_endpoint,
    ) {
        Ok(pid) => platform::println!("drivers.service: display.driver spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: display.driver spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }
    match spawn_named_service(
        COMPOSITOR_SERVICE_PATH,
        COMPOSITOR_PACKAGE_MANIFEST_PATH,
        logger_endpoint,
    ) {
        Ok(pid) => platform::println!("drivers.service: compositor.service spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: compositor.service spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }
    for bundle_root_path in DRIVER_BUNDLE_ROOTS {
        let bundle_roots = read_dir_names(bundle_root_path);
        for bundle in bundle_roots {
            if !bundle.ends_with(".driver") {
                continue;
            }
            let bundle_root = alloc::format!("{}/{}", bundle_root_path, bundle);
            maybe_spawn_bundle(&bundle_root, logger_endpoint);
        }
    }
    match spawn_tty_service(logger_endpoint) {
        Ok(pid) => platform::println!("drivers.service: tty.service spawned pid={}", pid),
        Err(err) => platform::println!(
            "drivers.service: tty.service spawn failed errno={}",
            err.errno().unwrap_or(0)
        ),
    }

    loop {
        platform::thread::yield_now();
    }
}
