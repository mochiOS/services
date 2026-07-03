#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use mochi_user_platform as platform;
use mochi_user_syscall as syscall;

const DRIVER_BUNDLE_ROOTS: &[&str] = &["/bin/drivers/usb", "/bin/drivers/ps2"];
const INPUT_SERVICE_PATH: &str = "/system/services/input.service";
const INPUT_PACKAGE_MANIFEST_PATH: &str = "/system/packages/input/manifest.toml";
const TTY_SERVICE_PATH: &str = "/system/services/tty.service";
const TTY_PACKAGE_MANIFEST_PATH: &str = "/system/packages/tty/manifest.toml";
const I8042_DRIVER_ID: &str = "org.mochios.ps2.i8042";
const CAPABILITY_SERVICE_NAME: &str = "capability.service";
const RESOLVE_CAPS_OPCODE: u32 = 0x4341_5053;

fn open_path(path: &str) -> Option<u64> {
    platform::file::open_path(path, 0).ok()
}

fn read_dir_names(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(fd) = open_path(path) else {
        platform::println!("drivers.service: open dir failed {}", path);
        return out;
    };
    let mut buf = [0u8; 4096];
    loop {
        let read = syscall::call3(
            syscall::SyscallNumber::FileReadDir,
            fd,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        );
        let Ok(read) = read else {
            platform::println!("drivers.service: readdir error fd={}", fd);
            break;
        };
        if read == 0 {
            break;
        }
        let bytes = &buf[..read as usize];
        for raw in bytes.split(|&b| b == 0 || b == b'\n') {
            if raw.is_empty() {
                continue;
            }
            if let Ok(name) = core::str::from_utf8(raw) {
                let name =
                    name.trim_matches(|ch: char| ch.is_ascii_control() || ch.is_ascii_whitespace());
                if !name.is_empty() {
                    out.push(name.to_string());
                }
            }
        }
        if (read as usize) < buf.len() {
            break;
        }
    }
    let _ = platform::file::close(fd);
    out
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

fn resolve_capabilities(entry_path: &str) -> Option<Vec<u8>> {
    let service_tid = platform::process::find_by_name(CAPABILITY_SERVICE_NAME).ok()?;
    if service_tid == 0 {
        return None;
    }
    let mut request = Vec::with_capacity(4 + entry_path.len());
    request.extend_from_slice(&RESOLVE_CAPS_OPCODE.to_le_bytes());
    request.extend_from_slice(entry_path.as_bytes());
    let mut reply = [0u8; 1024];
    let msg = platform::ipc::call(service_tid, &request, &mut reply).ok()?;
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 || len > reply.len() {
        return None;
    }
    let status = u64::from_le_bytes(reply[..8].try_into().ok()?);
    if status != 0 {
        return None;
    }
    Some(reply[8..len].to_vec())
}

fn spawn_bundle(entry_path: &str, args: Option<&[u8]>, logger_endpoint: u64) -> Option<u64> {
    let caps_nul = resolve_capabilities(entry_path)?;
    let mut spawn_args = Vec::new();
    if let Some(args) = args {
        let text = core::str::from_utf8(args).ok()?;
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
    .ok()
}

fn spawn_input_service(
    raw_endpoint_handle: u64,
    control_endpoint_handle: u64,
    logger_endpoint: u64,
) -> Option<u64> {
    let _manifest = platform::package::read_manifest(INPUT_PACKAGE_MANIFEST_PATH)?;
    let args = vec![
        raw_endpoint_handle.to_string(),
        control_endpoint_handle.to_string(),
        logger_endpoint.to_string(),
    ];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = resolve_capabilities(INPUT_SERVICE_PATH)?;
    platform::service::spawn_manifest(
        INPUT_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
    .ok()
}

fn spawn_tty_service(control_endpoint_handle: u64, logger_endpoint: u64) -> Option<u64> {
    let _manifest = platform::package::read_manifest(TTY_PACKAGE_MANIFEST_PATH)?;
    let args = vec![
        control_endpoint_handle.to_string(),
        logger_endpoint.to_string(),
    ];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = resolve_capabilities(TTY_SERVICE_PATH)?;
    platform::service::spawn_manifest(
        TTY_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
    .ok()
}

fn bundle_manifest_path(bundle_root: &str) -> String {
    alloc::format!(
        "/system/packages{}/manifest.toml",
        bundle_root.trim_start_matches("/bin")
    )
}

fn maybe_spawn_bundle(bundle_root: &str, raw_input_endpoint_handle: u64, logger_endpoint: u64) {
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

    let args = if manifest.package_id == I8042_DRIVER_ID && raw_input_endpoint_handle != 0 {
        let args = vec![raw_input_endpoint_handle.to_string()];
        Some(encode_spawn_args(&args))
    } else {
        None
    };
    match spawn_bundle(&entry_path, args.as_deref(), logger_endpoint) {
        Some(pid) => {
            platform::println!("drivers.service: spawned driver pid={}", pid);
        }
        None => {
            platform::println!("drivers.service: spawn failed {}", entry_path);
        }
    }
}

pub fn run(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    platform::println!("drivers.service: start");
    let raw_input_endpoint_handle = platform::ipc::create().ok().unwrap_or(0);
    let input_control_endpoint_handle = platform::ipc::create().ok().unwrap_or(0);
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    if raw_input_endpoint_handle != 0 && input_control_endpoint_handle != 0 {
        match spawn_input_service(
            raw_input_endpoint_handle,
            input_control_endpoint_handle,
            logger_endpoint,
        ) {
            Some(pid) => platform::println!("drivers.service: input.service spawned pid={}", pid),
            None => platform::println!("drivers.service: input.service spawn failed"),
        }
        match spawn_tty_service(input_control_endpoint_handle, logger_endpoint) {
            Some(pid) => platform::println!("drivers.service: tty.service spawned pid={}", pid),
            None => platform::println!("drivers.service: tty.service spawn failed"),
        }
    } else {
        platform::println!("drivers.service: input endpoint create failed");
    }
    for bundle_root_path in DRIVER_BUNDLE_ROOTS {
        let bundle_roots = read_dir_names(bundle_root_path);
        for bundle in bundle_roots {
            if !bundle.ends_with(".driver") {
                continue;
            }
            let bundle_root = alloc::format!("{}/{}", bundle_root_path, bundle);
            maybe_spawn_bundle(&bundle_root, raw_input_endpoint_handle, logger_endpoint);
        }
    }

    loop {
        platform::thread::yield_now();
    }
}
