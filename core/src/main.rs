extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use mochi_user_platform as platform;
use mochios_signature_protocol::{InstallProvenance, InstallRecordView};
use sha2::{Digest, Sha256};

#[cfg(feature = "performance-benchmark")]
use std::fs::OpenOptions;
#[cfg(feature = "performance-benchmark")]
use std::io::{Read, Seek, SeekFrom, Write};

const LOGGER_SERVICE_PATH: &str = "/system/services/logger.service";
const LOGGER_PACKAGE_MANIFEST_PATH: &str = "/system/packages/logger/manifest.toml";
const CAPABILITY_SERVICE_PATH: &str = "/system/services/capability.service";
const CAPABILITY_PACKAGE_MANIFEST_PATH: &str = "/system/packages/capability/manifest.toml";
const ROOTFS_READY_RETRIES: usize = 16;
const BUILT_IN_DEVELOPER_ID: &str = "org.mochios.system";

#[cfg(feature = "performance-benchmark")]
const VFS_BENCHMARK_PATH: &str = "/tmp/mochios-vfs-benchmark";
#[cfg(feature = "performance-benchmark")]
const VFS_BENCHMARK_WARMUP_ITERATIONS: usize = 16;
#[cfg(feature = "performance-benchmark")]
const VFS_BENCHMARK_ITERATIONS: usize = 256;
#[cfg(feature = "performance-benchmark")]
const VFS_BENCHMARK_BUFFER_BYTES: usize = 4 * 1024;

fn encode_nul_list(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.as_bytes());
        out.push(0);
    }
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

fn load_builtin_execution_security(
    manifest_path: &str,
    binary_path: &str,
) -> Result<(Vec<String>, Vec<String>), mochi_user_syscall::SysError> {
    use mnu_abi::exec::{
        APPLICATION_DEVELOPER_ID_PREFIX, APPLICATION_PACKAGE_ID_PREFIX,
        APPLICATION_PROVENANCE_PREFIX, APPLICATION_SUBJECT_KEY_ID_PREFIX,
    };

    let manifest = read_manifest_with_retry(manifest_path)?;
    if manifest.install_provenance.as_deref() != Some("built-in") {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let manifest_bytes = platform::file::read_to_end_path(manifest_path)?;
    let package_root = manifest_path.rsplit_once('/').map(|(root, _)| root).ok_or_else(|| {
        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
    })?;
    let verification_path = alloc::format!("{package_root}/verification.bin");
    let verification_bytes = platform::file::read_to_end_path(&verification_path)?;
    let record = InstallRecordView::decode(&verification_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    let verified = record.verification;
    if record.provenance != InstallProvenance::BuiltIn
        || verified.provenance != InstallProvenance::BuiltIn
        || verified.request_id != 0
        || verified.certificate_serial != 0
        || verified.subject_key_id != [0; 32]
        || verified.developer_id != BUILT_IN_DEVELOPER_ID
        || verified.verified_package_id != manifest.package_id
        || verified.package_digest != verified.manifest_digest
        || Sha256::digest(&manifest_bytes).as_slice() != verified.manifest_digest
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let capabilities = manifest.binary_requires(binary_path).ok_or_else(|| {
        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
    })?;
    for capability in capabilities {
        let mut allowed = false;
        for record_capability in verified.allowed_capabilities() {
            if record_capability
                .map_err(|_| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64)
                })?
                == capability
            {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
    }
    let identity = alloc::vec![
        alloc::format!("{APPLICATION_PACKAGE_ID_PREFIX}{}", manifest.package_id),
        alloc::format!("{APPLICATION_DEVELOPER_ID_PREFIX}{BUILT_IN_DEVELOPER_ID}"),
        alloc::format!("{APPLICATION_SUBJECT_KEY_ID_PREFIX}{}", "0".repeat(64)),
        alloc::format!("{APPLICATION_PROVENANCE_PREFIX}built-in"),
    ];
    Ok((identity, capabilities.to_vec()))
}

fn stderr_line(message: &str) {
    let _ = platform::io::stderr(message.as_bytes());
    let _ = platform::io::stderr(b"\n");
}

#[cfg(feature = "performance-benchmark")]
fn vfs_benchmark_iteration(buffer: &mut [u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(VFS_BENCHMARK_PATH)?;
    file.write_all(buffer)?;
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(buffer)?;
    let _ = file.metadata()?;
    Ok(())
}

#[cfg(feature = "performance-benchmark")]
fn run_vfs_benchmark() {
    let mut buffer = [0x5au8; VFS_BENCHMARK_BUFFER_BYTES];
    for _ in 0..VFS_BENCHMARK_WARMUP_ITERATIONS {
        if let Err(error) = vfs_benchmark_iteration(&mut buffer) {
            platform::logln!("VFS_BENCHMARK error=warmup detail={}", error);
            return;
        }
    }

    let before = match platform::performance::snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            platform::logln!(
                "VFS_BENCHMARK error=snapshot-before errno={}",
                error.errno().unwrap_or(0)
            );
            return;
        }
    };
    for _ in 0..VFS_BENCHMARK_ITERATIONS {
        if let Err(error) = vfs_benchmark_iteration(&mut buffer) {
            platform::logln!("VFS_BENCHMARK error=workload detail={}", error);
            return;
        }
    }
    let after = match platform::performance::snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            platform::logln!(
                "VFS_BENCHMARK error=snapshot-after errno={}",
                error.errno().unwrap_or(0)
            );
            return;
        }
    };
    let _ = std::fs::remove_file(VFS_BENCHMARK_PATH);

    let activity = after.vfs_activity.saturating_sub(before.vfs_activity);
    let open = after.latencies[platform::performance::LatencyMetric::VfsOpen as usize];
    let read = after.latencies[platform::performance::LatencyMetric::VfsRead as usize];
    let write = after.latencies[platform::performance::LatencyMetric::VfsWrite as usize];
    let close = after.latencies[platform::performance::LatencyMetric::VfsClose as usize];
    let stat = after.latencies[platform::performance::LatencyMetric::VfsStat as usize];
    platform::logln!(
        "VFS_BENCHMARK_ACTIVITY iterations={} bytes={} metadata={} read_ranges={} write_ranges={} read_requested={} read_transferred={} write_requested={} write_transferred={} temp_allocations={} temp_bytes={} path_clones={} path_clone_bytes={}",
        VFS_BENCHMARK_ITERATIONS,
        VFS_BENCHMARK_BUFFER_BYTES,
        activity.metadata_queries,
        activity.read_range_calls,
        activity.write_range_calls,
        activity.read_requested_bytes,
        activity.read_transferred_bytes,
        activity.write_requested_bytes,
        activity.write_transferred_bytes,
        activity.temporary_buffer_allocations,
        activity.temporary_buffer_bytes,
        activity.path_clone_allocations,
        activity.path_clone_bytes,
    );
    platform::logln!(
        "VFS_BENCHMARK_LATENCY open_p50={} open_p95={} open_p99={} read_p50={} read_p95={} read_p99={} write_p50={} write_p95={} write_p99={} close_p50={} close_p95={} close_p99={} stat_p50={} stat_p95={} stat_p99={}",
        open.p50_cycles,
        open.p95_cycles,
        open.p99_cycles,
        read.p50_cycles,
        read.p95_cycles,
        read.p99_cycles,
        write.p50_cycles,
        write.p95_cycles,
        write.p99_cycles,
        close.p50_cycles,
        close.p95_cycles,
        close.p99_cycles,
        stat.p50_cycles,
        stat.p95_cycles,
        stat.p99_cycles,
    );
}

fn bytes_preview(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes.iter().take(96).copied() {
        match byte {
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push('.'),
        }
    }
    out
}

fn read_manifest_with_retry(
    path: &str,
) -> Result<platform::package::PackageManifest, mochi_user_syscall::SysError> {
    let mut last_errno = mochi_user_syscall::ENOENT;
    let mut last_len = 0usize;
    let mut last_preview = String::new();
    for _ in 0..ROOTFS_READY_RETRIES {
        match platform::file::read_to_end_path(path) {
            Ok(bytes) => {
                last_len = bytes.len();
                last_preview = bytes_preview(&bytes);
                match core::str::from_utf8(&bytes) {
                    Ok(text) => {
                        if let Some(manifest) = platform::package::parse_manifest(text) {
                            return Ok(manifest);
                        }
                        last_errno = mochi_user_syscall::EINVAL;
                    }
                    Err(_) => {
                        last_errno = mochi_user_syscall::EINVAL;
                    }
                }
            }
            Err(err) => {
                last_errno = err.errno().unwrap_or(mochi_user_syscall::EIO);
            }
        }
        platform::thread::yield_now();
    }
    stderr_line(&alloc::format!(
        "core.service: manifest read timed out path={} errno={} len={} first={}",
        path,
        last_errno,
        last_len,
        last_preview
    ));
    Err(mochi_user_syscall::SysError::from_raw(last_errno as i64))
}

fn spawn_logger_service() -> Result<u64, mochi_user_syscall::SysError> {
    let bootstrap = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(err) => {
            platform::logln!(
                "core.service: logger bootstrap endpoint create failed errno={}",
                err.errno().unwrap_or(0)
            );
            return Err(err);
        }
    };
    let (mut args, caps) =
        load_builtin_execution_security(LOGGER_PACKAGE_MANIFEST_PATH, LOGGER_SERVICE_PATH)?;
    let caps_nul = encode_nul_list(&caps);
    args.push(bootstrap.to_string());
    let args_nul = encode_spawn_args(&args);
    let pid = match platform::service::spawn_manifest(
        LOGGER_SERVICE_PATH,
        platform::service::ExecutionClass::Privileged,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    ) {
        Ok(pid) => pid,
        Err(err) => {
            stderr_line(&alloc::format!(
                "core.service: logger exec failed caps={} args_len={} caps_len={} errno={}",
                caps.len(),
                args_nul.len(),
                caps_nul.len(),
                err.errno().unwrap_or(0)
            ));
            return Err(err);
        }
    };
    let mut buf = [0u8; 16];
    let msg = platform::ipc::wait(bootstrap, &mut buf)?;
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let logger_endpoint = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    platform::logger::init(logger_endpoint);
    Ok(pid)
}

fn spawn_capability_service() -> Result<u64, mochi_user_syscall::SysError> {
    let (mut args, caps) = load_builtin_execution_security(
        CAPABILITY_PACKAGE_MANIFEST_PATH,
        CAPABILITY_SERVICE_PATH,
    )?;
    platform::logln!(
        "core.service: parsed capability.service package caps={}",
        caps.len()
    );
    let caps_nul = encode_nul_list(&caps);
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    args.push(logger_endpoint.to_string());
    let args_nul = encode_spawn_args(&args);
    match platform::service::spawn_manifest(
        CAPABILITY_SERVICE_PATH,
        platform::service::ExecutionClass::Privileged,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    ) {
        Ok(pid) => Ok(pid),
        Err(err) => Err(err),
    }
}

fn main() {
    let _logger_pid = match spawn_logger_service() {
        Ok(pid) => pid,
        Err(err) => {
            platform::logln!(
                "core.service: logger.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    };

    #[cfg(feature = "performance-benchmark")]
    run_vfs_benchmark();

    run();
    platform::process::exit(0)
}

fn run() {
    platform::logln!("core.service: start");
    match spawn_capability_service() {
        Ok(pid) => {
            platform::logln!("core.service: capability.service spawned pid={}", pid);
        }
        Err(err) => {
            platform::logln!(
                "core.service: capability.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }

    loop {
        platform::thread::yield_now();
    }
}
