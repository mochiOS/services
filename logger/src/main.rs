extern crate alloc;

use alloc::string::String;
use mochi_user_platform as platform;

const LOG_ROOT: &str = "/var/log/services";

fn parse_decimal_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut out = 0u64;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out.checked_mul(10)?;
        out = out.checked_add(u64::from(b - b'0'))?;
    }
    Some(out)
}

fn parse_bootstrap_endpoint() -> Option<u64> {
    for argument in std::env::args() {
        if let Some(value) = parse_decimal_u64(argument.as_bytes()) {
            return Some(value);
        }
    }
    None
}

fn service_key_from_prefix(prefix: &str) -> String {
    let mut key = prefix.trim();
    if let Some(stripped) = key.strip_suffix(".service") {
        key = stripped;
    }
    let mut out = String::new();
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("misc");
    }
    out
}

fn log_path_for_line(line: &str) -> String {
    let prefix = line
        .split_once(':')
        .map(|(prefix, _)| prefix)
        .unwrap_or("misc");
    let key = service_key_from_prefix(prefix);
    alloc::format!("{}/{}.log", LOG_ROOT, key)
}

fn ensure_dir_tree(path: &str) -> platform::syscall::SysResult<()> {
    let mut current = String::new();
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        current.push('/');
        current.push_str(segment);
        if let Err(error) = platform::file::create_dir(&current, 0o755) {
            if error.raw() != platform::syscall::EEXIST as i64 {
                return Err(error);
            }
        }
    }
    Ok(())
}

fn ensure_log_parent(path: &str) -> platform::syscall::SysResult<()> {
    let Some((parent, _)) = path.rsplit_once('/') else {
        return Ok(());
    };
    ensure_dir_tree(parent)
}

fn append_log_line(line: &[u8]) -> platform::syscall::SysResult<()> {
    let text = core::str::from_utf8(line)
        .map_err(|_| platform::syscall::SysError::from_raw(platform::syscall::EINVAL as i64))?;
    let path = log_path_for_line(text);
    ensure_log_parent(&path)?;
    const AT_FDCWD: i64 = -100;
    const O_WRONLY: u64 = 0o1;
    const O_CREAT: u64 = 0o100;
    const O_APPEND: u64 = 0o2000;
    const O_CLOEXEC: u64 = 0o2_000_000;
    let fd = platform::file::openat_path(
        AT_FDCWD,
        &path,
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
        0o640,
    )?;
    let result = append_and_sync(fd, line);
    let close_result = platform::file::close(fd).map(|_| ());
    result.and(close_result)
}

fn append_and_sync(fd: u64, line: &[u8]) -> platform::syscall::SysResult<()> {
    let mut offset = 0usize;
    while offset < line.len() {
        let written = platform::file::write(
            fd,
            line[offset..].as_ptr() as u64,
            (line.len() - offset) as u64,
        )?;
        if written == 0 || written as usize > line.len() - offset {
            return Err(platform::syscall::SysError::from_raw(
                platform::syscall::EIO as i64,
            ));
        }
        offset += written as usize;
    }
    platform::file::sync(fd).map(|_| ())
}

fn report_persistence_error(error: platform::syscall::SysError) {
    let errno = error.errno().unwrap_or(5);
    let _ = platform::write_fmt(
        platform::io::STDERR,
        format_args!("logger.service: log persistence failed errno={errno}\n"),
    );
}

fn main() {
    let Some(bootstrap_endpoint) = parse_bootstrap_endpoint() else {
        platform::process::exit(1);
    };

    let log_endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => platform::process::exit(1),
    };

    let bytes = log_endpoint.to_le_bytes();
    let _ = platform::ipc::send(bootstrap_endpoint, &bytes);

    let mut buf = [0u8; 512];
    loop {
        let Ok(msg) = platform::ipc::wait(log_endpoint, &mut buf) else {
            platform::thread::yield_now();
            continue;
        };
        let len = (msg & 0xffff_ffff) as usize;
        if len == 0 {
            continue;
        }
        if let Err(error) = append_log_line(&buf[..len]) {
            report_persistence_error(error);
        }
    }
}
