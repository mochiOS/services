#![no_std]
#![no_main]

use core::arch::global_asm;
use mochi_user_platform as platform;
use mochi_user_syscall as syscall;

global_asm!(
    r#"
    .global _start
_start:
    xor rbp, rbp
    and rsp, -16
    call service_main
1:
    hlt
    jmp 1b
"#
);

static HELLO_PATH: &[u8] = b"/bin/hello\0";
static PERSIST_PATH: &[u8] = b"/persist.txt\0";
static HELLO_ARG0: &[u8] = b"hello\0";
static HELLO_ARG1: &[u8] = b"spawned\0";
static PERSIST_BYTES: &[u8] = b"persisted by core.service\n";

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;

fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}

fn spawn_child() -> Result<u64, syscall::SysError> {
    syscall::call2(syscall::SyscallNumber::ProcessSpawn, 0, 0)
}

fn wait_child(pid: u64, status: &mut i32) -> Result<u64, syscall::SysError> {
    syscall::call3(
        syscall::SyscallNumber::ProcessWait,
        pid,
        status as *mut i32 as u64,
        0,
    )
}

fn exec_hello() -> Result<u64, syscall::SysError> {
    let argv = [
        HELLO_ARG0.as_ptr() as u64,
        HELLO_ARG1.as_ptr() as u64,
        0,
    ];
    syscall::call3(
        syscall::SyscallNumber::Execve,
        HELLO_PATH.as_ptr() as u64,
        argv.as_ptr() as u64,
        0,
    )
}

fn ensure_persistence() -> Result<(), syscall::SysError> {
    platform::println!("core.service: persist open");
    let fd = match platform::file::open(PERSIST_PATH.as_ptr() as u64, O_RDWR) {
        Ok(fd) => fd,
        Err(err) => {
            platform::println!(
                "core.service: persist initial open errno={}",
                err.errno().unwrap_or(0)
            );
            if err.raw() != syscall::ENOENT as i64 {
                return Err(err);
            }
            platform::println!("core.service: persist create open");
            let fd = platform::file::open(PERSIST_PATH.as_ptr() as u64, O_CREAT | O_WRONLY)?;
            platform::println!("core.service: persist write");
            let wrote = platform::file::write(
                fd,
                PERSIST_BYTES.as_ptr() as u64,
                PERSIST_BYTES.len() as u64,
            )?;
            if wrote != PERSIST_BYTES.len() as u64 {
                let _ = platform::file::close(fd);
                return Err(syscall::SysError::from_raw(syscall::EIO as i64));
            }
            platform::file::close(fd)?;
            platform::println!("core.service: persist created");
            platform::println!("core.service: persist reopen");
            platform::file::open(PERSIST_PATH.as_ptr() as u64, O_RDONLY)?
        }
    };

    let mut buf = [0u8; 64];
    platform::println!("core.service: persist read");
    let read = platform::file::read(fd, buf.as_mut_ptr() as u64, buf.len() as u64)?;
    platform::file::close(fd)?;
    let read_len = read as usize;
    if read_len != PERSIST_BYTES.len() || &buf[..read_len] != PERSIST_BYTES {
        platform::println!("core.service: persist verify failed len={}", read_len);
        return Err(syscall::SysError::from_raw(syscall::EIO as i64));
    }
    platform::println!("core.service: persist verified");
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main() -> ! {
    main();
    platform::process::exit(0)
}

fn main() {
    platform::println!("core.service: start");
    if let Err(err) = ensure_persistence() {
        platform::println!(
            "core.service: persist failed errno={}",
            err.errno().unwrap_or(0)
        );
        platform::process::exit(1);
    }

    match spawn_child() {
        Ok(0) => match exec_hello() {
            Ok(_) => platform::process::exit(127),
            Err(err) => {
                platform::println!("core.service: execve failed errno={}", err.errno().unwrap_or(0));
                platform::process::exit(127);
            }
        },
        Ok(pid) => {
            let mut status = -1i32;
            match wait_child(pid, &mut status) {
                Ok(waited) => {
                    platform::println!(
                        "waitpid status={} exited={} code={} pid={} waited={}",
                        status,
                        wifexited(status) as u8,
                        wexitstatus(status),
                        pid,
                        waited
                    );
                    if wifexited(status) && wexitstatus(status) == 0 {
                        return;
                    }
                    platform::process::exit(1);
                }
                Err(err) => {
                    platform::println!(
                        "core.service: waitpid failed errno={}",
                        err.errno().unwrap_or(0)
                    );
                    platform::process::exit(1);
                }
            }
        }
        Err(err) => {
            platform::println!(
                "core.service: process_spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
}
