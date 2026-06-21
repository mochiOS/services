#![no_std]
#![no_main]

use mochi_user_platform as platform;
use mochi_user_syscall as syscall;

static HELLO_PATH: &[u8] = b"/bin/hello\0";
static HELLO_ARG0: &[u8] = b"hello\0";
static HELLO_ARG1: &[u8] = b"spawned\0";

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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    main();
    platform::process::exit(0)
}

fn main() {
    platform::println!("core.service: start");

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
