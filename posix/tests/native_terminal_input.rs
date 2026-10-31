//! Real interactive terminal fixture; run by the normal Terminal/msh path.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-terminal-input: requires mochiOS");
}

#[cfg(target_os = "mochios")]
const _: [(); 56] = [(); core::mem::size_of::<libc::termios>()];
#[cfg(target_os = "mochios")]
const _: [(); 16] = [(); core::mem::offset_of!(libc::termios, c_cc)];
#[cfg(target_os = "mochios")]
const _: [(); 48] = [(); core::mem::offset_of!(libc::termios, c_ispeed)];
#[cfg(target_os = "mochios")]
const _: [(); 20] = [(); libc::SIGCHLD as usize];
#[cfg(target_os = "mochios")]
const _: [(); 18] = [(); libc::SIGTSTP as usize];

#[cfg(target_os = "mochios")]
fn main() {
    use std::io::{self, Read, Write};
    unsafe {
        libc::alarm(180);
    }
    let mode = std::env::args().nth(1).unwrap_or_else(|| "read".into());
    if mode == "copy" {
        io::copy(&mut io::stdin().lock(), &mut io::stdout().lock()).unwrap();
        return;
    }
    assert_eq!(unsafe { libc::isatty(0) }, 1);
    assert_eq!(
        unsafe { libc::fcntl(0, libc::F_GETFL) } & libc::O_NONBLOCK,
        0
    );
    if mode != "background" {
        assert_eq!(unsafe { libc::tcgetpgrp(0) }, unsafe { libc::getpgrp() });
        assert_eq!(unsafe { libc::getpgrp() }, unsafe { libc::getpid() });
    }
    let mut size = std::mem::MaybeUninit::uninit();
    assert_eq!(unsafe { libc::tcgetwinsize(0, size.as_mut_ptr()) }, 0);
    let size = unsafe { size.assume_init() };
    assert!(size.ws_row > 1 && size.ws_col > 1);
    println!(
        "terminal-input-311: {mode} READY {}x{}",
        size.ws_col, size.ws_row
    );
    io::stdout().flush().unwrap();
    match mode.as_str() {
        "read" | "background" => {
            let mut line = String::new();
            io::stdin().read_line(&mut line).unwrap();
            assert_eq!(
                line,
                if mode == "read" {
                    "child input311\n"
                } else {
                    "bg input311\n"
                }
            );
            println!("terminal-input-311: {mode} PASS");
        }
        "raw" | "stop" => {
            let mut attributes = std::mem::MaybeUninit::uninit();
            assert_eq!(unsafe { libc::tcgetattr(0, attributes.as_mut_ptr()) }, 0);
            let mut attributes = unsafe { attributes.assume_init() };
            unsafe {
                libc::cfmakeraw(&mut attributes);
            }
            assert_eq!(unsafe { libc::tcsetattr(0, libc::TCSANOW, &attributes) }, 0);
            if mode == "stop" {
                assert_eq!(unsafe { libc::raise(libc::SIGTSTP) }, 0);
                let mut resumed = std::mem::MaybeUninit::uninit();
                assert_eq!(unsafe { libc::tcgetattr(0, resumed.as_mut_ptr()) }, 0);
                assert_eq!(unsafe { resumed.assume_init() }.c_lflag & libc::ICANON, 0);
                println!("terminal-input-311: stop RESUMED");
            } else {
                println!("terminal-input-311: raw INPUT_READY");
                io::stdout().flush().unwrap();
                let mut bytes = [0; 3];
                io::stdin().read_exact(&mut bytes).unwrap();
                assert_eq!(bytes, *b"\x1b[A");
                println!("terminal-input-311: raw PASS");
            }
            // Deliberately leave raw mode and a shared nonblocking status flag.
            let flags = unsafe { libc::fcntl(0, libc::F_GETFL) };
            assert_eq!(
                unsafe { libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
        "interrupt" => {
            let mut line = String::new();
            io::stdin().read_line(&mut line).unwrap();
            panic!("SIGINT did not terminate foreground input: {line:?}");
        }
        _ => panic!("unknown terminal fixture mode"),
    }
    unsafe {
        libc::alarm(0);
    }
}
