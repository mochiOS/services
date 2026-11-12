use appcore::process::{Command, Executable, Stdio};
use mochi_user_platform as p;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};
fn main() {
    std::panic::set_hook(Box::new(|info| {
        if let Ok(mut result) = OpenOptions::new()
            .append(true)
            .open("/tmp/executable-api-results.log")
        {
            let _ = writeln!(result, "EXE-API FAIL panic: {info}");
        }
    }));
    let Ok(mut result) = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open("/tmp/executable-api-results.log")
    else {
        return;
    };
    p::logln!("EXE-API BEGIN");
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> std::io::Result<()> {
        assert!(Executable::main("/bin/sh").is_err());
        assert!(Executable::main("missing").is_err());
        assert!(Executable::main("forbidden").is_err());
        assert!(Executable::dependency("missing").is_err());
        assert!(Executable::dependency("bad-abi").is_err());
        writeln!(result, "selections begin")?;
        for (exe, expected) in [
            (Executable::main("worker")?, "owned-helper\n"),
            (
                Executable::dependency("external-worker")?,
                "external-helper\n",
            ),
        ] {
            writeln!(result, "spawn begin {expected:?}")?;
            let mut child = Command::new(exe).stdout(Stdio::Piped).env_clear().spawn()?;
            writeln!(result, "spawn committed")?;
            let mut output = String::new();
            child.stdout.take().unwrap().read_to_string(&mut output)?;
            assert_eq!(output, expected);
            assert!(child.wait()?.success());
            assert!(child.wait()?.success());
        }
        let output = OpenOptions::new()
            .create(true)
            .write(true)
            .open("/tmp/executable-api-fd.log")?;
        let mut cmd = Command::new(Executable::main("worker")?);
        cmd.arg("7").inherit_fd(output.as_fd(), 7)?;
        assert!(cmd.spawn()?.wait()?.success());
        assert_eq!(
            std::fs::read_to_string("/tmp/executable-api-fd.log")?,
            "owned-helper\n"
        );
        // Real WebKit transport: packet boundaries, CLOEXEC source sockets,
        // explicitly delegated child FD 3, and a bidirectional native roundtrip.
        let mut pair = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let server = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        let client = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        let mut command = Command::new(Executable::dependency("external-worker")?);
        command
            .arg("ipc")
            .arg("3")
            .env_clear()
            .inherit_fd(client.as_fd(), 3)?;
        let mut child = command.spawn()?;
        drop(client);
        assert_eq!(
            unsafe { libc::send(server.as_raw_fd(), b"host".as_ptr().cast(), 4, 0) },
            4
        );
        let mut reply = [0; 64];
        let length = unsafe {
            libc::recv(
                server.as_raw_fd(),
                reply.as_mut_ptr().cast(),
                reply.len(),
                0,
            )
        };
        assert_eq!(length, 16);
        assert_eq!(&reply[..16], b"external-helper\n");
        assert!(child.wait()?.success());
        writeln!(result, "SOCK_SEQPACKET FD3 roundtrip PASS")?;
        Ok(())
    }));
    match run {
        Ok(Ok(())) => {
            p::logln!("EXE-API PASS");
            writeln!(result, "EXE-API PASS").unwrap();
        }
        other => {
            p::logln!("EXE-API FAIL {:?}", other);
            writeln!(result, "EXE-API FAIL {other:?}").unwrap();
        }
    }
}
