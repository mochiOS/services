//! Real delegated endpoint authority after dropping all ambient IPC grants.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("delegated-ipc: requires mochiOS");
}

#[cfg(target_os = "mochios")]
mod native {
    use mochi_user_platform as p;
    use mochi_user_syscall::{NativeError, SyscallNumber as S};

    fn denied<T: core::fmt::Debug>(result: p::syscall::SysResult<T>, error: NativeError) {
        assert_eq!(result.unwrap_err().native_error(), Some(error));
    }

    fn attachments(entries: &[(u32, u64)]) -> p::ipc::IpcObjectHandles {
        let mut result = p::ipc::IpcObjectHandles::default();
        result.count = entries.len() as u32;
        for (slot, &(handle, rights)) in result.handles.iter_mut().zip(entries) {
            *slot = p::ipc::IpcObjectHandle {
                handle,
                rights,
                reserved: 0,
            };
        }
        result
    }

    fn ram(bytes: &[u8]) -> p::memory_object::MemoryObject {
        let object = p::memory_object::MemoryObject::create_resizable(bytes.len() as u64).unwrap();
        assert_eq!(
            p::handle::write_at(object.handle(), bytes, 0).unwrap(),
            bytes.len()
        );
        object
    }

    fn receive(endpoint: u64, expected_sender: u64, expected: &[u8]) -> p::ipc::IpcObjectHandles {
        let mut bytes = [0; 64];
        let mut handles = p::ipc::IpcObjectHandles::default();
        let message = p::ipc::wait_object_handles(endpoint, &mut bytes, &mut handles).unwrap();
        assert_eq!(message >> 32, expected_sender);
        assert_eq!(&bytes[..message as u32 as usize], expected);
        assert_eq!(handles.delivery_flags, p::ipc::IPC_DELIVERY_ENDPOINT_HANDLE);
        handles
    }

    fn server(parent: u64) -> ! {
        unsafe {
            libc::alarm(90);
        }
        let global = p::ipc::create().unwrap();
        let local = p::ipc::create_handle().unwrap();
        let mut handles = attachments(&[
            (local, mnu_abi::HANDLE_RIGHT_SEND),
            (local, mnu_abi::HANDLE_RIGHT_WAIT),
        ]);
        let mut reply = [0; 16];
        let message = p::ipc::call_object_handles(
            u32::try_from(parent).unwrap(),
            &global.to_le_bytes(),
            &mut reply,
            &mut handles,
        )
        .unwrap();
        assert_eq!(&reply[..message as u32 as usize], b"ready");
        assert_eq!(handles.count, 0);

        let handles = receive(global, parent, b"plain");
        assert_eq!(handles.count, 0);
        p::ipc::reply(parent, b"pong").unwrap();

        let handles = receive(global, parent, b"object");
        assert_eq!(handles.count, 1);
        let input = handles.handles[0];
        assert_eq!(input.rights, mnu_abi::HANDLE_RIGHT_READ);
        assert_eq!(p::handle::rights(input.handle).unwrap(), input.rights);
        let mut bytes = [0; 13];
        assert_eq!(
            p::handle::read_at(input.handle, &mut bytes, 0).unwrap(),
            bytes.len()
        );
        assert_eq!(&bytes, b"delegated RAM");
        denied(
            p::handle::write_at(input.handle, b"x", 0),
            NativeError::AccessDenied,
        );
        p::handle::close(input.handle).unwrap();
        let output = ram(b"reply RAM");
        p::ipc::reply_object_handles(
            parent,
            b"object reply",
            &attachments(&[(output.handle(), mnu_abi::HANDLE_RIGHT_READ)]),
        )
        .unwrap();
        drop(output);

        let handles = receive(global, parent, b"done");
        assert_eq!(handles.count, 0);
        p::handle::close(local).unwrap();
        unsafe { libc::_exit(0) }
    }

    pub fn run() {
        unsafe {
            libc::alarm(120);
        }
        let parent = p::ipc::create().unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            server(parent);
        }

        let mut bytes = [0; 8];
        let mut handles = p::ipc::IpcObjectHandles::default();
        let message = p::ipc::wait_object_handles(parent, &mut bytes, &mut handles).unwrap();
        assert_eq!(message as u32, 8);
        let global = u64::from_le_bytes(bytes);
        assert_eq!(message >> 32, global);
        assert_eq!(handles.delivery_flags, 0);
        assert_eq!(handles.count, 2);
        let sender = handles.handles[0];
        let waiter = handles.handles[1];
        assert_eq!(sender.rights, mnu_abi::HANDLE_RIGHT_SEND);
        assert_eq!(waiter.rights, mnu_abi::HANDLE_RIGHT_WAIT);
        assert_eq!(p::handle::rights(sender.handle).unwrap(), sender.rights);
        assert_eq!(p::handle::rights(waiter.handle).unwrap(), waiter.rights);
        p::ipc::reply(global, b"ready").unwrap();

        for name in ["ipc.client", "ipc.server"] {
            assert_eq!(
                p::capability::query(name.as_ptr() as u64, name.len() as u64).unwrap(),
                1
            );
            p::syscall::call2(S::CapDrop, name.as_ptr() as u64, name.len() as u64).unwrap();
        }
        let mut reply = [0; 32];
        denied(
            p::ipc::call(global, b"forbidden", &mut reply),
            NativeError::AccessDenied,
        );
        denied(
            p::ipc::send(global, b"forbidden"),
            NativeError::AccessDenied,
        );
        denied(
            p::ipc::call_object_handles(
                u32::try_from(global).unwrap(),
                b"forbidden",
                &mut reply,
                &mut p::ipc::IpcObjectHandles::default(),
            ),
            NativeError::AccessDenied,
        );
        denied(
            p::ipc::send_object_handles(global, b"forbidden", &p::ipc::IpcObjectHandles::default()),
            NativeError::AccessDenied,
        );
        denied(
            p::ipc::call(waiter.handle as u64, b"forbidden", &mut reply),
            NativeError::AccessDenied,
        );
        let mut forged = p::ipc::IpcObjectHandles::default();
        forged.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
        denied(
            p::ipc::send_object_handles(sender.handle as u64, b"forbidden", &forged),
            NativeError::InvalidArgument,
        );
        p::io::stdout(b"delegated-ipc: PASS ambient IPC dropped; global IDs, missing SEND and forged origin refused\n").unwrap();

        let message = p::ipc::call(sender.handle as u64, b"plain", &mut reply).unwrap();
        assert_eq!(&reply[..message as u32 as usize], b"pong");
        let input = ram(b"delegated RAM");
        let mut handles = attachments(&[(input.handle(), mnu_abi::HANDLE_RIGHT_READ)]);
        let message =
            p::ipc::call_object_handles(sender.handle, b"object", &mut reply, &mut handles)
                .unwrap();
        assert_eq!(&reply[..message as u32 as usize], b"object reply");
        assert_eq!(handles.count, 1);
        assert_eq!(handles.delivery_flags, 0);
        let output = handles.handles[0];
        assert_eq!(output.rights, mnu_abi::HANDLE_RIGHT_READ);
        assert_eq!(p::handle::rights(output.handle).unwrap(), output.rights);
        let mut bytes = [0; 9];
        assert_eq!(
            p::handle::read_at(output.handle, &mut bytes, 0).unwrap(),
            bytes.len()
        );
        assert_eq!(&bytes, b"reply RAM");
        denied(
            p::handle::write_at(output.handle, b"x", 0),
            NativeError::AccessDenied,
        );
        denied(
            p::handle::duplicate(output.handle, output.rights),
            NativeError::AccessDenied,
        );
        denied(
            p::ipc::send_object_handles(
                sender.handle as u64,
                b"forbidden",
                &attachments(&[(output.handle, output.rights)]),
            ),
            NativeError::AccessDenied,
        );
        p::handle::close(output.handle).unwrap();
        drop(input);
        p::ipc::send_object_handles(
            sender.handle as u64,
            b"done",
            &p::ipc::IpcObjectHandles::default(),
        )
        .unwrap();

        let mut status = -1;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        denied(
            p::ipc::call(sender.handle as u64, b"stale", &mut reply),
            NativeError::NotFound,
        );
        for name in ["ipc.client", "ipc.server"] {
            assert_eq!(
                p::capability::query(name.as_ptr() as u64, name.len() as u64).unwrap(),
                0
            );
        }
        p::handle::close(sender.handle).unwrap();
        p::handle::close(waiter.handle).unwrap();
        unsafe {
            libc::alarm(0);
        }
        p::io::stdout(b"delegated-ipc: PASS calls, attenuated RAM request/reply, async send, POSIX wait, stale generation and no ambient authority\n").unwrap();
    }
}

#[cfg(target_os = "mochios")]
fn main() {
    native::run();
}
