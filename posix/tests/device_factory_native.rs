//! Exercise the production owned factory adapter; native calls are deterministic.
extern crate self as mochi_user_platform;
use mnu_abi::{
    HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_READ as R, HANDLE_RIGHT_SEND as S,
    HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol::device_open::Request;
use std::cell::RefCell;
#[path = "../../filesystem/src/device_factory.rs"]
mod implementation;
use implementation::{Factory, NativeFactory};
#[derive(Debug)]
pub struct Error;
pub mod memory_updates {
    pub fn native_error(_: crate::Error) -> i32 {
        32
    }
}
#[derive(Default)]
struct Calls {
    closed: Vec<u32>,
    transport_fails: bool,
    wire_status: i64,
}
thread_local! { static CALLS: RefCell<Calls> = RefCell::new(Calls::default()); }
pub mod handle {
    pub fn close(handle: u32) -> Result<(), crate::Error> {
        super::CALLS.with_borrow_mut(|calls| calls.closed.push(handle));
        Ok(())
    }
}
pub mod ipc {
    use super::*;
    pub fn call_object_handles(
        endpoint: u32,
        bytes: &[u8],
        reply: &mut [u8],
        objects: &mut IpcObjectHandles,
    ) -> Result<u64, Error> {
        assert_eq!(endpoint, 11);
        assert_eq!(
            Request::decode(bytes),
            Ok(Request {
                rights: R | D | T,
                options: 0
            })
        );
        assert_eq!(objects.count, 2);
        assert_eq!(objects.delivery_flags, 0);
        assert_eq!(objects.handles[0], object(30, T));
        assert_eq!(objects.handles[1], object(40, D | T));
        CALLS.with_borrow(|calls| {
            if calls.transport_fails {
                return Err(Error);
            }
            *objects = IpcObjectHandles::default();
            reply.copy_from_slice(&calls.wire_status.to_le_bytes());
            if calls.wire_status == 0 {
                objects.count = 1;
                objects.handles[0] = object(70, R | D | T);
            }
            Ok(8)
        })
    }
}
fn object(handle: u32, rights: u64) -> IpcObjectHandle {
    IpcObjectHandle {
        handle,
        reserved: 0,
        rights,
    }
}

#[test]
fn factory_owns_only_endpoint_and_grant_across_success_wire_error_and_transport_error() {
    for (transport_fails, wire_status) in [(false, 0), (false, -13), (true, 0)] {
        CALLS.set(Calls {
            transport_fails,
            wire_status,
            ..Calls::default()
        });
        let factory = NativeFactory::from_received(object(11, S), object(30, D | T)).unwrap();
        let result = factory.open(
            object(40, D | T),
            Request {
                rights: R | D | T,
                options: 0,
            },
        );
        if transport_fails {
            assert_eq!(result, Err(32));
        } else if wire_status != 0 {
            assert_eq!(result, Err(13));
        } else {
            assert_eq!(result, Ok(object(70, R | D | T)));
        }
        CALLS.with_borrow(|calls| assert!(calls.closed.is_empty()));
        drop(factory);
        CALLS.with_borrow(|calls| assert_eq!(calls.closed, vec![11, 30]));
    }
}

#[test]
fn invalid_received_authority_is_closed_exactly_once_without_service_discovery() {
    for (endpoint, grant, closed) in [
        (object(11, S | T), object(30, T), vec![11, 30]),
        (object(11, S), object(30, R | T), vec![11, 30]),
        (object(11, S), object(30, D), vec![11, 30]),
        (object(0, S), object(30, T), vec![30]),
        (object(11, S), object(11, T), vec![11]),
        (
            IpcObjectHandle {
                reserved: 1,
                ..object(11, S)
            },
            object(30, T),
            vec![11, 30],
        ),
    ] {
        CALLS.set(Calls::default());
        assert_eq!(
            NativeFactory::from_received(endpoint, grant).unwrap_err(),
            13
        );
        CALLS.with_borrow(|calls| assert_eq!(calls.closed, closed));
    }
}
