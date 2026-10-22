use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_READ as R, HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle,
};
use posix_service::{
    OpenedObject,
    filesystem_metadata::{fstat_response, through_provider},
};
use std::cell::RefCell;
fn source() -> IpcObjectHandle {
    IpcObjectHandle {
        handle: 40,
        reserved: 0,
        rights: R | C | T,
    }
}

#[test]
fn native_filesystem_fast_path_does_not_query_the_terminal_provider() {
    for result in [Ok(123), Err(-13), Err(-5), Err(-2)] {
        assert_eq!(
            through_provider(
                source(),
                |received| {
                    assert_eq!(
                        received,
                        IpcObjectHandle {
                            rights: T,
                            ..source()
                        }
                    );
                    result
                },
                |_| panic!("not an owner rejection"),
                |_| panic!("borrowed source")
            ),
            result
        );
    }
}

#[test]
fn owner_rejection_queries_only_the_explicit_data_handle_and_closes_temporary_metadata() {
    let events = RefCell::new(Vec::new());
    let result = through_provider(
        source(),
        |received| {
            assert_eq!(received.rights, T);
            events.borrow_mut().push(("stat", received.handle));
            match received.handle {
                40 => Err(-9),
                92 => Ok(123),
                _ => panic!("unrelated object"),
            }
        },
        |received| {
            assert_eq!(
                received,
                IpcObjectHandle {
                    rights: T,
                    ..source()
                }
            );
            events.borrow_mut().push(("query", received.handle));
            Ok(OpenedObject {
                handle: 92,
                rights: T,
            })
        },
        |handle| events.borrow_mut().push(("close", handle)),
    );
    assert_eq!(result, Ok(123));
    assert_eq!(
        *events.borrow(),
        vec![("stat", 40), ("query", 40), ("stat", 92), ("close", 92)]
    );
}

#[test]
fn provider_and_metadata_stat_failures_do_not_mask_errors_or_close_the_data_reference() {
    let mut closed = Vec::new();
    assert_eq!(
        through_provider::<()>(source(), |_| Err(-9), |_| Err(-32), |h| closed.push(h)),
        Err(-32)
    );
    assert!(closed.is_empty());
    assert_eq!(
        through_provider::<()>(
            source(),
            |h| Err(if h.handle == 40 { -9 } else { -5 }),
            |_| Ok(OpenedObject {
                handle: 92,
                rights: T
            }),
            |h| closed.push(h)
        ),
        Err(-5)
    );
    assert_eq!(closed, vec![92]);
    for (handle, rights) in [(0, T), (40, T), (93, C | T)] {
        assert_eq!(
            through_provider::<()>(
                source(),
                |_| Err(-9),
                |_| Ok(OpenedObject { handle, rights }),
                |h| closed.push(h)
            ),
            Err(-5)
        );
    }
    assert_eq!(closed, vec![92, 93]);
    assert_eq!(
        through_provider::<()>(
            IpcObjectHandle {
                rights: R,
                ..source()
            },
            |_| panic!("no transfer right"),
            |_| panic!("no transfer right"),
            |_| panic!("borrowed")
        ),
        Err(-13)
    );
}

#[test]
fn status_response_preserves_posix_metadata_and_preflight_precedes_state_lock_and_image_validation()
{
    let status = mochios_posix_protocol::FileStatus {
        mode: 0o020600,
        inode: 123,
        uid: 501,
        ..Default::default()
    };
    let response = fstat_response::<u32>(17, Ok(status));
    assert_eq!(response.response.header.request_id, 17);
    assert_eq!(response.response.header.status, 0);
    assert!(response.handles.is_empty());
    assert_eq!(
        mochios_posix_protocol::decode_file_status(&response.response.payload).unwrap(),
        status
    );
    let response = fstat_response::<u32>(18, Err(-13));
    assert_eq!(response.response.header.status, -13);
    assert!(response.response.payload.is_empty());
    let source = include_str!("../src/main.rs");
    let preflight = source.split("let inspected_file = ").nth(1).unwrap();
    assert!(
        preflight
            .find("filesystem_metadata::through_provider(")
            .unwrap()
            < preflight
                .find("let mut service = service_state.lock().unwrap()")
                .unwrap()
    );
    let completion = preflight
        .split("if inspected_file.is_some()")
        .nth(1)
        .unwrap();
    assert!(
        completion.find("validate_pending_request_image(").unwrap()
            < completion
                .find("filesystem_metadata::fstat_response(")
                .unwrap()
    );
}
