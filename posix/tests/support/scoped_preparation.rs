use super::*;
use mochios_posix_client::image_preparation::{Backend, Environment, Preparation, scoped::Scoped};
use mochios_posix_client::{
    Client as PosixClient, ClientError, ObjectHandles, ObjectTransport, Transport,
};
use posix_protocol::read_scope as wire;

struct TransportState {
    deny: bool,
    calls: RefCell<Vec<u16>>,
}
impl Transport for TransportState {
    type Error = i32;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, i32> {
        panic!("objects required")
    }
}
impl ObjectTransport for TransportState {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        exec_image::Runtime::close(handle);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        objects: &mut ObjectHandles<u32>,
    ) -> Result<usize, i32> {
        assert!(DEFER.get() > 0);
        let (header, payload) = posix_protocol::decode(request).unwrap();
        self.calls.borrow_mut().push(header.opcode);
        let source = objects.get(0).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(
            source.rights,
            if header.opcode == posix_protocol::OP_FSTAT {
                wire::FILE_RIGHTS
            } else {
                wire::ATTACH_RIGHTS
            }
        );
        objects.clear();
        let mut bytes = [0; posix_protocol::FILE_STATUS_LEN];
        let mut size = 0;
        let mut status = 0;
        match header.opcode {
            wire::OP_INFO => {
                assert_eq!(source.handle, 777);
                size = posix_protocol::SESSION_INFO_LEN;
                posix_protocol::encode_session_info(
                    posix_protocol::SessionInfo {
                        effective_uid: 501,
                        ..Default::default()
                    },
                    &mut bytes[..size],
                )
                .unwrap();
            }
            wire::OP_OPEN => {
                assert_eq!(source.handle, 777);
                let open = wire::decode_open(payload).unwrap();
                STATE.with_borrow_mut(|state| state.library_paths.push(open.path.to_vec()));
                status = if self.deny {
                    -13
                } else {
                    STATE.with_borrow(|state| {
                        match state
                            .libraries
                            .iter()
                            .position(|(path, _)| path == open.path)
                        {
                            Some(index) => {
                                objects
                                    .push(ObjectHandleAttachment {
                                        handle: 200 + index as u32,
                                        rights: wire::FILE_RIGHTS,
                                    })
                                    .unwrap();
                                0
                            }
                            None => -2,
                        }
                    })
                };
            }
            posix_protocol::OP_FSTAT => {
                assert!(source.handle >= 200 && source.handle < 300);
                size = posix_protocol::FILE_STATUS_LEN;
                posix_protocol::encode_file_status(
                    posix_protocol::FileStatus {
                        mode: 0o100444,
                        ..Default::default()
                    },
                    &mut bytes[..size],
                )
                .unwrap();
            }
            _ => panic!("ambient or unexpected operation {}", header.opcode),
        }
        posix_protocol::encode(
            posix_protocol::Header {
                opcode: posix_protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: size as u32,
                status,
                ..Default::default()
            },
            &bytes[..size],
            response,
        )
        .map_err(|_| EIO)
    }
}
fn translate(error: ClientError<i32>) -> i32 {
    match error {
        ClientError::Remote(status) => {
            mochios_posix_client::newlib_errno::from_status(status as i64)
        }
        ClientError::Transport(status) => status,
        _ => EIO,
    }
}

#[test]
fn shared_preparer_uses_delegated_identity_and_never_falls_back_to_ambient_open() {
    let (root, library) = dependency_fixture(&[], &[]);
    for deny in [false, true] {
        reset(0);
        STATE.with_borrow_mut(|state| {
            state.bytes = root.clone();
            state.libraries = vec![(b"/usr/lib/libscope.so".to_vec(), library.clone())];
        });
        let client = PosixClient::new(TransportState {
            deny,
            calls: RefCell::new(Vec::new()),
        });
        let scope = Scoped::new(
            &client,
            ObjectHandleAttachment {
                handle: 777,
                rights: wire::TOKEN_RIGHTS,
            },
            &exec_image::Runtime,
            translate,
        )
        .unwrap();
        assert_eq!(
            (scope.identity().real_uid, scope.identity().effective_uid),
            (0, 501)
        );
        let mut owner = Preparation::default();
        let result = scope.prepare(
            &mut owner,
            19,
            Environment {
                library_path: Some(b"/untrusted"),
                preload: Some(b"/ignored"),
                audit: Some(b"/ignored"),
            },
        );
        if deny {
            assert!(matches!(result, Err(EACCES)));
            assert!(
                !client
                    .transport()
                    .calls
                    .borrow()
                    .contains(&posix_protocol::OP_FSTAT)
            );
        } else {
            let prepared = result.unwrap();
            assert_eq!(prepared.image, 29);
            assert!(prepared.executable.is_some());
            assert!(
                client
                    .transport()
                    .calls
                    .borrow()
                    .contains(&posix_protocol::OP_FSTAT)
            );
            assert!(matches!(
                scope.prepare(&mut owner, 19, Environment::default()),
                Err(EINVAL)
            ));
        }
        drop(owner);
        STATE.with_borrow(|state| {
            assert_eq!(
                state.identity_queries, 0,
                "must not query the receiver's credentials"
            );
            assert_eq!(state.opened, 0, "must not open using the ambient backend");
            assert_eq!(
                state.library_paths,
                [
                    b"/lib/libscope.so".to_vec(),
                    b"/usr/lib/libscope.so".to_vec(),
                ]
            );
            assert!(
                !state.closed.contains(&777),
                "borrowed scope stays with its caller"
            );
            assert_eq!(
                state.closed.iter().filter(|&&handle| handle == 200).count(),
                usize::from(!deny)
            );
        });
    }
}

#[derive(Default)]
struct Allocations {
    fail_at: usize,
    calls: usize,
    live: Vec<usize>,
}
thread_local! { static ALLOCATIONS: RefCell<Allocations> = RefCell::new(Allocations::default()); }
struct FaultAllocation;
// Delegate native references and critical sections to the production adapter.
// Only allocation failure is injected; every successful allocation still uses
// the same malloc/free pair and max_align_t storage as the actual runtime.
unsafe impl Backend for FaultAllocation {
    fn critical<T>(operation: impl FnOnce() -> T) -> T {
        exec_image::Runtime::critical(operation)
    }
    fn allocate(length: usize) -> *mut u8 {
        assert!(DEFER.get() > 0);
        ALLOCATIONS.with_borrow_mut(|state| {
            state.calls += 1;
            if state.calls == state.fail_at {
                return ptr::null_mut();
            }
            let pointer = exec_image::Runtime::allocate(length);
            if !pointer.is_null() {
                state.live.push(pointer as usize);
            }
            pointer
        })
    }
    unsafe fn deallocate(pointer: *mut u8) {
        assert!(DEFER.get() > 0);
        if !pointer.is_null() {
            ALLOCATIONS.with_borrow_mut(|state| {
                let index = state
                    .live
                    .iter()
                    .position(|value| *value == pointer as usize)
                    .expect("must free a live owned allocation exactly once");
                state.live.swap_remove(index);
            });
        }
        unsafe { exec_image::Runtime::deallocate(pointer) };
    }
    fn close(handle: u32) {
        exec_image::Runtime::close(handle)
    }
    fn read_at(&self, image: u32, output: &mut [u8], offset: usize) -> Result<usize, i32> {
        exec_image::Runtime.read_at(image, output, offset)
    }
    fn open_library(&self, path: &[u8]) -> Result<ObjectHandleAttachment<u32>, i32> {
        exec_image::Runtime.open_library(path)
    }
    fn validate_library(&self, file: ObjectHandleAttachment<u32>) -> Result<(), i32> {
        exec_image::Runtime.validate_library(file)
    }
    fn entropy(&self, output: &mut [u8]) -> Result<(), i32> {
        exec_image::Runtime.entropy(output)
    }
    fn create_image(&self, length: usize) -> Result<u32, i32> {
        exec_image::Runtime.create_image(length)
    }
    fn write_at(&self, image: u32, bytes: &[u8], offset: usize) -> Result<usize, i32> {
        exec_image::Runtime.write_at(image, bytes, offset)
    }
    fn readonly_image(&self, image: u32) -> Result<u32, i32> {
        exec_image::Runtime.readonly_image(image)
    }
}

#[test]
fn each_allocation_failure_reclaims_partial_loader_state_without_closing_the_borrowed_root() {
    let (root, library) = dependency_fixture(&[], &[]);
    for failure in 1..128 {
        reset(0);
        STATE.with_borrow_mut(|state| {
            state.bytes = root.clone();
            state.libraries = vec![(b"/lib/libscope.so".to_vec(), library.clone())];
        });
        ALLOCATIONS.with_borrow_mut(|state| {
            *state = Allocations {
                fail_at: failure,
                ..Default::default()
            }
        });
        let mut owner = Preparation::<FaultAllocation>::default();
        let result = owner.prepare(
            &FaultAllocation,
            19,
            Environment::default(),
            Default::default(),
        );
        let success = result.is_ok();
        if !success {
            assert!(matches!(result, Err(ENOMEM)), "failure point {failure}");
        }
        drop(owner);
        ALLOCATIONS.with_borrow(|state| assert!(state.live.is_empty(), "failure point {failure}"));
        STATE.with_borrow(|state| {
            assert!(!state.closed.contains(&19));
            for handle in [200, 28, 29] {
                assert!(
                    state
                        .closed
                        .iter()
                        .filter(|&&closed| closed == handle)
                        .count()
                        <= 1
                );
            }
        });
        if success {
            assert!(failure > 10);
            return;
        }
    }
    panic!("did not reach the complete allocation sequence");
}
