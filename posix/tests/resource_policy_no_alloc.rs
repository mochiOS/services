use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as wire;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static MONITOR: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
struct Allocator;
fn record() {
    if MONITOR.try_with(Cell::get).unwrap_or(false) {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
    }
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record();
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        unsafe { System.realloc(pointer, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
struct Monitored;
impl Monitored {
    fn enter() -> Self {
        ALLOCATIONS.with(|count| count.set(0));
        MONITOR.with(|monitor| assert!(!monitor.replace(true)));
        Self
    }
}
impl Drop for Monitored {
    fn drop(&mut self) {
        MONITOR.with(|monitor| monitor.set(false));
    }
}

struct State {
    mode: Cell<u8>,
    closes: Cell<usize>,
    capacity: Cell<usize>,
}
struct Endpoint<'a>(&'a State);
impl Transport for Endpoint<'_> {
    type Error = ();
    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = wire::decode(request).unwrap();
        if header.opcode == wire::OP_RESOURCE_LIMIT {
            let query = wire::decode_resource_limit_request(payload).unwrap();
            assert_eq!(
                (query.process_id, query.resource, query.flags),
                (0, wire::RLIMIT_AS, 0)
            );
            let mut body = [0; wire::RESOURCE_LIMIT_LEN];
            wire::encode_resource_limit(wire::ResourceLimit::INFINITY, &mut body).unwrap();
            return Ok(wire::encode(
                wire::Header {
                    opcode: wire::OP_STATUS,
                    request_id: header.request_id,
                    payload_len: body.len() as u32,
                    ..Default::default()
                },
                &body,
                response,
            )
            .unwrap());
        }
        assert_eq!(header.opcode, wire::OP_SESSION_REGISTER);
        assert!(payload.is_empty());
        Ok(wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: header.request_id,
                ..Default::default()
            },
            &[],
            response,
        )
        .unwrap())
    }
}
impl ObjectTransport for Endpoint<'_> {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        assert_eq!(handle, 9);
        self.0.closes.set(self.0.closes.get() + 1);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = wire::decode(request).unwrap();
        if header.opcode == wire::OP_PING {
            assert!(handles.is_empty());
            self.0.capacity.set(response.len());
            return Ok(wire::encode(
                wire::Header {
                    opcode: wire::OP_STATUS,
                    request_id: header.request_id,
                    ..Default::default()
                },
                &[],
                response,
            )
            .unwrap());
        }
        assert_eq!(header.opcode, wire::OP_RESOURCE_POLICY);
        assert!(payload.is_empty() && handles.is_empty());
        self.0.capacity.set(response.len());
        let mode = self.0.mode.get();
        let attachment = ObjectHandleAttachment {
            handle: 9,
            rights: wire::resource_policy::READER_RIGHTS | if mode == 1 { 2 } else { 0 },
        };
        if mode != 6 {
            handles.push(attachment).unwrap();
        }
        if mode == 7 {
            handles.push(attachment).unwrap();
        }
        if mode == 2 {
            return Err(());
        }
        let payload = if mode == 5 { &[1u8][..] } else { &[][..] };
        Ok(wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: header.request_id + u64::from(mode == 3),
                status: if mode == 4 { -5 } else { 0 },
                payload_len: payload.len() as u32,
                ..Default::default()
            },
            payload,
            response,
        )
        .unwrap())
    }
}

#[test]
fn bootstrap_discovery_validation_and_cleanup_do_not_touch_the_allocator() {
    let state = State {
        mode: Cell::new(0),
        closes: Cell::new(0),
        capacity: Cell::new(0),
    };
    let client = Client::new(Endpoint(&state));
    for mode in 0..8 {
        state.mode.set(mode);
        state.closes.set(0);
        let result;
        {
            let _monitor = Monitored::enter();
            client.register_session().unwrap();
            assert_eq!(
                client.resource_limit(0, wire::RLIMIT_AS, None).unwrap(),
                wire::ResourceLimit::INFINITY
            );
            result = client.resource_policy_handle();
        }
        assert_eq!(
            ALLOCATIONS.with(Cell::get),
            0,
            "allocator used by mode {mode}"
        );
        assert_eq!(
            state.capacity.get(),
            256,
            "fixed-size page discovery reserved a path-sized frame"
        );
        if mode == 0 {
            assert_eq!(
                result,
                Ok(ObjectHandleAttachment {
                    handle: 9,
                    rights: wire::resource_policy::READER_RIGHTS
                })
            );
        } else {
            assert!(result.is_err());
            if mode == 2 {
                assert_eq!(result, Err(ClientError::Transport(())));
            }
        }
        assert_eq!(state.closes.get(), usize::from(mode != 0 && mode != 6));
    }
}

#[test]
fn object_frame_selection_covers_both_payload_boundaries_without_allocating() {
    let state = State {
        mode: Cell::new(0),
        closes: Cell::new(0),
        capacity: Cell::new(0),
    };
    let client = Client::new(Endpoint(&state));
    let request = [0x5a; wire::MAX_CONTROL_PAYLOAD_LEN];
    let mut response = [0; 225];
    for (input, output, capacity) in [
        (0, 0, 256),
        (224, 224, 256),
        (225, 0, wire::CONTROL_MESSAGE_LEN),
        (0, 225, wire::CONTROL_MESSAGE_LEN),
        (wire::MAX_CONTROL_PAYLOAD_LEN, 0, wire::CONTROL_MESSAGE_LEN),
    ] {
        let result;
        {
            let _monitor = Monitored::enter();
            result = client.request_with_handles(
                wire::OP_PING,
                0,
                &request[..input],
                &mut response[..output],
                &mut ObjectHandles::new(),
            );
        }
        assert_eq!(result, Ok(0));
        assert_eq!(state.capacity.get(), capacity);
        assert_eq!(ALLOCATIONS.with(Cell::get), 0);
    }
}
