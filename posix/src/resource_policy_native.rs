use mochi_user_platform::{
    handle,
    memory_object::{MemoryMapping, MemoryObject},
};
use mochios_posix_protocol::{
    self as protocol,
    resource_policy::{Error, READER_RIGHTS, ResourcePolicy},
};
use posix_service::{
    OpenedObject,
    resource_policy::{Factory, Published},
};

const PAGE_BYTES: u64 = 4096;
pub struct NativeFactory;

struct Page {
    // Mapping drops before the creator's native object reference.
    mapping: MemoryMapping,
    object: MemoryObject,
}

impl core::fmt::Debug for Page {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResourcePolicyPage")
            .field("object", &self.object.handle())
            .finish_non_exhaustive()
    }
}

impl Factory<u32> for NativeFactory {
    fn create(
        &mut self,
        limits: [protocol::ResourceLimit; protocol::RLIMIT_COUNT as usize],
    ) -> Result<Box<dyn Published<u32>>, i32> {
        let policy = ResourcePolicy::new(limits).map_err(|_| -22)?;
        let object = MemoryObject::create(PAGE_BYTES).map_err(|error| error.raw() as i32)?;
        let mapping = object
            .map(
                0,
                PAGE_BYTES,
                mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE,
            )
            .map_err(|error| error.raw() as i32)?;
        // The owned shared RAM mapping is page-aligned, writable and larger
        // than the wire type. Initialize it before creating any reader Handle.
        const {
            assert!(protocol::resource_policy::BYTE_LEN <= PAGE_BYTES as usize);
        }
        unsafe {
            (mapping.address() as *mut ResourcePolicy).write(policy);
        }
        let page = Box::try_new(Page { mapping, object }).map_err(|_| -12)?;
        Ok(page)
    }
}

impl Published<u32> for Page {
    fn publish_record_locks(&self, held: bool) {
        // The constructor initialized this private writable view before any
        // read-only reader was delegated; its lifetime is owned by this Page.
        unsafe { &*(self.mapping.address() as *const ResourcePolicy) }.publish_record_locks(held);
    }

    fn publish(&self, resource: u32, limit: protocol::ResourceLimit) -> Result<(), i32> {
        // This object retains its initialized mapping for the entire borrow.
        // All contents are accessed atomically; service state serializes policy.
        let policy = unsafe { &*(self.mapping.address() as *const ResourcePolicy) };
        policy
            .publish(resource, limit)
            .map_err(|error| match error {
                Error::Busy => -11,
                Error::Exhausted => -75,
                Error::UnsupportedTarget => -38,
                _ => -5,
            })
    }

    fn delegate(&self) -> Result<OpenedObject<u32>, i32> {
        // The temporary source needs TRANSFER, but the client must not receive
        // it, DUPLICATE, WRITE or CONTROL. Kernel IPC attenuates once more.
        let handle = handle::duplicate(
            self.object.handle(),
            READER_RIGHTS | mnu_abi::HANDLE_RIGHT_TRANSFER,
        )
        .map_err(|error| error.raw() as i32)?;
        Ok(OpenedObject {
            handle,
            rights: READER_RIGHTS,
        })
    }
}
