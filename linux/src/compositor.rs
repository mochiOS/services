use mochi_user_platform as platform;

const SERVICE_NAME: &str = "compositor.service";
const PAGE_SIZE: usize = 4096;
const OP_CREATE_SURFACE: u32 = 1;
const OP_ATTACH_BUFFER: u32 = 2;
const OP_DAMAGE: u32 = 3;
const OP_COMMIT: u32 = 4;
const OP_DESTROY_SURFACE: u32 = 6;
const ROLE_TOPLEVEL: u32 = 1;
const PIXEL_FORMAT_XRGB8888: u32 = 1;
const OP_SET_TITLE: u32 = 10;
const MAX_WINDOW_TITLE_BYTES: usize = 64;

#[derive(Debug)]
pub(crate) enum CompositorError {
    Unavailable,
    InvalidReply,
    InvalidSize,
}

pub(crate) struct Surface {
    compositor: u64,
    token: u64,
    buffer: Option<SharedBuffer>,
}

impl Surface {
    pub(crate) fn create(width: u16, height: u16) -> Result<Self, CompositorError> {
        let compositor = platform::process::find_by_name(SERVICE_NAME)
            .map_err(|_| CompositorError::Unavailable)?;
        if compositor == 0 {
            return Err(CompositorError::Unavailable);
        }
        let endpoint = platform::ipc::create().map_err(|_| CompositorError::Unavailable)?;
        let mut request = [0u8; 24];
        put_u32(&mut request, 0, OP_CREATE_SURFACE);
        put_u32(&mut request, 4, ROLE_TOPLEVEL);
        put_u32(&mut request, 8, u32::from(width));
        put_u32(&mut request, 12, u32::from(height));
        put_u64(&mut request, 16, endpoint);
        let reply = call(compositor, &request)?;
        Ok(Self {
            compositor,
            token: read_u64(&reply, 4),
            buffer: None,
        })
    }

    pub(crate) fn present(
        &mut self,
        width: u16,
        height: u16,
        frame: &[u8],
    ) -> Result<(), CompositorError> {
        let needed = usize::from(width)
            .checked_mul(usize::from(height))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(CompositorError::InvalidSize)?;
        if frame.len() != needed {
            return Err(CompositorError::InvalidSize);
        }
        let replace = self
            .buffer
            .as_ref()
            .is_none_or(|buffer| buffer.width != width || buffer.height != height);
        if replace {
            self.buffer = Some(SharedBuffer::allocate(width, height)?);
            let mut request = [0u8; 28];
            put_u32(&mut request, 0, OP_ATTACH_BUFFER);
            put_u64(&mut request, 4, self.token);
            put_u32(&mut request, 12, u32::from(width));
            put_u32(&mut request, 16, u32::from(height));
            put_u32(&mut request, 20, u32::from(width));
            put_u32(&mut request, 24, PIXEL_FORMAT_XRGB8888);
            call(self.compositor, &request)?;
            self.buffer
                .as_mut()
                .ok_or(CompositorError::InvalidSize)?
                .send_to(self.compositor)?;
        }
        self.buffer
            .as_mut()
            .ok_or(CompositorError::InvalidSize)?
            .copy_from(frame)?;

        let mut damage = [0u8; 28];
        put_u32(&mut damage, 0, OP_DAMAGE);
        put_u64(&mut damage, 4, self.token);
        put_u32(&mut damage, 20, u32::from(width));
        put_u32(&mut damage, 24, u32::from(height));
        call(self.compositor, &damage)?;

        let mut commit = [0u8; 12];
        put_u32(&mut commit, 0, OP_COMMIT);
        put_u64(&mut commit, 4, self.token);
        call(self.compositor, &commit)?;
        Ok(())
    }

    pub(crate) const fn token(&self) -> u64 {
        self.token
    }

    pub(crate) fn set_title(&self, title: &str) -> Result<(), CompositorError> {
        let title = title.as_bytes();
        if title.len() > MAX_WINDOW_TITLE_BYTES {
            return Err(CompositorError::InvalidSize);
        }
        let mut request = [0u8; 16 + MAX_WINDOW_TITLE_BYTES];
        put_u32(&mut request, 0, OP_SET_TITLE);
        put_u64(&mut request, 4, self.token);
        put_u32(&mut request, 12, title.len() as u32);
        request[16..16 + title.len()].copy_from_slice(title);
        call(self.compositor, &request[..16 + title.len()])?;
        Ok(())
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        let mut request = [0u8; 12];
        put_u32(&mut request, 0, OP_DESTROY_SURFACE);
        put_u64(&mut request, 4, self.token);
        let _ = call(self.compositor, &request);
    }
}

struct SharedBuffer {
    address: u64,
    byte_capacity: usize,
    page_count: usize,
    width: u16,
    height: u16,
    sent: bool,
}

impl SharedBuffer {
    fn allocate(width: u16, height: u16) -> Result<Self, CompositorError> {
        let bytes = usize::from(width)
            .checked_mul(usize::from(height))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(CompositorError::InvalidSize)?;
        let page_count = bytes
            .checked_add(PAGE_SIZE - 1)
            .map(|rounded| rounded / PAGE_SIZE)
            .filter(|count| *count != 0)
            .ok_or(CompositorError::InvalidSize)?;
        let address = platform::memory::alloc_shared_page_count(page_count)
            .map_err(|_| CompositorError::Unavailable)?;
        Ok(Self {
            address,
            byte_capacity: page_count * PAGE_SIZE,
            page_count,
            width,
            height,
            sent: false,
        })
    }

    fn copy_from(&mut self, frame: &[u8]) -> Result<(), CompositorError> {
        if frame.len() > self.byte_capacity {
            return Err(CompositorError::InvalidSize);
        }
        // SAFETY: alloc_shared_page_count returned this writable mapping for exactly
        // byte_capacity bytes, and the mapping remains owned by this buffer.
        let destination =
            unsafe { core::slice::from_raw_parts_mut(self.address as *mut u8, self.byte_capacity) };
        destination[..frame.len()].copy_from_slice(frame);
        Ok(())
    }

    fn send_to(&mut self, compositor: u64) -> Result<(), CompositorError> {
        if !self.sent {
            platform::ipc::send_page_count(compositor, self.page_count, self.address)
                .map_err(|_| CompositorError::Unavailable)?;
            self.sent = true;
        }
        Ok(())
    }
}

fn call(destination: u64, request: &[u8]) -> Result<[u8; 16], CompositorError> {
    let mut reply = [0u8; 16];
    let raw = platform::ipc::call(destination, request, &mut reply)
        .map_err(|_| CompositorError::Unavailable)?;
    if (raw as u32) < 4 {
        return Err(CompositorError::InvalidReply);
    }
    let status = read_u32(&reply, 0);
    if status != 0 {
        return Err(CompositorError::Unavailable);
    }
    Ok(reply)
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

fn read_u64(buffer: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ])
}

fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
