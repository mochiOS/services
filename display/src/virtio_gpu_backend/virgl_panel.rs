use alloc::vec::Vec;

use mochios_virtio_gpu_protocol::{
    AttachBacking, Box3d, Command, ContextResource, Rect, ResourceCreate3d, ResourceOperation,
    SetScanout, Submit3d, TransferHost3d,
};

use crate::present::{DisplayGeometry, PanelFrame};

use super::control::ControlChannel;
use super::dma::BackingStore;
use super::error::GpuError;

const CONTEXT_ID: u32 = 1;
const RENDER_TARGET_ID: u32 = 3;
const TEXTURE_ID: u32 = 4;
const VERTEX_BUFFER_ID: u32 = 5;

const PIPE_BUFFER: u32 = 0;
const PIPE_TEXTURE_2D: u32 = 2;
const FORMAT_B8G8R8A8_UNORM: u32 = 1;
const FORMAT_R32G32_FLOAT: u32 = 29;
const FORMAT_R32G32B32_FLOAT: u32 = 30;
const BIND_RENDER_TARGET: u32 = 1 << 1;
const BIND_SAMPLER_VIEW: u32 = 1 << 3;
const BIND_VERTEX_BUFFER: u32 = 1 << 4;

const CMD_CREATE_OBJECT: u32 = 1;
const CMD_BIND_OBJECT: u32 = 2;
const CMD_SET_VIEWPORT: u32 = 4;
const CMD_SET_FRAMEBUFFER: u32 = 5;
const CMD_SET_VERTEX_BUFFERS: u32 = 6;
const CMD_CLEAR: u32 = 7;
const CMD_DRAW_VBO: u32 = 8;
const CMD_SET_SAMPLER_VIEWS: u32 = 10;
const CMD_BIND_SAMPLER_STATES: u32 = 18;
const CMD_BIND_SHADER: u32 = 31;

const OBJECT_BLEND: u32 = 1;
const OBJECT_RASTERIZER: u32 = 2;
const OBJECT_DSA: u32 = 3;
const OBJECT_SHADER: u32 = 4;
const OBJECT_VERTEX_ELEMENTS: u32 = 5;
const OBJECT_SAMPLER_VIEW: u32 = 6;
const OBJECT_SAMPLER_STATE: u32 = 7;
const OBJECT_SURFACE: u32 = 8;

const SHADER_VERTEX: u32 = 0;
const SHADER_FRAGMENT: u32 = 1;
const PRIM_TRIANGLES: u32 = 4;
const CLEAR_COLOR0: u32 = 4;

const SURFACE_HANDLE: u32 = 10;
const VERTEX_SHADER_HANDLE: u32 = 11;
const FRAGMENT_SHADER_HANDLE: u32 = 12;
const VERTEX_ELEMENTS_HANDLE: u32 = 13;
const RASTERIZER_HANDLE: u32 = 14;
const BLEND_HANDLE: u32 = 15;
const DSA_HANDLE: u32 = 16;
const SAMPLER_VIEW_HANDLE: u32 = 20;
const SAMPLER_STATE_HANDLE: u32 = 21;

const VERTEX_STRIDE: u32 = 20;
const SHADER_TOKEN_BUDGET: u32 = 4096;

const VERTEX_SHADER: &str = "VERT\n\
DCL IN[0]\n\
DCL IN[1]\n\
DCL OUT[0], POSITION\n\
DCL OUT[1], GENERIC[0]\n\
MOV OUT[0], IN[0]\n\
MOV OUT[1], IN[1]\n\
END\n";

const FRAGMENT_SHADER: &str = "FRAG\n\
DCL IN[0], GENERIC[0], PERSPECTIVE\n\
DCL OUT[0], COLOR\n\
DCL SAMP[0]\n\
DCL SVIEW[0], 2D, FLOAT\n\
TEX OUT[0], IN[0], SAMP[0], 2D\n\
END\n";

pub(super) struct PanelRenderer {
    geometry: DisplayGeometry,
    render_target: BackingStore,
    texture: BackingStore,
    vertex_buffer: BackingStore,
    resources_created: usize,
    resources_attached: usize,
    validated: bool,
}

impl PanelRenderer {
    pub(super) fn initialize(
        channel: &mut ControlChannel,
        geometry: DisplayGeometry,
    ) -> Result<Self, GpuError> {
        let byte_len = geometry.byte_len().map_err(GpuError::System)?;
        let mut renderer = Self {
            geometry,
            render_target: BackingStore::allocate(byte_len).map_err(GpuError::System)?,
            texture: BackingStore::allocate(byte_len).map_err(GpuError::System)?,
            vertex_buffer: BackingStore::allocate(6 * VERTEX_STRIDE as usize)
                .map_err(GpuError::System)?,
            resources_created: 0,
            resources_attached: 0,
            validated: false,
        };
        if let Err(error) = renderer.initialize_resources(channel) {
            renderer.cleanup(channel);
            return Err(error);
        }
        Ok(renderer)
    }

    fn initialize_resources(&mut self, channel: &mut ControlChannel) -> Result<(), GpuError> {
        create_resource(
            channel,
            RENDER_TARGET_ID,
            PIPE_TEXTURE_2D,
            FORMAT_B8G8R8A8_UNORM,
            BIND_RENDER_TARGET,
            self.geometry.width,
            self.geometry.height,
            &self.render_target,
        )?;
        self.resources_created += 1;
        self.resources_attached += 1;
        create_resource(
            channel,
            TEXTURE_ID,
            PIPE_TEXTURE_2D,
            FORMAT_B8G8R8A8_UNORM,
            BIND_SAMPLER_VIEW,
            self.geometry.width,
            self.geometry.height,
            &self.texture,
        )?;
        self.resources_created += 1;
        self.resources_attached += 1;
        create_resource(
            channel,
            VERTEX_BUFFER_ID,
            PIPE_BUFFER,
            0,
            BIND_VERTEX_BUFFER,
            6 * VERTEX_STRIDE,
            1,
            &self.vertex_buffer,
        )?;
        self.resources_created += 1;
        self.resources_attached += 1;

        let vertices = fullscreen_vertices();
        self.vertex_buffer
            .write_all(&vertices)
            .map_err(GpuError::System)?;
        channel.submit_no_data(Command::TransferToHost3d(TransferHost3d {
            context_id: CONTEXT_ID,
            box_3d: Box3d {
                x: 0,
                y: 0,
                z: 0,
                width: 6 * VERTEX_STRIDE,
                height: 1,
                depth: 1,
            },
            offset: 0,
            resource_id: VERTEX_BUFFER_ID,
            level: 0,
            stride: 0,
            layer_stride: 0,
        }))?;

        let setup = setup_commands(self.geometry.width, self.geometry.height);
        channel.submit_no_data(Command::Submit3d(Submit3d {
            context_id: CONTEXT_ID,
            commands: &setup,
        }))
    }

    pub(super) fn present(
        &mut self,
        channel: &mut ControlChannel,
        scanout_id: u32,
        frame: &PanelFrame<'_>,
    ) -> Result<(), GpuError> {
        frame.validate().map_err(GpuError::System)?;
        if frame.geometry.width != self.geometry.width
            || frame.geometry.height != self.geometry.height
            || frame.geometry.stride != self.geometry.stride
        {
            return Err(GpuError::InvalidFrame);
        }
        self.texture
            .copy_rect(
                frame.pixels,
                frame.geometry.stride,
                self.geometry.stride,
                frame.damage,
            )
            .map_err(GpuError::System)?;
        let offset = u64::from(frame.damage.y)
            .checked_mul(u64::from(self.geometry.stride))
            .and_then(|pixels| pixels.checked_add(u64::from(frame.damage.x)))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(GpuError::InvalidFrame)?;
        channel.submit_no_data(Command::TransferToHost3d(TransferHost3d {
            context_id: CONTEXT_ID,
            box_3d: Box3d {
                x: frame.damage.x,
                y: frame.damage.y,
                z: 0,
                width: frame.damage.width,
                height: frame.damage.height,
                depth: 1,
            },
            offset,
            resource_id: TEXTURE_ID,
            level: 0,
            stride: self.geometry.stride.saturating_mul(4),
            layer_stride: self
                .geometry
                .stride
                .saturating_mul(self.geometry.height)
                .saturating_mul(4),
        }))?;

        let commands = frame_commands(frame.background);
        channel.submit_no_data(Command::Submit3d(Submit3d {
            context_id: CONTEXT_ID,
            commands: &commands,
        }))?;
        if !self.validated {
            self.validate_readback(channel, frame)?;
            self.validated = true;
        }
        let rect = full_rect(self.geometry);
        channel.submit_pair_no_data(
            Command::SetScanout(SetScanout {
                rect,
                scanout_id,
                resource_id: RENDER_TARGET_ID,
            }),
            Command::ResourceFlush {
                rect,
                resource_id: RENDER_TARGET_ID,
            },
        )
    }

    fn validate_readback(
        &mut self,
        channel: &mut ControlChannel,
        frame: &PanelFrame<'_>,
    ) -> Result<(), GpuError> {
        channel.submit_no_data(Command::TransferFromHost3d(TransferHost3d {
            context_id: CONTEXT_ID,
            box_3d: Box3d {
                x: 0,
                y: 0,
                z: 0,
                width: self.geometry.width,
                height: self.geometry.height,
                depth: 1,
            },
            offset: 0,
            resource_id: RENDER_TARGET_ID,
            level: 0,
            stride: self.geometry.stride.saturating_mul(4),
            layer_stride: self
                .geometry
                .stride
                .saturating_mul(self.geometry.height)
                .saturating_mul(4),
        }))?;
        let width = self.geometry.width as usize;
        let height = self.geometry.height as usize;
        let samples = [
            (width / 8, height / 8),
            (width / 2, height / 4),
            (width / 2, height / 2),
            (width * 3 / 4, height * 3 / 4),
            (width * 7 / 8, height * 7 / 8),
        ];
        for (x, y) in samples {
            let index = y
                .checked_mul(width)
                .and_then(|row| row.checked_add(x))
                .ok_or(GpuError::InvalidFrame)?;
            let offset = index.checked_mul(4).ok_or(GpuError::InvalidFrame)?;
            let actual = self
                .render_target
                .read_u32_at(offset)
                .map_err(GpuError::System)?;
            let source = read_source_pixel(frame.pixels, offset)?;
            let expected = blend_panel_pixel(frame.background, source);
            if !pixels_close(actual, expected) {
                return Err(GpuError::InvalidFrame);
            }
        }
        Ok(())
    }

    pub(super) fn cleanup(&mut self, channel: &mut ControlChannel) {
        let ids = [RENDER_TARGET_ID, TEXTURE_ID, VERTEX_BUFFER_ID];
        for resource_id in ids[..self.resources_attached].iter().rev().copied() {
            let _ = channel.submit_no_data(Command::ContextDetachResource(ContextResource {
                context_id: CONTEXT_ID,
                resource_id,
            }));
            let _ = channel.submit_no_data(Command::ResourceDetachBacking(ResourceOperation {
                resource_id,
            }));
        }
        self.resources_attached = 0;
        for resource_id in ids[..self.resources_created].iter().rev().copied() {
            let _ =
                channel.submit_no_data(Command::ResourceUnref(ResourceOperation { resource_id }));
        }
        self.resources_created = 0;
    }
}

fn read_source_pixel(bytes: &[u8], offset: usize) -> Result<u32, GpuError> {
    let pixel = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(GpuError::InvalidFrame)?;
    Ok(u32::from_le_bytes([pixel[0], pixel[1], pixel[2], pixel[3]]))
}

fn blend_panel_pixel(background: u32, source: u32) -> u32 {
    let alpha = (source >> 24) & 0xff;
    let inverse = 255 - alpha;
    let red = ((source >> 16) & 0xff) + (((background >> 16) & 0xff) * inverse + 127) / 255;
    let green = ((source >> 8) & 0xff) + (((background >> 8) & 0xff) * inverse + 127) / 255;
    let blue = (source & 0xff) + ((background & 0xff) * inverse + 127) / 255;
    0xff00_0000 | (red.min(255) << 16) | (green.min(255) << 8) | blue.min(255)
}

fn pixels_close(actual: u32, expected: u32) -> bool {
    [0, 8, 16].into_iter().all(|shift| {
        let actual = ((actual >> shift) & 0xff) as i32;
        let expected = ((expected >> shift) & 0xff) as i32;
        actual.abs_diff(expected) <= 3
    })
}

#[allow(clippy::too_many_arguments)]
fn create_resource(
    channel: &mut ControlChannel,
    resource_id: u32,
    target: u32,
    format: u32,
    bind: u32,
    width: u32,
    height: u32,
    backing: &BackingStore,
) -> Result<(), GpuError> {
    channel.submit_no_data(Command::ResourceCreate3d(ResourceCreate3d {
        resource_id,
        target,
        format,
        bind,
        width,
        height,
        depth: 1,
        array_size: 1,
        last_level: 0,
        samples: 0,
        flags: 0,
    }))?;
    if let Err(error) = channel.submit_no_data(Command::ResourceAttachBacking(AttachBacking {
        resource_id,
        entries: backing.entries(),
    })) {
        let _ = channel.submit_no_data(Command::ResourceUnref(ResourceOperation { resource_id }));
        return Err(error);
    }
    if let Err(error) = channel.submit_no_data(Command::ContextAttachResource(ContextResource {
        context_id: CONTEXT_ID,
        resource_id,
    })) {
        let _ = channel.submit_no_data(Command::ResourceDetachBacking(ResourceOperation {
            resource_id,
        }));
        let _ = channel.submit_no_data(Command::ResourceUnref(ResourceOperation { resource_id }));
        return Err(error);
    }
    Ok(())
}

fn full_rect(geometry: DisplayGeometry) -> Rect {
    Rect {
        x: 0,
        y: 0,
        width: geometry.width,
        height: geometry.height,
    }
}

fn fullscreen_vertices() -> Vec<u8> {
    let vertices: [[f32; 5]; 6] = [
        [-1.0, -1.0, 0.0, 0.0, 0.0],
        [1.0, -1.0, 0.0, 1.0, 0.0],
        [1.0, 1.0, 0.0, 1.0, 1.0],
        [-1.0, -1.0, 0.0, 0.0, 0.0],
        [1.0, 1.0, 0.0, 1.0, 1.0],
        [-1.0, 1.0, 0.0, 0.0, 1.0],
    ];
    let mut bytes = Vec::with_capacity(6 * VERTEX_STRIDE as usize);
    for vertex in vertices {
        for value in vertex {
            bytes.extend_from_slice(&value.to_bits().to_le_bytes());
        }
    }
    bytes
}

struct Builder {
    words: Vec<u32>,
}

impl Builder {
    fn new() -> Self {
        Self { words: Vec::new() }
    }

    fn command(&mut self, command: u32, object: u32, length: u32) {
        self.word(command | (object << 8) | (length << 16));
    }

    fn word(&mut self, value: u32) {
        self.words.push(value);
    }

    fn float(&mut self, value: f32) {
        self.word(value.to_bits());
    }

    fn bind_object(&mut self, object: u32, handle: u32) {
        self.command(CMD_BIND_OBJECT, object, 1);
        self.word(handle);
    }

    fn shader(&mut self, handle: u32, shader_type: u32, source: &str) {
        let byte_len = source.len().saturating_add(1);
        let text_words = byte_len.saturating_add(3) / 4;
        self.command(
            CMD_CREATE_OBJECT,
            OBJECT_SHADER,
            5u32.saturating_add(text_words as u32),
        );
        self.word(handle);
        self.word(shader_type);
        self.word(byte_len as u32);
        self.word(SHADER_TOKEN_BUDGET);
        self.word(0);
        for chunk in source.as_bytes().chunks(4) {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.word(u32::from_le_bytes(word));
        }
        if source.len() % 4 == 0 {
            self.word(0);
        }
    }

    fn bind_shader(&mut self, handle: u32, shader_type: u32) {
        self.command(CMD_BIND_SHADER, 0, 2);
        self.word(handle);
        self.word(shader_type);
    }

    fn finish(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.words.len() * 4);
        for word in self.words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

fn setup_commands(width: u32, height: u32) -> Vec<u8> {
    let mut builder = Builder::new();
    builder.shader(VERTEX_SHADER_HANDLE, SHADER_VERTEX, VERTEX_SHADER);
    builder.bind_shader(VERTEX_SHADER_HANDLE, SHADER_VERTEX);
    builder.shader(FRAGMENT_SHADER_HANDLE, SHADER_FRAGMENT, FRAGMENT_SHADER);
    builder.bind_shader(FRAGMENT_SHADER_HANDLE, SHADER_FRAGMENT);

    builder.command(CMD_CREATE_OBJECT, OBJECT_SURFACE, 5);
    for value in [
        SURFACE_HANDLE,
        RENDER_TARGET_ID,
        FORMAT_B8G8R8A8_UNORM,
        0,
        0,
    ] {
        builder.word(value);
    }

    builder.command(CMD_CREATE_OBJECT, OBJECT_VERTEX_ELEMENTS, 9);
    for value in [
        VERTEX_ELEMENTS_HANDLE,
        0,
        0,
        0,
        FORMAT_R32G32B32_FLOAT,
        12,
        0,
        0,
        FORMAT_R32G32_FLOAT,
    ] {
        builder.word(value);
    }
    builder.bind_object(OBJECT_VERTEX_ELEMENTS, VERTEX_ELEMENTS_HANDLE);

    builder.command(CMD_CREATE_OBJECT, OBJECT_RASTERIZER, 9);
    builder.word(RASTERIZER_HANDLE);
    builder.word((1 << 1) | (1 << 29));
    builder.float(1.0);
    builder.word(0);
    builder.word(0);
    builder.float(1.0);
    builder.float(0.0);
    builder.float(0.0);
    builder.float(0.0);
    builder.bind_object(OBJECT_RASTERIZER, RASTERIZER_HANDLE);

    // Premultiplied source-over: ONE, INV_SRC_ALPHA for RGB and alpha.
    let blend_rt0 = 1 | (1 << 4) | (19 << 9) | (1 << 17) | (19 << 22) | (0xf << 27);
    builder.command(CMD_CREATE_OBJECT, OBJECT_BLEND, 11);
    for value in [BLEND_HANDLE, 0, 0, blend_rt0, 0, 0, 0, 0, 0, 0, 0] {
        builder.word(value);
    }
    builder.bind_object(OBJECT_BLEND, BLEND_HANDLE);

    builder.command(CMD_CREATE_OBJECT, OBJECT_DSA, 5);
    for value in [DSA_HANDLE, 0, 0, 0, 0] {
        builder.word(value);
    }
    builder.bind_object(OBJECT_DSA, DSA_HANDLE);

    builder.command(CMD_CREATE_OBJECT, OBJECT_SAMPLER_VIEW, 6);
    for value in [
        SAMPLER_VIEW_HANDLE,
        TEXTURE_ID,
        FORMAT_B8G8R8A8_UNORM,
        0,
        0,
        0x688,
    ] {
        builder.word(value);
    }
    builder.command(CMD_CREATE_OBJECT, OBJECT_SAMPLER_STATE, 9);
    let sampler = (2 << 0) | (2 << 3) | (2 << 6) | (1 << 9) | (2 << 11) | (1 << 13);
    builder.word(SAMPLER_STATE_HANDLE);
    builder.word(sampler);
    for _ in 0..7 {
        builder.word(0);
    }

    builder.command(CMD_SET_SAMPLER_VIEWS, 0, 3);
    for value in [SHADER_FRAGMENT, 0, SAMPLER_VIEW_HANDLE] {
        builder.word(value);
    }
    builder.command(CMD_BIND_SAMPLER_STATES, 0, 3);
    for value in [SHADER_FRAGMENT, 0, SAMPLER_STATE_HANDLE] {
        builder.word(value);
    }
    builder.command(CMD_SET_FRAMEBUFFER, 0, 3);
    for value in [1, 0, SURFACE_HANDLE] {
        builder.word(value);
    }
    builder.command(CMD_SET_VIEWPORT, 0, 7);
    builder.word(0);
    let half_width = width as f32 / 2.0;
    let half_height = height as f32 / 2.0;
    for value in [half_width, half_height, 0.5, half_width, half_height, 0.5] {
        builder.float(value);
    }
    builder.command(CMD_SET_VERTEX_BUFFERS, 0, 3);
    for value in [VERTEX_STRIDE, 0, VERTEX_BUFFER_ID] {
        builder.word(value);
    }
    builder.finish()
}

fn frame_commands(background: u32) -> Vec<u8> {
    let mut builder = Builder::new();
    builder.command(CMD_CLEAR, 0, 8);
    builder.word(CLEAR_COLOR0);
    for shift in [16, 8, 0] {
        builder.float(((background >> shift) & 0xff) as f32 / 255.0);
    }
    builder.float(1.0);
    builder.word(0);
    builder.word(0);
    builder.word(0);
    builder.command(CMD_DRAW_VBO, 0, 12);
    for value in [0, 6, PRIM_TRIANGLES, 0, 1, 0, 0, 0, 0, 0, u32::MAX, 0] {
        builder.word(value);
    }
    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_streams_are_aligned_and_use_premultiplied_blending() {
        let setup = setup_commands(640, 480);
        let frame = frame_commands(0xffc8_c8c8);
        assert_eq!(setup.len() % 4, 0);
        assert_eq!(frame.len(), (9 + 13) * 4);
        assert!(setup.windows(4).any(|word| word == 0x688u32.to_le_bytes()));
    }

    #[test]
    fn fullscreen_quad_contains_six_complete_vertices() {
        let vertices = fullscreen_vertices();
        assert_eq!(vertices.len(), 6 * VERTEX_STRIDE as usize);
    }
}
