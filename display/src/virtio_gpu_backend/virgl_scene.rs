use alloc::vec::Vec;

use mochios_viewkit_gpu_protocol::{ATLAS_WIDTH, CLEAR_VERTEX_COUNT, MAX_VERTICES, VERTEX_STRIDE};
use mochios_virtio_gpu_protocol::{
    AttachBacking, Box3d, Command, ContextResource, Rect, ResourceCreate3d, ResourceOperation,
    SetScanout, Submit3d, TransferHost3d,
};

use crate::present::DisplayGeometry;

use super::control::ControlChannel;
use super::dma::BackingStore;
use super::error::GpuError;

const CONTEXT_ID: u32 = 1;
const RENDER_TARGET_ID: u32 = 6;
const TEXTURE_ID: u32 = 7;
const VERTEX_BUFFER_ID: u32 = 8;
const PIPE_BUFFER: u32 = 0;
const PIPE_TEXTURE_2D: u32 = 2;
const FORMAT_B8G8R8A8_UNORM: u32 = 1;
const FORMAT_R32G32_FLOAT: u32 = 29;
const FORMAT_R32G32B32_FLOAT: u32 = 30;
const FORMAT_R32G32B32A32_FLOAT: u32 = 31;
const BIND_RENDER_TARGET: u32 = 1 << 1;
const BIND_SAMPLER_VIEW: u32 = 1 << 3;
const BIND_VERTEX_BUFFER: u32 = 1 << 4;
const CMD_CREATE_OBJECT: u32 = 1;
const CMD_BIND_OBJECT: u32 = 2;
const CMD_SET_VIEWPORT: u32 = 4;
const CMD_SET_FRAMEBUFFER: u32 = 5;
const CMD_SET_VERTEX_BUFFERS: u32 = 6;
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
const SURFACE_HANDLE: u32 = 30;
const VERTEX_SHADER_HANDLE: u32 = 31;
const FRAGMENT_SHADER_HANDLE: u32 = 32;
const VERTEX_ELEMENTS_HANDLE: u32 = 33;
const RASTERIZER_HANDLE: u32 = 34;
const BLEND_HANDLE: u32 = 35;
const NO_BLEND_HANDLE: u32 = 39;
const DSA_HANDLE: u32 = 36;
const SAMPLER_VIEW_HANDLE: u32 = 37;
const SAMPLER_STATE_HANDLE: u32 = 38;
const SHADER_TOKEN_BUDGET: u32 = 4096;

const VERTEX_SHADER: &str = "VERT\n\
DCL IN[0]\n\
DCL IN[1]\n\
DCL IN[2]\n\
DCL OUT[0], POSITION\n\
DCL OUT[1], GENERIC[0]\n\
DCL OUT[2], GENERIC[1]\n\
MOV OUT[0], IN[0]\n\
MOV OUT[1], IN[1]\n\
MOV OUT[2], IN[2]\n\
END\n";

const FRAGMENT_SHADER: &str = "FRAG\n\
DCL IN[0], GENERIC[0], PERSPECTIVE\n\
DCL IN[1], GENERIC[1], COLOR\n\
DCL OUT[0], COLOR\n\
DCL SAMP[0]\n\
DCL SVIEW[0], 2D, FLOAT\n\
DCL TEMP[0]\n\
TEX TEMP[0], IN[0], SAMP[0], 2D\n\
MUL OUT[0], TEMP[0], IN[1]\n\
END\n";

pub(super) struct SceneRenderer {
    geometry: DisplayGeometry,
    render_target: BackingStore,
    texture: BackingStore,
    vertices: BackingStore,
    resources_created: usize,
    resources_attached: usize,
}

impl SceneRenderer {
    pub(super) fn initialize(
        channel: &mut ControlChannel,
        geometry: DisplayGeometry,
    ) -> Result<Self, GpuError> {
        let render_bytes = geometry.byte_len().map_err(GpuError::System)?;
        let texture_bytes = (ATLAS_WIDTH as usize)
            .checked_mul(ATLAS_WIDTH as usize)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(GpuError::InvalidFrame)?;
        let vertex_bytes = (MAX_VERTICES as usize)
            .checked_mul(VERTEX_STRIDE)
            .ok_or(GpuError::InvalidFrame)?;
        let mut renderer = Self {
            geometry,
            render_target: BackingStore::allocate(render_bytes).map_err(GpuError::System)?,
            texture: BackingStore::allocate(texture_bytes).map_err(GpuError::System)?,
            vertices: BackingStore::allocate(vertex_bytes).map_err(GpuError::System)?,
            resources_created: 0,
            resources_attached: 0,
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
            ATLAS_WIDTH,
            ATLAS_WIDTH,
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
            MAX_VERTICES.saturating_mul(VERTEX_STRIDE as u32),
            1,
            &self.vertices,
        )?;
        self.resources_created += 1;
        self.resources_attached += 1;
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
        scene: &mochios_viewkit_gpu_protocol::Scene<'_>,
    ) -> Result<(), GpuError> {
        if scene.width != self.geometry.width
            || scene.height != self.geometry.height
            || scene.atlas_width != ATLAS_WIDTH
            || scene.atlas_height != ATLAS_WIDTH
            || scene
                .atlas_data_y
                .checked_add(scene.atlas_data_height)
                .is_none_or(|end| end > ATLAS_WIDTH)
            || scene.vertices.len() > MAX_VERTICES as usize * VERTEX_STRIDE
        {
            return Err(GpuError::InvalidFrame);
        }
        let atlas_offset = scene.atlas_data_y as usize * ATLAS_WIDTH as usize * 4;
        self.texture
            .write_at(atlas_offset, scene.atlas)
            .map_err(GpuError::System)?;
        self.vertices
            .write_all(scene.vertices)
            .map_err(GpuError::System)?;
        if scene.atlas_data_height != 0 {
            channel.submit_no_data(Command::TransferToHost3d(TransferHost3d {
                context_id: CONTEXT_ID,
                box_3d: Box3d {
                    x: 0,
                    y: scene.atlas_data_y,
                    z: 0,
                    width: ATLAS_WIDTH,
                    height: scene.atlas_data_height,
                    depth: 1,
                },
                offset: atlas_offset as u64,
                resource_id: TEXTURE_ID,
                level: 0,
                stride: ATLAS_WIDTH.saturating_mul(4),
                layer_stride: ATLAS_WIDTH.saturating_mul(ATLAS_WIDTH).saturating_mul(4),
            }))?;
        }
        let vertex_transfer = Command::TransferToHost3d(TransferHost3d {
            context_id: CONTEXT_ID,
            box_3d: Box3d {
                x: 0,
                y: 0,
                z: 0,
                width: scene.vertices.len() as u32,
                height: 1,
                depth: 1,
            },
            offset: 0,
            resource_id: VERTEX_BUFFER_ID,
            level: 0,
            stride: 0,
            layer_stride: 0,
        });
        let frame = frame_commands(scene.vertex_count());
        channel.submit_pair_no_data(
            vertex_transfer,
            Command::Submit3d(Submit3d {
                context_id: CONTEXT_ID,
                commands: &frame,
            }),
        )?;
        let rect = Rect {
            x: 0,
            y: 0,
            width: self.geometry.width,
            height: self.geometry.height,
        };
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
    channel.submit_no_data(Command::ResourceAttachBacking(AttachBacking {
        resource_id,
        entries: backing.entries(),
    }))?;
    channel.submit_no_data(Command::ContextAttachResource(ContextResource {
        context_id: CONTEXT_ID,
        resource_id,
    }))
}

struct Builder {
    words: Vec<u32>,
}

impl Builder {
    fn new() -> Self {
        Self { words: Vec::new() }
    }
    fn command(&mut self, command: u32, object: u32, length: u32) {
        self.words.push(command | (object << 8) | (length << 16));
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
    fn draw(&mut self, start: u32, count: u32) {
        self.command(CMD_DRAW_VBO, 0, 12);
        for value in [
            start,
            count,
            PRIM_TRIANGLES,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            u32::MAX,
            0,
        ] {
            self.word(value);
        }
    }
    fn shader(&mut self, handle: u32, shader_type: u32, source: &str) {
        let byte_len = source.len().saturating_add(1);
        let text_words = byte_len.saturating_add(3) / 4;
        self.command(CMD_CREATE_OBJECT, OBJECT_SHADER, 5 + text_words as u32);
        for value in [handle, shader_type, byte_len as u32, SHADER_TOKEN_BUDGET, 0] {
            self.word(value);
        }
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
    let mut b = Builder::new();
    b.shader(VERTEX_SHADER_HANDLE, SHADER_VERTEX, VERTEX_SHADER);
    b.bind_shader(VERTEX_SHADER_HANDLE, SHADER_VERTEX);
    b.shader(FRAGMENT_SHADER_HANDLE, SHADER_FRAGMENT, FRAGMENT_SHADER);
    b.bind_shader(FRAGMENT_SHADER_HANDLE, SHADER_FRAGMENT);
    b.command(CMD_CREATE_OBJECT, OBJECT_SURFACE, 5);
    for value in [
        SURFACE_HANDLE,
        RENDER_TARGET_ID,
        FORMAT_B8G8R8A8_UNORM,
        0,
        0,
    ] {
        b.word(value);
    }
    b.command(CMD_CREATE_OBJECT, OBJECT_VERTEX_ELEMENTS, 13);
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
        20,
        0,
        0,
        FORMAT_R32G32B32A32_FLOAT,
    ] {
        b.word(value);
    }
    b.bind_object(OBJECT_VERTEX_ELEMENTS, VERTEX_ELEMENTS_HANDLE);
    b.command(CMD_CREATE_OBJECT, OBJECT_RASTERIZER, 9);
    b.word(RASTERIZER_HANDLE);
    b.word((1 << 1) | (1 << 29));
    b.float(1.0);
    b.word(0);
    b.word(0);
    b.float(1.0);
    b.float(0.0);
    b.float(0.0);
    b.float(0.0);
    b.bind_object(OBJECT_RASTERIZER, RASTERIZER_HANDLE);
    let blend_rt0 = 1 | (1 << 4) | (19 << 9) | (1 << 17) | (19 << 22) | (0xf << 27);
    b.command(CMD_CREATE_OBJECT, OBJECT_BLEND, 11);
    for value in [BLEND_HANDLE, 0, 0, blend_rt0, 0, 0, 0, 0, 0, 0, 0] {
        b.word(value);
    }
    b.command(CMD_CREATE_OBJECT, OBJECT_BLEND, 11);
    for value in [NO_BLEND_HANDLE, 0, 0, 0xf << 27, 0, 0, 0, 0, 0, 0, 0] {
        b.word(value);
    }
    b.bind_object(OBJECT_BLEND, BLEND_HANDLE);
    b.command(CMD_CREATE_OBJECT, OBJECT_DSA, 5);
    for value in [DSA_HANDLE, 0, 0, 0, 0] {
        b.word(value);
    }
    b.bind_object(OBJECT_DSA, DSA_HANDLE);
    b.command(CMD_CREATE_OBJECT, OBJECT_SAMPLER_VIEW, 6);
    for value in [
        SAMPLER_VIEW_HANDLE,
        TEXTURE_ID,
        FORMAT_B8G8R8A8_UNORM,
        0,
        0,
        0x688,
    ] {
        b.word(value);
    }
    b.command(CMD_CREATE_OBJECT, OBJECT_SAMPLER_STATE, 9);
    let sampler = (2 << 0) | (2 << 3) | (2 << 6) | (1 << 9) | (2 << 11) | (1 << 13);
    b.word(SAMPLER_STATE_HANDLE);
    b.word(sampler);
    for _ in 0..7 {
        b.word(0);
    }
    b.command(CMD_SET_SAMPLER_VIEWS, 0, 3);
    for value in [SHADER_FRAGMENT, 0, SAMPLER_VIEW_HANDLE] {
        b.word(value);
    }
    b.command(CMD_BIND_SAMPLER_STATES, 0, 3);
    for value in [SHADER_FRAGMENT, 0, SAMPLER_STATE_HANDLE] {
        b.word(value);
    }
    b.command(CMD_SET_FRAMEBUFFER, 0, 3);
    for value in [1, 0, SURFACE_HANDLE] {
        b.word(value);
    }
    b.command(CMD_SET_VIEWPORT, 0, 7);
    b.word(0);
    let half_width = width as f32 / 2.0;
    let half_height = height as f32 / 2.0;
    for value in [half_width, half_height, 0.5, half_width, half_height, 0.5] {
        b.float(value);
    }
    b.command(CMD_SET_VERTEX_BUFFERS, 0, 3);
    for value in [VERTEX_STRIDE as u32, 0, VERTEX_BUFFER_ID] {
        b.word(value);
    }
    b.finish()
}

fn frame_commands(vertex_count: u32) -> Vec<u8> {
    let mut b = Builder::new();
    b.bind_object(OBJECT_BLEND, NO_BLEND_HANDLE);
    b.draw(0, CLEAR_VERTEX_COUNT);
    b.bind_object(OBJECT_BLEND, BLEND_HANDLE);
    if vertex_count > CLEAR_VERTEX_COUNT {
        b.draw(
            CLEAR_VERTEX_COUNT,
            vertex_count.saturating_sub(CLEAR_VERTEX_COUNT),
        );
    }
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scene_pipeline_uses_complete_vertex_layout() {
        let commands = setup_commands(1280, 800);
        assert_eq!(commands.len() % 4, 0);
        assert_eq!(frame_commands(6).len(), (2 + 13 + 2) * 4);
        assert_eq!(frame_commands(9).len(), (2 + 13 + 2 + 13) * 4);
        assert!(
            commands
                .windows(4)
                .any(|word| word == FORMAT_R32G32B32A32_FLOAT.to_le_bytes())
        );
    }
}
