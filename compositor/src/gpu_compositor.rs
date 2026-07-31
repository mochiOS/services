use alloc::vec::Vec;

use crate::cursor::CursorImage;
use crate::geometry::{Rect, clip_present_rect};
use crate::protocol::{PIXEL_FORMAT_GPU_SCENE, PIXEL_FORMAT_XRGB8888};
use crate::surface::{Surface, read_current_pixel, surface_has_current_pixels};

const ATLAS_EXTENT: u32 = mochios_viewkit_gpu_protocol::ATLAS_WIDTH;
const ATLAS_BYTES_PER_PIXEL: usize = 4;
const CURSOR_TEXTURE_KEY: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TextureRequirement {
    key: u64,
    width: u32,
    height: u32,
    generation: u64,
    surface_index: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AtlasEntry {
    requirement: TextureRequirement,
    x: u32,
    y: u32,
}

#[derive(Clone, Copy)]
struct Vertex {
    x: f32,
    y: f32,
    u: f32,
    v: f32,
    color: [f32; 4],
}

pub(crate) fn merge_surface_vertices(
    previous: &[u8],
    replacement: &[u8],
    width: u32,
    height: u32,
    damage: Rect,
    output: &mut Vec<u8>,
) -> Option<()> {
    let full_damage =
        damage.x == 0 && damage.y == 0 && damage.width == width && damage.height == height;
    if previous.is_empty() || full_damage {
        output.clear();
        output.try_reserve_exact(replacement.len()).ok()?;
        output.extend_from_slice(replacement);
        return Some(());
    }

    let mut retained = Vec::new();
    let damage_right = u32::try_from(damage.x).ok()?.checked_add(damage.width)?;
    let damage_bottom = u32::try_from(damage.y).ok()?.checked_add(damage.height)?;
    let strips = [
        Rect {
            x: 0,
            y: 0,
            width,
            height: u32::try_from(damage.y).ok()?,
        },
        Rect {
            x: 0,
            y: i32::try_from(damage_bottom).ok()?,
            width,
            height: height.checked_sub(damage_bottom)?,
        },
        Rect {
            x: 0,
            y: damage.y,
            width: u32::try_from(damage.x).ok()?,
            height: damage.height,
        },
        Rect {
            x: i32::try_from(damage_right).ok()?,
            y: damage.y,
            width: width.checked_sub(damage_right)?,
            height: damage.height,
        },
    ];
    for triangle in previous.chunks_exact(mochios_viewkit_gpu_protocol::VERTEX_STRIDE * 3) {
        let triangle = decode_local_triangle(triangle, width, height)?;
        for strip in strips
            .iter()
            .copied()
            .filter(|strip| strip.width != 0 && strip.height != 0)
        {
            append_clipped_triangle(&mut retained, triangle, strip);
        }
    }
    for triangle in replacement.chunks_exact(mochios_viewkit_gpu_protocol::VERTEX_STRIDE * 3) {
        append_clipped_triangle(
            &mut retained,
            decode_local_triangle(triangle, width, height)?,
            damage,
        );
    }
    if retained.len() > mochios_viewkit_gpu_protocol::MAX_VERTICES as usize {
        return None;
    }
    encode_local_vertices(&retained, width, height, output)
}

fn decode_local_triangle(bytes: &[u8], width: u32, height: u32) -> Option<[Vertex; 3]> {
    let mut result = [Vertex {
        x: 0.0,
        y: 0.0,
        u: 0.0,
        v: 0.0,
        color: [0.0; 4],
    }; 3];
    for (index, source) in bytes
        .chunks_exact(mochios_viewkit_gpu_protocol::VERTEX_STRIDE)
        .enumerate()
    {
        if index >= result.len() {
            return None;
        }
        result[index] = Vertex {
            x: (read_f32(source, 0)? + 1.0) * 0.5 * width as f32,
            y: (read_f32(source, 4)? + 1.0) * 0.5 * height as f32,
            u: read_f32(source, 12)?,
            v: read_f32(source, 16)?,
            color: [
                read_f32(source, 20)?,
                read_f32(source, 24)?,
                read_f32(source, 28)?,
                read_f32(source, 32)?,
            ],
        };
    }
    Some(result)
}

fn encode_local_vertices(
    vertices: &[Vertex],
    width: u32,
    height: u32,
    output: &mut Vec<u8>,
) -> Option<()> {
    let byte_len = vertices
        .len()
        .checked_mul(mochios_viewkit_gpu_protocol::VERTEX_STRIDE)?;
    output.clear();
    output.try_reserve_exact(byte_len).ok()?;
    for vertex in vertices {
        let x = vertex.x / width as f32 * 2.0 - 1.0;
        let y = vertex.y / height as f32 * 2.0 - 1.0;
        for value in [
            x,
            y,
            0.0,
            vertex.u,
            vertex.v,
            vertex.color[0],
            vertex.color[1],
            vertex.color[2],
            vertex.color[3],
        ] {
            output.extend_from_slice(&value.to_bits().to_le_bytes());
        }
    }
    Some(())
}

#[derive(Default)]
pub(crate) struct GpuCompositor {
    atlas: Vec<u8>,
    entries: Vec<AtlasEntry>,
    vertices: Vec<Vertex>,
    output: Vec<u8>,
}

impl GpuCompositor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compose(
        &mut self,
        surfaces: &[Surface],
        display_width: u32,
        display_height: u32,
        damage: Option<Rect>,
        cursor_x: i32,
        cursor_y: i32,
        cursor_visible: bool,
        cursor: &CursorImage,
    ) -> Option<&[u8]> {
        let damage = clip_present_rect(
            damage,
            usize::try_from(display_width).ok()?,
            usize::try_from(display_height).ok()?,
        )?;
        let requirements = texture_requirements(surfaces, cursor_visible, cursor);
        let layout = pack_requirements(&requirements)?;
        let layout_changed = !same_layout(&self.entries, &layout);
        if !self.prepare_atlas() {
            return None;
        }
        let mut dirty_rows = if layout_changed {
            self.atlas.fill(0);
            if let Some(white) = self.atlas.get_mut(..4) {
                white.copy_from_slice(&[255; 4]);
            }
            Some((0, 1))
        } else {
            None
        };
        for entry in &layout {
            let previous_generation = self
                .entries
                .iter()
                .find(|current| current.requirement.key == entry.requirement.key)
                .map(|current| current.requirement.generation);
            if layout_changed || previous_generation != Some(entry.requirement.generation) {
                if !copy_texture_to_atlas(&mut self.atlas, *entry, surfaces, cursor) {
                    return None;
                }
                dirty_rows = merge_rows(
                    dirty_rows,
                    entry.y,
                    entry.y.saturating_add(entry.requirement.height),
                );
            }
        }
        self.entries = layout;
        self.vertices.clear();
        push_solid_quad(
            &mut self.vertices,
            damage,
            [200.0 / 255.0, 200.0 / 255.0, 200.0 / 255.0, 1.0],
        );

        let mut indices: Vec<usize> = surfaces
            .iter()
            .enumerate()
            .filter_map(|(index, surface)| {
                (surface.live && surface.visible && surface_has_current_pixels(surface))
                    .then_some(index)
            })
            .collect();
        indices.sort_by_key(|index| {
            let surface = &surfaces[*index];
            (surface.role.stack_layer(), surface.z)
        });
        for index in indices {
            let surface = &surfaces[index];
            let entry = self
                .entries
                .iter()
                .find(|entry| entry.requirement.surface_index == Some(index))
                .copied()?;
            if surface.current_format == PIXEL_FORMAT_GPU_SCENE {
                append_gpu_surface(&mut self.vertices, surface, entry, damage)?;
            } else {
                append_cpu_surface(&mut self.vertices, surface, entry, damage);
            }
        }
        if cursor_visible {
            let entry = self
                .entries
                .iter()
                .find(|entry| entry.requirement.key == CURSOR_TEXTURE_KEY)
                .copied();
            if let (Some(entry), Some((width, height, _, _))) = (entry, cursor.texture()) {
                let bounds = cursor.bounds(cursor_x, cursor_y);
                append_textured_quad(&mut self.vertices, bounds, entry, width, height, damage);
            }
        }
        for vertex in &mut self.vertices {
            vertex.x = vertex.x / display_width as f32 * 2.0 - 1.0;
            vertex.y = vertex.y / display_height as f32 * 2.0 - 1.0;
        }
        encode_scene(
            &self.vertices,
            &self.atlas,
            dirty_rows,
            display_width,
            display_height,
            &mut self.output,
        )?;
        Some(self.output.as_slice())
    }

    pub(crate) fn invalidate_atlas(&mut self) {
        self.entries.clear();
    }

    fn prepare_atlas(&mut self) -> bool {
        let Some(length) = usize::try_from(ATLAS_EXTENT)
            .ok()
            .and_then(|extent| extent.checked_mul(extent))
            .and_then(|pixels| pixels.checked_mul(ATLAS_BYTES_PER_PIXEL))
        else {
            return false;
        };
        if self.atlas.len() == length {
            return true;
        }
        self.atlas.clear();
        if self.atlas.try_reserve_exact(length).is_err() {
            return false;
        }
        self.atlas.resize(length, 0);
        if let Some(white) = self.atlas.get_mut(..4) {
            white.copy_from_slice(&[255; 4]);
        }
        true
    }
}

fn texture_requirements(
    surfaces: &[Surface],
    cursor_visible: bool,
    cursor: &CursorImage,
) -> Vec<TextureRequirement> {
    let mut requirements = Vec::new();
    for (index, surface) in surfaces.iter().enumerate() {
        if !surface.live || !surface.visible || !surface_has_current_pixels(surface) {
            continue;
        }
        let (width, height, generation) = if surface.current_format == PIXEL_FORMAT_GPU_SCENE {
            let Some(gpu) = surface.gpu.as_ref() else {
                continue;
            };
            let Some((used_width, used_height)) = gpu_texture_extent(gpu) else {
                continue;
            };
            (used_width, used_height, gpu.atlas_generation)
        } else {
            (
                surface.current_width,
                surface.current_height,
                surface.content_generation,
            )
        };
        requirements.push(TextureRequirement {
            key: surface.handle.0,
            width,
            height,
            generation,
            surface_index: Some(index),
        });
    }
    if cursor_visible && let Some((width, height, _, generation)) = cursor.texture() {
        requirements.push(TextureRequirement {
            key: CURSOR_TEXTURE_KEY,
            width,
            height,
            generation,
            surface_index: None,
        });
    }
    requirements
}

fn pack_requirements(requirements: &[TextureRequirement]) -> Option<Vec<AtlasEntry>> {
    let mut entries = Vec::new();
    let mut x = 1u32;
    let mut y = 0u32;
    let mut row_height = 1u32;
    for requirement in requirements {
        if requirement.width == 0
            || requirement.height == 0
            || requirement.width > ATLAS_EXTENT
            || requirement.height > ATLAS_EXTENT
        {
            return None;
        }
        if x.saturating_add(requirement.width) > ATLAS_EXTENT {
            x = 0;
            y = y.saturating_add(row_height);
            row_height = 0;
        }
        if y.saturating_add(requirement.height) > ATLAS_EXTENT {
            return None;
        }
        entries.push(AtlasEntry {
            requirement: *requirement,
            x,
            y,
        });
        x = x.saturating_add(requirement.width).saturating_add(1);
        row_height = row_height.max(requirement.height.saturating_add(1));
    }
    Some(entries)
}

fn same_layout(first: &[AtlasEntry], second: &[AtlasEntry]) -> bool {
    first.len() == second.len()
        && first.iter().zip(second).all(|(first, second)| {
            first.requirement.key == second.requirement.key
                && first.requirement.width == second.requirement.width
                && first.requirement.height == second.requirement.height
                && first.x == second.x
                && first.y == second.y
        })
}

fn merge_rows(current: Option<(u32, u32)>, start: u32, end: u32) -> Option<(u32, u32)> {
    if start >= end {
        return current;
    }
    Some(current.map_or((start, end), |(old_start, old_end)| {
        (old_start.min(start), old_end.max(end))
    }))
}

fn copy_texture_to_atlas(
    atlas: &mut [u8],
    entry: AtlasEntry,
    surfaces: &[Surface],
    cursor: &CursorImage,
) -> bool {
    if entry.requirement.key == CURSOR_TEXTURE_KEY {
        let Some((width, height, pixels, _)) = cursor.texture() else {
            return false;
        };
        return copy_pixels(atlas, entry, width, height, |x, y| {
            pixels
                .get(y.saturating_mul(width as usize).saturating_add(x))
                .copied()
        });
    }
    let Some(index) = entry.requirement.surface_index else {
        return false;
    };
    let Some(surface) = surfaces.get(index) else {
        return false;
    };
    if surface.current_format == PIXEL_FORMAT_GPU_SCENE {
        let Some(gpu) = surface.gpu.as_ref() else {
            return false;
        };
        return copy_bytes(atlas, entry, gpu.atlas_width, &gpu.atlas);
    }
    copy_pixels(
        atlas,
        entry,
        surface.current_width,
        surface.current_height,
        |x, y| {
            let mut pixel = read_current_pixel(surface, x, y)?;
            if surface.current_format == PIXEL_FORMAT_XRGB8888 {
                pixel |= 0xff00_0000;
            }
            Some(pixel)
        },
    )
}

fn copy_bytes(atlas: &mut [u8], entry: AtlasEntry, source_width: u32, source: &[u8]) -> bool {
    let row_bytes = entry.requirement.width as usize * 4;
    let source_row_bytes = source_width as usize * 4;
    if source.len() < source_row_bytes.saturating_mul(entry.requirement.height as usize) {
        return false;
    }
    for y in 0..entry.requirement.height as usize {
        let source_start = y.saturating_mul(source_row_bytes);
        let destination_start = ((entry.y as usize + y)
            .saturating_mul(ATLAS_EXTENT as usize)
            .saturating_add(entry.x as usize))
        .saturating_mul(4);
        let Some(destination) = atlas.get_mut(destination_start..destination_start + row_bytes)
        else {
            return false;
        };
        destination.copy_from_slice(&source[source_start..source_start + row_bytes]);
    }
    true
}

fn gpu_texture_extent(gpu: &crate::surface::GpuSurfaceState) -> Option<(u32, u32)> {
    let mut max_u = 0.0f32;
    let mut max_v = 0.0f32;
    for vertex in gpu
        .vertices
        .chunks_exact(mochios_viewkit_gpu_protocol::VERTEX_STRIDE)
    {
        max_u = max_u.max(read_f32(vertex, 12)?.clamp(0.0, 1.0));
        max_v = max_v.max(read_f32(vertex, 16)?.clamp(0.0, 1.0));
    }
    let width = ((max_u * gpu.atlas_width as f32).ceil() as u32)
        .saturating_add(1)
        .clamp(1, gpu.atlas_width);
    let height = ((max_v * gpu.atlas_height as f32).ceil() as u32)
        .saturating_add(1)
        .clamp(1, gpu.atlas_height);
    Some((width, height))
}

fn copy_pixels(
    atlas: &mut [u8],
    entry: AtlasEntry,
    width: u32,
    height: u32,
    mut pixel: impl FnMut(usize, usize) -> Option<u32>,
) -> bool {
    if width != entry.requirement.width || height != entry.requirement.height {
        return false;
    }
    for y in 0..height as usize {
        for x in 0..width as usize {
            let destination = ((entry.y as usize + y)
                .saturating_mul(ATLAS_EXTENT as usize)
                .saturating_add(entry.x as usize + x))
            .saturating_mul(4);
            let Some(bytes) = atlas.get_mut(destination..destination + 4) else {
                return false;
            };
            bytes.copy_from_slice(&pixel(x, y).unwrap_or(0).to_le_bytes());
        }
    }
    true
}

fn append_gpu_surface(
    output: &mut Vec<Vertex>,
    surface: &Surface,
    entry: AtlasEntry,
    damage: Rect,
) -> Option<()> {
    let gpu = surface.gpu.as_ref()?;
    for triangle in gpu
        .vertices
        .chunks_exact(mochios_viewkit_gpu_protocol::VERTEX_STRIDE * 3)
    {
        let mut vertices = [Vertex {
            x: 0.0,
            y: 0.0,
            u: 0.0,
            v: 0.0,
            color: [0.0; 4],
        }; 3];
        for (index, source) in triangle
            .chunks_exact(mochios_viewkit_gpu_protocol::VERTEX_STRIDE)
            .enumerate()
        {
            let local_x = (read_f32(source, 0)? + 1.0) * 0.5 * gpu.width as f32;
            let local_y = (read_f32(source, 4)? + 1.0) * 0.5 * gpu.height as f32;
            let source_u = read_f32(source, 12)? * gpu.atlas_width as f32;
            let source_v = read_f32(source, 16)? * gpu.atlas_height as f32;
            vertices[index] = Vertex {
                x: surface.x as f32 + local_x,
                y: surface.y as f32 + local_y,
                u: (entry.x as f32 + source_u) / ATLAS_EXTENT as f32,
                v: (entry.y as f32 + source_v) / ATLAS_EXTENT as f32,
                color: [
                    read_f32(source, 20)?,
                    read_f32(source, 24)?,
                    read_f32(source, 28)?,
                    read_f32(source, 32)?,
                ],
            };
        }
        append_clipped_triangle(output, vertices, damage);
    }
    Some(())
}

fn append_cpu_surface(
    output: &mut Vec<Vertex>,
    surface: &Surface,
    entry: AtlasEntry,
    damage: Rect,
) {
    append_textured_quad(
        output,
        Rect {
            x: surface.x,
            y: surface.y,
            width: surface.current_width,
            height: surface.current_height,
        },
        entry,
        surface.current_width,
        surface.current_height,
        damage,
    );
}

fn append_textured_quad(
    output: &mut Vec<Vertex>,
    bounds: Rect,
    entry: AtlasEntry,
    width: u32,
    height: u32,
    damage: Rect,
) {
    let left = bounds.x as f32;
    let top = bounds.y as f32;
    let right = left + bounds.width as f32;
    let bottom = top + bounds.height as f32;
    let u0 = entry.x as f32 / ATLAS_EXTENT as f32;
    let v0 = entry.y as f32 / ATLAS_EXTENT as f32;
    let u1 = (entry.x + width) as f32 / ATLAS_EXTENT as f32;
    let v1 = (entry.y + height) as f32 / ATLAS_EXTENT as f32;
    let color = [1.0; 4];
    for triangle in [
        [
            Vertex {
                x: left,
                y: top,
                u: u0,
                v: v0,
                color,
            },
            Vertex {
                x: right,
                y: top,
                u: u1,
                v: v0,
                color,
            },
            Vertex {
                x: right,
                y: bottom,
                u: u1,
                v: v1,
                color,
            },
        ],
        [
            Vertex {
                x: left,
                y: top,
                u: u0,
                v: v0,
                color,
            },
            Vertex {
                x: right,
                y: bottom,
                u: u1,
                v: v1,
                color,
            },
            Vertex {
                x: left,
                y: bottom,
                u: u0,
                v: v1,
                color,
            },
        ],
    ] {
        append_clipped_triangle(output, triangle, damage);
    }
}

fn push_solid_quad(output: &mut Vec<Vertex>, bounds: Rect, color: [f32; 4]) {
    let left = bounds.x as f32;
    let top = bounds.y as f32;
    let right = left + bounds.width as f32;
    let bottom = top + bounds.height as f32;
    let uv = 0.25 / ATLAS_EXTENT as f32;
    output.extend_from_slice(&[
        Vertex {
            x: left,
            y: top,
            u: uv,
            v: uv,
            color,
        },
        Vertex {
            x: right,
            y: top,
            u: uv,
            v: uv,
            color,
        },
        Vertex {
            x: right,
            y: bottom,
            u: uv,
            v: uv,
            color,
        },
        Vertex {
            x: left,
            y: top,
            u: uv,
            v: uv,
            color,
        },
        Vertex {
            x: right,
            y: bottom,
            u: uv,
            v: uv,
            color,
        },
        Vertex {
            x: left,
            y: bottom,
            u: uv,
            v: uv,
            color,
        },
    ]);
}

fn append_clipped_triangle(output: &mut Vec<Vertex>, triangle: [Vertex; 3], rect: Rect) {
    let left = rect.x as f32;
    let top = rect.y as f32;
    let right = left + rect.width as f32;
    let bottom = top + rect.height as f32;
    let mut polygon = triangle.to_vec();
    polygon = clip_edge(
        &polygon,
        |vertex| vertex.x >= left,
        |a, b| interpolate_at_x(a, b, left),
    );
    polygon = clip_edge(
        &polygon,
        |vertex| vertex.x <= right,
        |a, b| interpolate_at_x(a, b, right),
    );
    polygon = clip_edge(
        &polygon,
        |vertex| vertex.y >= top,
        |a, b| interpolate_at_y(a, b, top),
    );
    polygon = clip_edge(
        &polygon,
        |vertex| vertex.y <= bottom,
        |a, b| interpolate_at_y(a, b, bottom),
    );
    if polygon.len() < 3 {
        return;
    }
    for index in 1..polygon.len() - 1 {
        output.extend_from_slice(&[polygon[0], polygon[index], polygon[index + 1]]);
    }
}

fn clip_edge(
    input: &[Vertex],
    inside: impl Fn(Vertex) -> bool,
    intersection: impl Fn(Vertex, Vertex) -> Vertex,
) -> Vec<Vertex> {
    let mut output = Vec::new();
    let Some(mut previous) = input.last().copied() else {
        return output;
    };
    let mut previous_inside = inside(previous);
    for current in input.iter().copied() {
        let current_inside = inside(current);
        if current_inside != previous_inside {
            output.push(intersection(previous, current));
        }
        if current_inside {
            output.push(current);
        }
        previous = current;
        previous_inside = current_inside;
    }
    output
}

fn interpolate_at_x(first: Vertex, second: Vertex, x: f32) -> Vertex {
    let denominator = second.x - first.x;
    interpolate(
        first,
        second,
        if denominator.abs() < f32::EPSILON {
            0.0
        } else {
            (x - first.x) / denominator
        },
    )
}

fn interpolate_at_y(first: Vertex, second: Vertex, y: f32) -> Vertex {
    let denominator = second.y - first.y;
    interpolate(
        first,
        second,
        if denominator.abs() < f32::EPSILON {
            0.0
        } else {
            (y - first.y) / denominator
        },
    )
}

fn interpolate(first: Vertex, second: Vertex, amount: f32) -> Vertex {
    let amount = amount.clamp(0.0, 1.0);
    let lerp = |first: f32, second: f32| first + (second - first) * amount;
    Vertex {
        x: lerp(first.x, second.x),
        y: lerp(first.y, second.y),
        u: lerp(first.u, second.u),
        v: lerp(first.v, second.v),
        color: [
            lerp(first.color[0], second.color[0]),
            lerp(first.color[1], second.color[1]),
            lerp(first.color[2], second.color[2]),
            lerp(first.color[3], second.color[3]),
        ],
    }
}

fn read_f32(bytes: &[u8], offset: usize) -> Option<f32> {
    let bytes = bytes.get(offset..offset.checked_add(4)?)?;
    let value = f32::from_bits(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    value.is_finite().then_some(value)
}

fn encode_scene(
    vertices: &[Vertex],
    atlas: &[u8],
    dirty_rows: Option<(u32, u32)>,
    width: u32,
    height: u32,
    output: &mut Vec<u8>,
) -> Option<()> {
    if vertices.len() > mochios_viewkit_gpu_protocol::MAX_VERTICES as usize {
        return None;
    }
    let vertex_bytes = vertices
        .len()
        .checked_mul(mochios_viewkit_gpu_protocol::VERTEX_STRIDE)?;
    let (atlas_y, atlas_end) = dirty_rows.unwrap_or((0, 0));
    let atlas_height = atlas_end.saturating_sub(atlas_y);
    let atlas_row_bytes = ATLAS_EXTENT as usize * 4;
    let atlas_bytes = atlas_height as usize * atlas_row_bytes;
    let total = mochios_viewkit_gpu_protocol::HEADER_LEN
        .checked_add(vertex_bytes)?
        .checked_add(atlas_bytes)?;
    output.clear();
    output.resize(total, 0);
    mochios_viewkit_gpu_protocol::encode_header(
        output,
        width,
        height,
        vertices.len() as u32,
        ATLAS_EXTENT,
        ATLAS_EXTENT,
        atlas_y,
        atlas_height,
    )
    .ok()?;
    let mut offset = mochios_viewkit_gpu_protocol::HEADER_LEN;
    for vertex in vertices {
        for value in [
            vertex.x,
            vertex.y,
            0.0,
            vertex.u,
            vertex.v,
            vertex.color[0],
            vertex.color[1],
            vertex.color[2],
            vertex.color[3],
        ] {
            output[offset..offset + 4].copy_from_slice(&value.to_bits().to_le_bytes());
            offset += 4;
        }
    }
    let atlas_start = atlas_y as usize * atlas_row_bytes;
    output[offset..].copy_from_slice(&atlas[atlas_start..atlas_start + atlas_bytes]);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_layout_is_stable_and_rejects_overflow() {
        let requirements = [
            TextureRequirement {
                key: 1,
                width: 1024,
                height: 512,
                generation: 1,
                surface_index: Some(0),
            },
            TextureRequirement {
                key: 2,
                width: 1024,
                height: 512,
                generation: 1,
                surface_index: Some(1),
            },
        ];
        let first = pack_requirements(&requirements).expect("two ViewKit atlases fit");
        let second = pack_requirements(&requirements).expect("layout remains available");
        assert!(same_layout(&first, &second));
        assert!(
            pack_requirements(&[TextureRequirement {
                key: 3,
                width: ATLAS_EXTENT + 1,
                height: 1,
                generation: 1,
                surface_index: None
            }])
            .is_none()
        );
    }

    #[test]
    fn triangle_clipping_preserves_triangles_inside_damage() {
        let vertex = |x, y| Vertex {
            x,
            y,
            u: 0.0,
            v: 0.0,
            color: [1.0; 4],
        };
        let mut output = Vec::new();
        append_clipped_triangle(
            &mut output,
            [vertex(-10.0, 5.0), vertex(5.0, 5.0), vertex(5.0, 20.0)],
            Rect {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            },
        );
        assert!(!output.is_empty());
        assert!(output.iter().all(|vertex| vertex.x >= 0.0
            && vertex.x <= 10.0
            && vertex.y >= 0.0
            && vertex.y <= 10.0));
    }
}
