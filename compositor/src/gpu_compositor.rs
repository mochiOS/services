use alloc::vec::Vec;

use crate::cursor::CursorImage;
use crate::geometry::{Rect, clip_present_rect};
use crate::protocol::{PIXEL_FORMAT_GPU_SCENE, PIXEL_FORMAT_XRGB8888};
use crate::surface::{Surface, read_current_pixel, surface_has_current_pixels};
use crate::window::{WINDOW_CORNER_RADIUS, Window, window_frame_rect, window_index_by_id};

const CURSOR_TEXTURE_KEY: u64 = u64::MAX;
const WHITE_TEXTURE_KEY: u64 = u64::MAX - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TextureRequirement {
    key: u64,
    width: u32,
    height: u32,
    generation: u64,
    surface_index: Option<usize>,
}

#[derive(Debug)]
struct TextureUpload {
    key: u64,
    pixels: Vec<u8>,
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
    textures: Vec<TextureRequirement>,
    uploads: Vec<TextureUpload>,
    batches: Vec<mochios_viewkit_gpu_protocol::compositor::Batch>,
    vertices: Vec<Vertex>,
    output: Vec<u8>,
}

impl GpuCompositor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compose(
        &mut self,
        surfaces: &[Surface],
        windows: &[Window],
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
        self.uploads.clear();
        for requirement in &requirements {
            let cached = self.textures.iter().find(|cached| {
                cached.key == requirement.key
                    && cached.width == requirement.width
                    && cached.height == requirement.height
                    && cached.generation == requirement.generation
            });
            if cached.is_none() {
                self.uploads.push(TextureUpload {
                    key: requirement.key,
                    pixels: texture_pixels(*requirement, surfaces, cursor)?,
                });
            }
        }
        self.textures = requirements;
        self.vertices.clear();
        self.batches.clear();
        let first = self.vertices.len() as u32;
        push_solid_quad(
            &mut self.vertices,
            damage,
            [200.0 / 255.0, 200.0 / 255.0, 200.0 / 255.0, 1.0],
        );
        push_batch(
            &mut self.batches,
            WHITE_TEXTURE_KEY,
            first,
            self.vertices.len() as u32,
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
            let window_clip = window_clip_polygon(surfaces, windows, surface);
            let first = self.vertices.len() as u32;
            if surface.current_format == PIXEL_FORMAT_GPU_SCENE {
                append_gpu_surface(&mut self.vertices, surface, damage, window_clip.as_deref())?;
            } else {
                append_cpu_surface(&mut self.vertices, surface, damage, window_clip.as_deref());
            }
            push_batch(
                &mut self.batches,
                surface.handle.0,
                first,
                self.vertices.len() as u32,
            );
        }
        if cursor_visible {
            if let Some((width, height, _, _)) = cursor.texture() {
                let first = self.vertices.len() as u32;
                let bounds = cursor.bounds(cursor_x, cursor_y);
                append_textured_quad(&mut self.vertices, bounds, width, height, damage);
                push_batch(
                    &mut self.batches,
                    CURSOR_TEXTURE_KEY,
                    first,
                    self.vertices.len() as u32,
                );
            }
        }
        for vertex in &mut self.vertices {
            vertex.x = vertex.x / display_width as f32 * 2.0 - 1.0;
            vertex.y = vertex.y / display_height as f32 * 2.0 - 1.0;
        }
        encode_compositor_scene(
            &self.vertices,
            &self.textures,
            &self.uploads,
            &self.batches,
            display_width,
            display_height,
            &mut self.output,
        )?;
        Some(self.output.as_slice())
    }

    pub(crate) fn invalidate_textures(&mut self) {
        self.textures.clear();
    }
}

fn texture_requirements(
    surfaces: &[Surface],
    cursor_visible: bool,
    cursor: &CursorImage,
) -> Vec<TextureRequirement> {
    let mut requirements = Vec::new();
    requirements.push(TextureRequirement {
        key: WHITE_TEXTURE_KEY,
        width: 1,
        height: 1,
        generation: 1,
        surface_index: None,
    });
    for (index, surface) in surfaces.iter().enumerate() {
        if !surface.live || !surface.visible || !surface_has_current_pixels(surface) {
            continue;
        }
        let (width, height, generation) = if surface.current_format == PIXEL_FORMAT_GPU_SCENE {
            let Some(gpu) = surface.gpu.as_ref() else {
                continue;
            };
            (gpu.atlas_width, gpu.atlas_height, gpu.atlas_generation)
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

fn texture_pixels(
    requirement: TextureRequirement,
    surfaces: &[Surface],
    cursor: &CursorImage,
) -> Option<Vec<u8>> {
    if requirement.key == WHITE_TEXTURE_KEY {
        return Some(vec![255; 4]);
    }
    if requirement.key == CURSOR_TEXTURE_KEY {
        let Some((width, height, pixels, _)) = cursor.texture() else {
            return None;
        };
        return collect_pixels(width, height, |x, y| {
            pixels
                .get(y.saturating_mul(width as usize).saturating_add(x))
                .copied()
        });
    }
    let surface = surfaces.get(requirement.surface_index?)?;
    if surface.current_format == PIXEL_FORMAT_GPU_SCENE {
        let gpu = surface.gpu.as_ref()?;
        return collect_bytes(
            requirement.width,
            requirement.height,
            gpu.atlas_width,
            &gpu.atlas,
        );
    }
    collect_pixels(surface.current_width, surface.current_height, |x, y| {
        let mut pixel = read_current_pixel(surface, x, y)?;
        if surface.current_format == PIXEL_FORMAT_XRGB8888 {
            pixel |= 0xff00_0000;
        }
        Some(pixel)
    })
}

fn collect_bytes(width: u32, height: u32, source_width: u32, source: &[u8]) -> Option<Vec<u8>> {
    let row_bytes = width as usize * 4;
    let source_row_bytes = source_width as usize * 4;
    if source.len() < source_row_bytes.saturating_mul(height as usize) {
        return None;
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(row_bytes.checked_mul(height as usize)?)
        .ok()?;
    for y in 0..height as usize {
        let source_start = y.saturating_mul(source_row_bytes);
        output.extend_from_slice(source.get(source_start..source_start + row_bytes)?);
    }
    Some(output)
}

fn collect_pixels(
    width: u32,
    height: u32,
    mut pixel: impl FnMut(usize, usize) -> Option<u32>,
) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(width as usize * height as usize * 4)
        .ok()?;
    for y in 0..height as usize {
        for x in 0..width as usize {
            output.extend_from_slice(&pixel(x, y).unwrap_or(0).to_le_bytes());
        }
    }
    Some(output)
}

fn append_gpu_surface(
    output: &mut Vec<Vertex>,
    surface: &Surface,
    damage: Rect,
    window_clip: Option<&[(f32, f32)]>,
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
            vertices[index] = Vertex {
                x: surface.x as f32 + local_x,
                y: surface.y as f32 + local_y,
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
        append_window_clipped_triangle(output, vertices, damage, window_clip);
    }
    Some(())
}

fn append_cpu_surface(
    output: &mut Vec<Vertex>,
    surface: &Surface,
    damage: Rect,
    window_clip: Option<&[(f32, f32)]>,
) {
    append_textured_quad_clipped(
        output,
        Rect {
            x: surface.x,
            y: surface.y,
            width: surface.current_width,
            height: surface.current_height,
        },
        damage,
        window_clip,
    );
}

fn window_clip_polygon(
    surfaces: &[Surface],
    windows: &[Window],
    surface: &Surface,
) -> Option<Vec<(f32, f32)>> {
    let window = windows.get(window_index_by_id(windows, surface.window)?)?;
    let content = surfaces
        .iter()
        .find(|candidate| candidate.live && candidate.handle == window.content)?;
    let frame = window_frame_rect(content, window);
    Some(rounded_rect_polygon(frame, WINDOW_CORNER_RADIUS as f32))
}

fn rounded_rect_polygon(rect: Rect, radius: f32) -> Vec<(f32, f32)> {
    const CORNER_SEGMENTS: usize = 8;
    let radius = radius
        .max(0.0)
        .min(rect.width.min(rect.height) as f32 * 0.5);
    let left = rect.x as f32;
    let top = rect.y as f32;
    let right = left + rect.width as f32;
    let bottom = top + rect.height as f32;
    if radius == 0.0 {
        return vec![(left, top), (right, top), (right, bottom), (left, bottom)];
    }
    let mut points = Vec::with_capacity(CORNER_SEGMENTS * 4 + 4);
    for (center_x, center_y, start) in [
        (right - radius, top + radius, -core::f32::consts::FRAC_PI_2),
        (right - radius, bottom - radius, 0.0),
        (left + radius, bottom - radius, core::f32::consts::FRAC_PI_2),
        (left + radius, top + radius, core::f32::consts::PI),
    ] {
        for step in 0..=CORNER_SEGMENTS {
            let angle = start + core::f32::consts::FRAC_PI_2 * step as f32 / CORNER_SEGMENTS as f32;
            points.push((
                center_x + angle.cos() * radius,
                center_y + angle.sin() * radius,
            ));
        }
    }
    points
}

fn append_textured_quad(
    output: &mut Vec<Vertex>,
    bounds: Rect,
    _width: u32,
    _height: u32,
    damage: Rect,
) {
    append_textured_quad_clipped(output, bounds, damage, None);
}

fn append_textured_quad_clipped(
    output: &mut Vec<Vertex>,
    bounds: Rect,
    damage: Rect,
    window_clip: Option<&[(f32, f32)]>,
) {
    let left = bounds.x as f32;
    let top = bounds.y as f32;
    let right = left + bounds.width as f32;
    let bottom = top + bounds.height as f32;
    let u0 = 0.0;
    let v0 = 0.0;
    let u1 = 1.0;
    let v1 = 1.0;
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
        append_window_clipped_triangle(output, triangle, damage, window_clip);
    }
}

fn append_window_clipped_triangle(
    output: &mut Vec<Vertex>,
    triangle: [Vertex; 3],
    damage: Rect,
    window_clip: Option<&[(f32, f32)]>,
) {
    let Some(window_clip) = window_clip else {
        append_clipped_triangle(output, triangle, damage);
        return;
    };
    let mut damage_clipped = Vec::new();
    append_clipped_triangle(&mut damage_clipped, triangle, damage);
    for triangle in damage_clipped.chunks_exact(3) {
        let mut polygon = triangle.to_vec();
        for index in 0..window_clip.len() {
            let edge_start = window_clip[index];
            let edge_end = window_clip[(index + 1) % window_clip.len()];
            polygon = clip_convex_edge(&polygon, edge_start, edge_end);
            if polygon.len() < 3 {
                break;
            }
        }
        if polygon.len() < 3 {
            continue;
        }
        for index in 1..polygon.len() - 1 {
            output.extend_from_slice(&[polygon[0], polygon[index], polygon[index + 1]]);
        }
    }
}

fn clip_convex_edge(input: &[Vertex], edge_start: (f32, f32), edge_end: (f32, f32)) -> Vec<Vertex> {
    let signed_distance = |vertex: Vertex| {
        (edge_end.0 - edge_start.0) * (vertex.y - edge_start.1)
            - (edge_end.1 - edge_start.1) * (vertex.x - edge_start.0)
    };
    let mut output = Vec::new();
    let Some(mut previous) = input.last().copied() else {
        return output;
    };
    let mut previous_distance = signed_distance(previous);
    for current in input.iter().copied() {
        let current_distance = signed_distance(current);
        let previous_inside = previous_distance >= -0.001;
        let current_inside = current_distance >= -0.001;
        if previous_inside != current_inside {
            let denominator = previous_distance - current_distance;
            let amount = if denominator.abs() <= f32::EPSILON {
                0.0
            } else {
                previous_distance / denominator
            };
            output.push(interpolate(previous, current, amount));
        }
        if current_inside {
            output.push(current);
        }
        previous = current;
        previous_distance = current_distance;
    }
    output
}

fn push_solid_quad(output: &mut Vec<Vertex>, bounds: Rect, color: [f32; 4]) {
    let left = bounds.x as f32;
    let top = bounds.y as f32;
    let right = left + bounds.width as f32;
    let bottom = top + bounds.height as f32;
    let uv = 0.5;
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

fn push_batch(
    batches: &mut Vec<mochios_viewkit_gpu_protocol::compositor::Batch>,
    texture_key: u64,
    first_vertex: u32,
    end_vertex: u32,
) {
    let vertex_count = end_vertex.saturating_sub(first_vertex);
    if vertex_count != 0 {
        batches.push(mochios_viewkit_gpu_protocol::compositor::Batch {
            texture_key,
            first_vertex,
            vertex_count,
        });
    }
}

fn encode_compositor_scene(
    vertices: &[Vertex],
    textures: &[TextureRequirement],
    uploads: &[TextureUpload],
    batches: &[mochios_viewkit_gpu_protocol::compositor::Batch],
    width: u32,
    height: u32,
    output: &mut Vec<u8>,
) -> Option<()> {
    if vertices.len() > mochios_viewkit_gpu_protocol::MAX_VERTICES as usize {
        return None;
    }
    let data_bytes = uploads.iter().try_fold(0usize, |length, upload| {
        length.checked_add(upload.pixels.len())
    })?;
    let total = mochios_viewkit_gpu_protocol::compositor::encoded_len(
        vertices.len() as u32,
        textures.len() as u32,
        batches.len() as u32,
        data_bytes,
    )
    .ok()?;
    output.clear();
    output.resize(total, 0);
    mochios_viewkit_gpu_protocol::compositor::encode_header(
        output,
        width,
        height,
        vertices.len() as u32,
        textures.len() as u32,
        batches.len() as u32,
        data_bytes,
    )
    .ok()?;
    let batch_offset = mochios_viewkit_gpu_protocol::compositor::HEADER_LEN
        + textures.len() * mochios_viewkit_gpu_protocol::compositor::TEXTURE_DESC_LEN;
    let vertex_offset =
        batch_offset + batches.len() * mochios_viewkit_gpu_protocol::compositor::BATCH_DESC_LEN;
    let mut data_offset =
        vertex_offset + vertices.len() * mochios_viewkit_gpu_protocol::VERTEX_STRIDE;
    for (index, texture) in textures.iter().enumerate() {
        let upload = uploads.iter().find(|upload| upload.key == texture.key);
        let (encoded_offset, data_len, data_height) = upload.map_or((0, 0, 0), |upload| {
            (data_offset, upload.pixels.len(), texture.height)
        });
        mochios_viewkit_gpu_protocol::compositor::encode_texture(
            output,
            index as u32,
            texture.key,
            texture.width,
            texture.height,
            0,
            data_height,
            encoded_offset,
            data_len,
            texture.generation,
        )
        .ok()?;
        if let Some(upload) = upload {
            output
                .get_mut(data_offset..data_offset.checked_add(upload.pixels.len())?)?
                .copy_from_slice(&upload.pixels);
            data_offset += upload.pixels.len();
        }
    }
    for (index, batch) in batches.iter().copied().enumerate() {
        mochios_viewkit_gpu_protocol::compositor::encode_batch(
            output,
            batch_offset,
            index as u32,
            batch,
        )
        .ok()?;
    }
    let mut offset = vertex_offset;
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
    (offset == vertex_offset + vertices.len() * mochios_viewkit_gpu_protocol::VERTEX_STRIDE)
        .then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_keep_independent_surface_textures() {
        let mut batches = Vec::new();
        push_batch(&mut batches, 10, 6, 12);
        push_batch(&mut batches, 11, 12, 18);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].texture_key, 10);
        assert_eq!(batches[1].texture_key, 11);
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

    #[test]
    fn window_clip_removes_square_corners() {
        let clip = rounded_rect_polygon(
            Rect {
                x: 0,
                y: 0,
                width: 100,
                height: 100,
            },
            20.0,
        );
        let mut output = Vec::new();
        append_textured_quad_clipped(
            &mut output,
            Rect {
                x: 0,
                y: 0,
                width: 100,
                height: 100,
            },
            Rect {
                x: 0,
                y: 0,
                width: 100,
                height: 100,
            },
            Some(&clip),
        );
        assert!(!output.is_empty());
        assert!(output.iter().all(|vertex| {
            let nearest_x = vertex.x.clamp(20.0, 80.0);
            let nearest_y = vertex.y.clamp(20.0, 80.0);
            let dx = vertex.x - nearest_x;
            let dy = vertex.y - nearest_y;
            dx * dx + dy * dy <= 20.5 * 20.5
        }));
        assert!(
            !output
                .iter()
                .any(|vertex| vertex.x == 0.0 && vertex.y == 0.0)
        );
    }
}
