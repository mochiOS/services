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
    data_y: u32,
    data_height: u32,
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
        // Clipping and coordinate round trips can collapse a triangle to an
        // edge. Keeping it lets later damage cuts multiply invisible geometry.
        if !triangle_has_area(&triangle) {
            continue;
        }
        let (outside, inside) = triangle_rect_bounds(&triangle, damage);
        if outside {
            // Do not split unchanged geometry at the extended damage edges.
            retained.extend_from_slice(&triangle);
            continue;
        }
        if inside {
            continue;
        }
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

#[derive(Clone, PartialEq)]
struct SurfaceGeometryKey {
    handle: u64,
    generation: u64,
    position: (i32, i32),
    size: (u32, u32),
    format: u32,
    window_clip: Option<WindowClip>,
}

#[derive(Clone, PartialEq)]
struct WindowClip {
    polygon: Vec<(f32, f32)>,
    bounds: [f32; 4],
    interior: [f32; 4],
}

#[derive(PartialEq)]
struct DesktopGeometryKey {
    size: (u32, u32),
    surfaces: Vec<SurfaceGeometryKey>,
}

struct SurfaceGeometry {
    key: SurfaceGeometryKey,
    display_size: (u32, u32),
    vertices: Vec<Vertex>,
}

#[derive(Default)]
pub(crate) struct GpuCompositor {
    textures: Vec<TextureRequirement>,
    uploads: Vec<TextureUpload>,
    batches: Vec<mochios_viewkit_gpu_protocol::compositor::Batch>,
    vertices: Vec<Vertex>,
    output: Vec<u8>,
    desktop_key: Option<DesktopGeometryKey>,
    desktop_vertices: usize,
    desktop_batches: usize,
    dirty_vertices: Vec<Vertex>,
    dirty_batches: Vec<mochios_viewkit_gpu_protocol::compositor::Batch>,
    surface_geometry: Vec<SurfaceGeometry>,
}

impl GpuCompositor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compose(
        &mut self,
        surfaces: &[Surface],
        windows: &[Window],
        display_width: u32,
        display_height: u32,
        cursor_x: i32,
        cursor_y: i32,
        cursor_visible: bool,
        cursor: &CursorImage,
        dirty: Option<Rect>,
    ) -> Option<&[u8]> {
        let damage = clip_present_rect(
            // Scene consumers clear their render target before drawing.
            None,
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
                let (data_y, data_height) =
                    texture_upload_range(*requirement, self.textures.as_slice(), surfaces)?;
                self.uploads.push(TextureUpload {
                    key: requirement.key,
                    data_y,
                    data_height,
                    pixels: texture_pixels(*requirement, data_y, data_height, surfaces, cursor)?,
                });
            }
        }
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
        let desktop_key = DesktopGeometryKey {
            size: (display_width, display_height),
            surfaces: indices.iter().map(|&index| {
                let surface = &surfaces[index];
                SurfaceGeometryKey {
                    handle: surface.handle.0,
                    generation: surface.content_generation,
                    position: (surface.x, surface.y),
                    size: if surface.current_format == PIXEL_FORMAT_GPU_SCENE {
                        surface.gpu.as_ref().map(|gpu| (gpu.width, gpu.height)).unwrap_or_default()
                    } else {
                        (surface.current_width, surface.current_height)
                    },
                    format: surface.current_format,
                    window_clip: window_clip_polygon(surfaces, windows, surface),
                }
            }).collect(),
        };
        self.surface_geometry.retain(|cached| {
            desktop_key.surfaces.iter().any(|key| key.handle == cached.key.handle)
        });
        // Only a successfully encoded scene may supply reusable geometry.
        let reuse_desktop = self.desktop_key.take().as_ref() == Some(&desktop_key);
        let normalize_from;
        if reuse_desktop {
            self.vertices.truncate(self.desktop_vertices);
            self.batches.truncate(self.desktop_batches);
            normalize_from = self.vertices.len();
        } else {
            self.vertices.clear();
            self.batches.clear();
            normalize_from = 0;
            push_solid_quad(&mut self.vertices, damage, [0.0, 0.0, 1.0, 1.0]);
            push_batch(&mut self.batches, WHITE_TEXTURE_KEY, 0, self.vertices.len() as u32);
            for (index, key) in indices.into_iter().zip(&desktop_key.surfaces) {
                let surface = &surfaces[index];
                let first = self.vertices.len() as u32;
                let cached_index = self.surface_geometry.iter()
                    .position(|cached| cached.key.handle == key.handle);
                let valid = cached_index.is_some_and(|index| {
                    let cached = &self.surface_geometry[index];
                    cached.key == *key && cached.display_size == desktop_key.size
                });
                if !valid {
                    let mut vertices = Vec::new();
                    if surface.current_format == PIXEL_FORMAT_GPU_SCENE {
                        append_gpu_surface(&mut vertices, surface, damage, key.window_clip.as_ref())?;
                    } else {
                        append_cpu_surface(&mut vertices, surface, damage, key.window_clip.as_ref());
                    }
                    let geometry = SurfaceGeometry {
                        key: key.clone(), display_size: desktop_key.size, vertices,
                    };
                    if let Some(index) = cached_index {
                        self.surface_geometry[index] = geometry;
                    } else {
                        self.surface_geometry.push(geometry);
                    }
                }
                let cached = &self.surface_geometry[cached_index
                    .unwrap_or(self.surface_geometry.len() - 1)];
                self.vertices.extend_from_slice(&cached.vertices);
                push_batch(
                    &mut self.batches,
                    surface.handle.0,
                    first,
                    self.vertices.len() as u32,
                );
            }
        }
        self.desktop_vertices = self.vertices.len();
        self.desktop_batches = self.batches.len();
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
        for vertex in &mut self.vertices[normalize_from..] {
            vertex.x = vertex.x / display_width as f32 * 2.0 - 1.0;
            vertex.y = vertex.y / display_height as f32 * 2.0 - 1.0;
        }
        // The first opaque quad describes the replacement region. The v1
        // packet layout stays unchanged; a full-screen quad still means full redraw.
        let dirty = clip_present_rect(dirty, display_width as usize, display_height as usize)?;
        for (destination, mut vertex) in self.vertices[..6].iter_mut()
            .zip(solid_quad(dirty, [0.0, 0.0, 1.0, 1.0]))
        {
            vertex.x = vertex.x / display_width as f32 * 2.0 - 1.0;
            vertex.y = vertex.y / display_height as f32 * 2.0 - 1.0;
            *destination = vertex;
        }
        self.dirty_vertices.clear();
        self.dirty_batches.clear();
        let left = dirty.x as f32 / display_width as f32 * 2.0 - 1.0;
        let top = dirty.y as f32 / display_height as f32 * 2.0 - 1.0;
        let right = left + dirty.width as f32 / display_width as f32 * 2.0;
        let bottom = top + dirty.height as f32 / display_height as f32 * 2.0;
        // Preserve painter order and whole triangles. The retained target's
        // scissor clips boundary triangles; unrelated geometry need not cross IPC.
        for batch in &self.batches {
            let first = self.dirty_vertices.len() as u32;
            let start = batch.first_vertex as usize;
            let end = start + batch.vertex_count as usize;
            for triangle in self.vertices[start..end].chunks_exact(3) {
                if triangle.iter().all(|v| v.x < left)
                    || triangle.iter().all(|v| v.x > right)
                    || triangle.iter().all(|v| v.y < top)
                    || triangle.iter().all(|v| v.y > bottom)
                {
                    continue;
                }
                self.dirty_vertices.extend_from_slice(triangle);
            }
            push_batch(&mut self.dirty_batches, batch.texture_key, first,
                       self.dirty_vertices.len() as u32);
        }
        encode_compositor_scene(
            &self.dirty_vertices,
            &requirements,
            &self.uploads,
            &self.dirty_batches,
            display_width,
            display_height,
            &mut self.output,
        )?;
        self.textures = requirements;
        self.desktop_key = Some(desktop_key);
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
    data_y: u32,
    data_height: u32,
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
        let source_row_bytes = usize::try_from(gpu.atlas_width).ok()?.checked_mul(4)?;
        let source_start = usize::try_from(data_y)
            .ok()?
            .checked_mul(source_row_bytes)?;
        return collect_bytes(
            requirement.width,
            data_height,
            gpu.atlas_width,
            gpu.atlas.get(source_start..)?,
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

fn texture_upload_range(
    requirement: TextureRequirement,
    cached_textures: &[TextureRequirement],
    surfaces: &[Surface],
) -> Option<(u32, u32)> {
    let Some(surface_index) = requirement.surface_index else {
        return Some((0, requirement.height));
    };
    let surface = surfaces.get(surface_index)?;
    if surface.current_format != PIXEL_FORMAT_GPU_SCENE {
        return Some((0, requirement.height));
    }
    let gpu = surface.gpu.as_ref()?;
    let Some(cached) = cached_textures.iter().find(|cached| {
        cached.key == requirement.key
            && cached.width == requirement.width
            && cached.height == requirement.height
    }) else {
        return Some((0, requirement.height));
    };
    let next_generation = cached.generation.wrapping_add(1).max(1);
    if next_generation != requirement.generation
        || gpu.atlas_dirty_height == 0
        || gpu.atlas_dirty_y.checked_add(gpu.atlas_dirty_height)? > requirement.height
    {
        return Some((0, requirement.height));
    }
    Some((gpu.atlas_dirty_y, gpu.atlas_dirty_height))
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
    window_clip: Option<&WindowClip>,
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
    window_clip: Option<&WindowClip>,
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
) -> Option<WindowClip> {
    let window = windows.get(window_index_by_id(windows, surface.window)?)?;
    let content = surfaces
        .iter()
        .find(|candidate| candidate.live && candidate.handle == window.content)?;
    let frame = window_frame_rect(content, window);
    Some(rounded_rect_polygon(frame, WINDOW_CORNER_RADIUS as f32))
}

fn rounded_rect_polygon(rect: Rect, radius: f32) -> WindowClip {
    const CORNER_SEGMENTS: usize = 8;
    let radius = radius
        .max(0.0)
        .min(rect.width.min(rect.height) as f32 * 0.5);
    let left = rect.x as f32;
    let top = rect.y as f32;
    let right = left + rect.width as f32;
    let bottom = top + rect.height as f32;
    let bounds = [left, top, right, bottom];
    let interior = [left + radius, top + radius, right - radius, bottom - radius];
    if radius == 0.0 {
        return WindowClip {
            polygon: vec![(left, top), (right, top), (right, bottom), (left, bottom)],
            bounds,
            interior,
        };
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
    WindowClip { polygon: points, bounds, interior }
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
    window_clip: Option<&WindowClip>,
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
    window_clip: Option<&WindowClip>,
) {
    let (outside, inside) = triangle_rect_bounds(&triangle, damage);
    if outside { return; }
    let Some(window_clip) = window_clip else {
        append_clipped_triangle(output, triangle, damage);
        return;
    };
    // A rounded rectangle differs from its bounds only in the four corner
    // squares. Its full horizontal and vertical interior strips therefore
    // need no per-edge polygon clipping.
    let (mut min_x, mut min_y, mut max_x, mut max_y) =
        (f32::INFINITY, f32::INFINITY, f32::NEG_INFINITY, f32::NEG_INFINITY);
    for vertex in triangle {
        min_x = min_x.min(vertex.x);
        min_y = min_y.min(vertex.y);
        max_x = max_x.max(vertex.x);
        max_y = max_y.max(vertex.y);
    }
    let [left, top, right, bottom] = window_clip.bounds;
    let [inner_left, inner_top, inner_right, inner_bottom] = window_clip.interior;
    let inside_bounds = min_x >= left && min_y >= top && max_x <= right && max_y <= bottom;
    let inside_core = min_x >= inner_left && max_x <= inner_right
        || min_y >= inner_top && max_y <= inner_bottom;
    if inside_bounds && inside_core {
        append_clipped_triangle(output, triangle, damage);
        return;
    }
    let window_clip = &window_clip.polygon;
    let mut window_inside = true;
    for index in 0..window_clip.len() {
        let start = window_clip[index];
        let end = window_clip[(index + 1) % window_clip.len()];
        let count = triangle.iter().filter(|vertex| edge_distance(**vertex, start, end) >= -0.001).count();
        if count == 0 { return; }
        window_inside &= count == 3;
    }
    if inside && window_inside {
        output.extend_from_slice(&triangle);
        return;
    }
    let mut damage_clipped = Vec::new();
    append_clipped_triangle(&mut damage_clipped, triangle, damage);
    for triangle in damage_clipped.chunks_exact(3) {
        let mut polygon = triangle.to_vec();
        for index in 0..window_clip.len() {
            let edge_start = window_clip[index];
            let edge_end = window_clip[(index + 1) % window_clip.len()];
            polygon = clip_convex_edge(polygon, edge_start, edge_end);
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

fn edge_distance(vertex: Vertex, start: (f32, f32), end: (f32, f32)) -> f32 {
    (end.0 - start.0) * (vertex.y - start.1)
        - (end.1 - start.1) * (vertex.x - start.0)
}

fn clip_convex_edge(mut input: Vec<Vertex>, edge_start: (f32, f32), edge_end: (f32, f32)) -> Vec<Vertex> {
    let signed_distance = |vertex| edge_distance(vertex, edge_start, edge_end);
    // Most edges do not cut this polygon. Keep its allocation and attributes
    // instead of copying it once for every edge of a rounded window.
    let inside_count = input.iter().filter(|&&vertex| signed_distance(vertex) >= -0.001).count();
    if inside_count == input.len() {
        return input;
    }
    if inside_count == 0 {
        input.clear();
        return input;
    }
    let mut output = Vec::with_capacity(input.len() + 1);
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
    output.extend_from_slice(&solid_quad(bounds, color));
}

fn solid_quad(bounds: Rect, color: [f32; 4]) -> [Vertex; 6] {
    let left = bounds.x as f32;
    let top = bounds.y as f32;
    let right = left + bounds.width as f32;
    let bottom = top + bounds.height as f32;
    let uv = 0.5;
    [
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
    ]
}

// Common-plane rejection and complete containment need no polygon allocation.
fn triangle_rect_bounds(triangle: &[Vertex; 3], rect: Rect) -> (bool, bool) {
    let left = rect.x as f32;
    let top = rect.y as f32;
    let right = left + rect.width as f32;
    let bottom = top + rect.height as f32;
    let (mut any, mut all) = (0u8, 15u8);
    for vertex in triangle {
        let code = u8::from(vertex.x < left)
            | (u8::from(vertex.x > right) << 1)
            | (u8::from(vertex.y < top) << 2)
            | (u8::from(vertex.y > bottom) << 3);
        any |= code;
        all &= code;
    }
    (all != 0, any == 0)
}

fn triangle_has_area(triangle: &[Vertex; 3]) -> bool {
    let [a, b, c] = *triangle;
    (b.x - a.x) * (c.y - a.y) != (b.y - a.y) * (c.x - a.x)
}

fn append_clipped_triangle(output: &mut Vec<Vertex>, triangle: [Vertex; 3], rect: Rect) {
    if !triangle_has_area(&triangle) {
        return;
    }
    let (outside, inside) = triangle_rect_bounds(&triangle, rect);
    if outside { return; }
    if inside {
        output.extend_from_slice(&triangle);
        return;
    }
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
        let triangle = [polygon[0], polygon[index], polygon[index + 1]];
        if triangle_has_area(&triangle) {
            output.extend_from_slice(&triangle);
        }
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
        let (encoded_offset, data_len, data_y, data_height) =
            upload.map_or((0, 0, 0, 0), |upload| {
                (
                    data_offset,
                    upload.pixels.len(),
                    upload.data_y,
                    upload.data_height,
                )
            });
        mochios_viewkit_gpu_protocol::compositor::encode_texture(
            output,
            index as u32,
            texture.key,
            texture.width,
            texture.height,
            data_y,
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
    fn repeated_damage_does_not_multiply_collapsed_triangles() {
        let full = Rect { x: 0, y: 0, width: 1920, height: 1080 };
        let mut scene = Vec::new();
        encode_local_vertices(&solid_quad(full, [1.0; 4]), 1920, 1080, &mut scene).unwrap();
        for i in 0..200 {
            let damage = Rect { x: 100 + (i % 100) * 3, y: 100 + (i / 100) * 3,
                width: 40, height: 40 };
            let mut replacement = Vec::new();
            encode_local_vertices(&solid_quad(damage, [0.5; 4]), 1920, 1080,
                &mut replacement).unwrap();
            let mut output = Vec::new();
            merge_surface_vertices(&scene, &replacement, 1920, 1080, damage,
                &mut output).unwrap();
            scene = output;
        }
        // Previously exceeded the protocol limit before completing this sequence.
        assert!(scene.len() / mochios_viewkit_gpu_protocol::VERTEX_STRIDE < 10_000);
    }

    #[test]
    fn clipping_discards_only_zero_area_triangles() {
        let vertex = |x, y| Vertex { x, y, u: x, v: y, color: [1.0; 4] };
        let rect = Rect { x: 0, y: 0, width: 10, height: 10 };
        let mut output = Vec::new();
        append_clipped_triangle(&mut output,
            [vertex(1.0, 1.0), vertex(2.0, 2.0), vertex(3.0, 3.0)], rect);
        assert!(output.is_empty());
        let thin = [vertex(1.0, 1.0), vertex(2.0, 1.0), vertex(1.0, 1.000001)];
        append_clipped_triangle(&mut output, thin, rect);
        assert_eq!(output.len(), 3);
        for (actual, expected) in output.iter().zip(thin) {
            assert_eq!((actual.x, actual.y, actual.u, actual.v, actual.color),
                (expected.x, expected.y, expected.u, expected.v, expected.color));
        }
    }

    #[test]
    fn cached_desktop_matches_rebuilt_scene_across_changes() {
        let mut surfaces: Vec<_> = (1..=2).map(|handle| {
            let mut surface = gpu_surface(1, 0, 3);
            surface.live = true;
            surface.visible = true;
            surface.handle = crate::surface::SurfaceHandle(handle);
            surface.current_width = 50;
            surface.current_height = 50;
            surface.content_generation = 1;
            let gpu = surface.gpu.as_mut().unwrap();
            gpu.width = 50;
            gpu.height = 50;
            let mut vertices = Vec::new();
            push_solid_quad(&mut vertices, Rect { x: 0, y: 0, width: 50, height: 50 }, [1.0; 4]);
            encode_local_vertices(&vertices, 50, 50, &mut gpu.vertices).unwrap();
            surface
        }).collect();
        let mut window = Window::empty();
        window.live = true;
        window.id = crate::window::WindowId(1);
        window.content = surfaces[0].handle;
        surfaces[0].window = window.id;
        let mut windows = [window];
        let mut cursor = CursorImage::default();
        assert!(cursor.set_premultiplied_rgba(1, 1, 0, 0, &[255; 4]));
        let mut cached = GpuCompositor::default();
        for step in 0..12 {
            match step {
                2 => surfaces[0].x = -10,
                3 => surfaces[0].z = 9,
                4 => windows[0].insets.left = 4,
                5 => {
                    surfaces[0].content_generation += 1;
                    surfaces[0].gpu.as_mut().unwrap().vertices.truncate(3 * mochios_viewkit_gpu_protocol::VERTEX_STRIDE);
                }
                6 => surfaces[1].visible = false,
                7 => surfaces[1].visible = true,
                8 => surfaces[0].live = false,
                _ => {}
            }
            let width = if step >= 9 { 200 } else { 100 };
            let mut rebuilt = GpuCompositor {
                textures: cached.textures.clone(),
                ..Default::default()
            };
            let expected = rebuilt.compose(&surfaces, &windows, width, 100, step, step, step % 2 == 0, &cursor, None).unwrap();
            let actual = cached.compose(&surfaces, &windows, width, 100, step, step, step % 2 == 0, &cursor, None).unwrap();
            assert_eq!(actual, expected, "step {step}");
        }
    }

    #[test]
    fn failed_composition_does_not_cache_unsent_textures() {
        let mut compositor = GpuCompositor::default();
        let mut surface = gpu_surface(1, 0, 3);
        surface.live = true;
        surface.visible = true;
        surface.handle = crate::surface::SurfaceHandle(10);
        let gpu = surface.gpu.as_mut().unwrap();
        gpu.vertices = vec![0; mochios_viewkit_gpu_protocol::VERTEX_STRIDE * 3];
        gpu.vertices[..4].copy_from_slice(&f32::NAN.to_le_bytes());
        assert!(compositor.compose(
            &[surface], &[], 100, 100, 0, 0, false, &CursorImage::default(), None,
        ).is_none());
        assert!(compositor.textures.is_empty());
    }

    #[test]
    fn scene_background_always_covers_the_display() {
        let mut compositor = GpuCompositor::default();
        compositor.compose(&[], &[], 1920, 1080, 0, 0, false, &CursorImage::default(), None).unwrap();
        for (x, y) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
            assert!(compositor.vertices.iter().any(|vertex| vertex.x == x && vertex.y == y));
        }
    }

    #[test]
    fn dirty_quad_preserves_v1_packet_and_resets_on_full_redraw() {
        let mut compositor = GpuCompositor::default();
        for dirty in [Some(Rect { x: 20, y: 30, width: 40, height: 50 }), None] {
            let bytes = compositor.compose(&[], &[], 100, 100, 0, 0, false,
                &CursorImage::default(), dirty).unwrap();
            let scene = mochios_viewkit_gpu_protocol::compositor::decode(bytes).unwrap();
            assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 1);
            assert_eq!(scene.batch(0).unwrap().vertex_count, 6);
            let expected = dirty.unwrap_or(Rect::full(100, 100));
            assert!((read_f32(scene.vertices, 0).unwrap() - (expected.x as f32 / 50.0 - 1.0)).abs() < 0.00001);
            assert!((read_f32(scene.vertices, 4).unwrap() - (expected.y as f32 / 50.0 - 1.0)).abs() < 0.00001);
            assert!((read_f32(scene.vertices, 72).unwrap() - ((expected.x as f32 + expected.width as f32) / 50.0 - 1.0)).abs() < 0.00001);
            assert!((read_f32(scene.vertices, 76).unwrap() - ((expected.y as f32 + expected.height as f32) / 50.0 - 1.0)).abs() < 0.00001);
        }
    }

    fn gpu_surface(atlas_generation: u64, dirty_y: u32, dirty_height: u32) -> Surface {
        let mut surface = Surface::empty();
        surface.current_format = PIXEL_FORMAT_GPU_SCENE;
        surface.gpu = Some(crate::surface::GpuSurfaceState {
            atlas_width: 2,
            atlas_height: 3,
            atlas: (0..24).collect(),
            atlas_generation,
            atlas_dirty_y: dirty_y,
            atlas_dirty_height: dirty_height,
            ..crate::surface::GpuSurfaceState::default()
        });
        surface
    }

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
    fn consecutive_gpu_atlas_generation_uploads_only_dirty_rows() {
        let surfaces = [gpu_surface(7, 1, 1)];
        let requirement = TextureRequirement {
            key: 10,
            width: 2,
            height: 3,
            generation: 7,
            surface_index: Some(0),
        };
        let cached = [TextureRequirement {
            generation: 6,
            ..requirement
        }];
        assert_eq!(
            texture_upload_range(requirement, &cached, &surfaces),
            Some((1, 1))
        );
        assert_eq!(
            texture_pixels(requirement, 1, 1, &surfaces, &CursorImage::default()),
            Some((8..16).collect())
        );
    }

    #[test]
    fn skipped_gpu_atlas_generation_falls_back_to_full_upload() {
        let surfaces = [gpu_surface(7, 1, 1)];
        let requirement = TextureRequirement {
            key: 10,
            width: 2,
            height: 3,
            generation: 7,
            surface_index: Some(0),
        };
        let cached = [TextureRequirement {
            generation: 5,
            ..requirement
        }];
        assert_eq!(
            texture_upload_range(requirement, &cached, &surfaces),
            Some((0, 3))
        );
    }

    #[test]
    fn compositor_scene_encodes_partial_texture_rows() {
        let textures = [TextureRequirement {
            key: 10,
            width: 2,
            height: 3,
            generation: 7,
            surface_index: Some(0),
        }];
        let uploads = [TextureUpload {
            key: 10,
            data_y: 1,
            data_height: 1,
            pixels: vec![1; 8],
        }];
        let vertices = [Vertex {
            x: 0.0,
            y: 0.0,
            u: 0.0,
            v: 0.0,
            color: [1.0; 4],
        }; 3];
        let batches = [mochios_viewkit_gpu_protocol::compositor::Batch {
            texture_key: 10,
            first_vertex: 0,
            vertex_count: 3,
        }];
        let mut output = Vec::new();
        encode_compositor_scene(
            &vertices,
            &textures,
            &uploads,
            &batches,
            100,
            100,
            &mut output,
        )
        .unwrap();
        let scene = mochios_viewkit_gpu_protocol::compositor::decode(&output).unwrap();
        let texture = scene.texture(0).unwrap();
        assert_eq!((texture.data_y, texture.data_height), (1, 1));
        assert_eq!(texture.data, &[1; 8]);
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
    fn contained_triangles_preserve_attributes_and_exterior_triangles_are_rejected() {
        let rect = Rect { x: 0, y: 0, width: 100, height: 100 };
        let clip = rounded_rect_polygon(rect, 20.0);
        let triangle = [(40.0, 40.0), (60.0, 40.0), (50.0, 60.0)].map(|(x, y)| Vertex {
            x, y, u: x / 100.0, v: y / 100.0, color: [0.25, 0.5, 0.75, 1.0],
        });
        let mut output = Vec::with_capacity(3);
        append_window_clipped_triangle(&mut output, triangle, rect, Some(&clip));
        assert_eq!(output.len(), 3);
        for (actual, expected) in output.iter().zip(triangle) {
            assert_eq!((actual.x, actual.y, actual.u, actual.v, actual.color),
                (expected.x, expected.y, expected.u, expected.v, expected.color));
        }
        output.clear();
        let exterior = triangle.map(|vertex| Vertex { x: vertex.x - 200.0, ..vertex });
        append_window_clipped_triangle(&mut output, exterior, rect, Some(&clip));
        assert!(output.is_empty());
    }

    #[test]
    fn interior_fast_path_still_clips_damage() {
        let frame = Rect { x: 0, y: 0, width: 100, height: 100 };
        let clip = rounded_rect_polygon(frame, 20.0);
        let triangle = [(30.0, 30.0), (70.0, 30.0), (50.0, 70.0)].map(|(x, y)| Vertex {
            x, y, u: x, v: y, color: [0.5; 4],
        });
        let damage = Rect { x: 40, y: 40, width: 20, height: 20 };
        let mut expected = Vec::new();
        let mut actual = Vec::new();
        append_clipped_triangle(&mut expected, triangle, damage);
        append_window_clipped_triangle(&mut actual, triangle, damage, Some(&clip));
        assert!(!actual.is_empty());
        assert_eq!(actual.len(), expected.len());
        for (a, b) in actual.iter().zip(expected) {
            assert_eq!((a.x, a.y, a.u, a.v, a.color), (b.x, b.y, b.u, b.v, b.color));
        }
    }

    #[test]
    fn rounded_rect_side_strips_skip_polygon_clipping() {
        let clip = rounded_rect_polygon(Rect { x: 0, y: 0, width: 100, height: 100 }, 20.0);
        for triangle in [
            [(2.0, 30.0), (18.0, 35.0), (2.0, 70.0)],
            [(30.0, 2.0), (70.0, 2.0), (35.0, 18.0)],
        ] {
            let triangle = triangle.map(|(x, y)| Vertex {
                x, y, u: x, v: y, color: [0.5; 4],
            });
            let mut expected = Vec::new();
            let mut actual = Vec::new();
            append_clipped_triangle(&mut expected, triangle, Rect::full(100, 100));
            append_window_clipped_triangle(
                &mut actual,
                triangle,
                Rect::full(100, 100),
                Some(&clip),
            );
            assert_eq!(actual.len(), expected.len());
        }
    }

    #[test]
    fn convex_clip_reuses_uncut_storage() {
        let vertices = [(1.0, 1.0), (3.0, 1.0), (2.0, 3.0)].map(|(x, y)| Vertex {
            x, y, u: x, v: y, color: [0.5; 4],
        });
        let polygon = vertices.to_vec();
        let allocation = polygon.as_ptr();
        let polygon = clip_convex_edge(polygon, (0.0, 0.0), (4.0, 0.0));
        assert_eq!(polygon.as_ptr(), allocation);
        assert_eq!(polygon.len(), vertices.len());
        for (actual, expected) in polygon.iter().zip(vertices) {
            assert_eq!((actual.x, actual.y, actual.u, actual.v, actual.color),
                (expected.x, expected.y, expected.u, expected.v, expected.color));
        }
        let polygon = clip_convex_edge(polygon, (0.0, 4.0), (4.0, 4.0));
        assert_eq!(polygon.as_ptr(), allocation);
        assert!(polygon.is_empty());
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
