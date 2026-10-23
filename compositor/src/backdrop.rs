//! Sparse, privileged shell contrast sampling below panel surfaces.
use crate::{
    geometry::Rect,
    surface::{Surface, SurfaceRole, read_background_pixel, surface_extent},
    window::{Window, point_inside_window_frame},
};

pub(crate) fn sample_background(
    surfaces: &[Surface],
    windows: &[Window],
    area: Rect,
) -> Option<u32> {
    let mut stack: Vec<_> = surfaces
        .iter()
        .filter(|surface| {
            surface.live
                && surface.visible
                && matches!(
                    surface.role,
                    SurfaceRole::Background | SurfaceRole::Toplevel | SurfaceRole::Popup
                )
        })
        .collect();
    stack.sort_by_key(|surface| std::cmp::Reverse((surface.role.stack_layer(), surface.z)));
    let mut sums = [0.0; 4];
    for (fx, fy) in [(0.2, 0.3), (0.5, 0.3), (0.8, 0.3), (0.3, 0.7), (0.7, 0.7)] {
        let x = area.x.saturating_add((area.width as f32 * fx) as i32);
        let y = area.y.saturating_add((area.height as f32 * fy) as i32);
        let mut result = [0.0; 4];
        for surface in &stack {
            let (width, height) = surface_extent(surface);
            let sx = i64::from(x) - i64::from(surface.x);
            let sy = i64::from(y) - i64::from(surface.y);
            if sx < 0
                || sy < 0
                || sx >= i64::from(width)
                || sy >= i64::from(height)
                || !point_inside_window_frame(surfaces, windows, surface, x, y)
            {
                continue;
            }
            let Some(mut pixel) = read_background_pixel(surface, sx as usize, sy as usize) else {
                continue;
            };
            if surface.current_format == crate::protocol::PIXEL_FORMAT_XRGB8888 {
                pixel |= 0xff00_0000;
            }
            let remaining = 1.0 - result[3];
            for (index, shift) in [16, 8, 0, 24].into_iter().enumerate() {
                result[index] += ((pixel >> shift) & 255) as f32 / 255.0 * remaining;
            }
            if result[3] >= 0.999 {
                break;
            }
        }
        for index in 0..4 {
            sums[index] += result[index];
        }
    }
    if sums[3] < 0.01 {
        return None;
    }
    let channel = |index: usize| (sums[index] / sums[3] * 255.0).round().clamp(0.0, 255.0) as u32;
    Some((channel(0) << 24) | (channel(1) << 16) | (channel(2) << 8) | 255)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excludes_shell_panels_and_samples_the_frontmost_application() {
        let make = |role, z, pixel| {
            let mut surface = Surface::empty();
            surface.live = true;
            surface.visible = true;
            surface.width = 20;
            surface.height = 20;
            surface.current_width = 20;
            surface.current_height = 20;
            surface.current_stride = 20;
            surface.role = role;
            surface.z = z;
            surface.current = vec![pixel; 400];
            surface
        };
        let background = make(SurfaceRole::Background, 0, 0xff101010);
        let app = make(SurfaceRole::Toplevel, 1, 0xffeeeeee);
        let panel = make(SurfaceRole::Panel, 2, 0xff000000);
        let area = Rect {
            x: 0,
            y: 0,
            width: 20,
            height: 20,
        };
        assert_eq!(
            sample_background(&[background.clone(), app, panel], &[], area),
            Some(0xeeeeeeff)
        );
        assert_eq!(
            sample_background(&[background], &[], area),
            Some(0x101010ff)
        );
    }
}
