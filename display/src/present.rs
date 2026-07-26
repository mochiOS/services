use mochi_user_syscall::{EINVAL, ERANGE};

pub(crate) const PIXEL_FORMAT_XRGB8888: u32 = 1;
pub(crate) const BYTES_PER_PIXEL: usize = 4;
pub(crate) const MAX_DIMENSION: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DisplayGeometry {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) stride: u32,
    pub(crate) format: u32,
}

impl DisplayGeometry {
    pub(crate) fn byte_len(self) -> Result<usize, u64> {
        if self.width == 0
            || self.height == 0
            || self.width > MAX_DIMENSION
            || self.height > MAX_DIMENSION
            || self.stride < self.width
            || self.stride > MAX_DIMENSION
            || self.format != PIXEL_FORMAT_XRGB8888
        {
            return Err(EINVAL);
        }
        (self.stride as usize)
            .checked_mul(BYTES_PER_PIXEL)
            .and_then(|row| row.checked_mul(self.height as usize))
            .ok_or(ERANGE)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DamageRect {
    pub(crate) x: u32,
    pub(crate) y: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

impl DamageRect {
    pub(crate) const fn full(geometry: DisplayGeometry) -> Self {
        Self {
            x: 0,
            y: 0,
            width: geometry.width,
            height: geometry.height,
        }
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }

    pub(crate) fn validate(self, geometry: DisplayGeometry) -> Result<(), u64> {
        if self.is_empty() {
            return Ok(());
        }
        let right = self.x.checked_add(self.width).ok_or(ERANGE)?;
        let bottom = self.y.checked_add(self.height).ok_or(ERANGE)?;
        if right > geometry.width || bottom > geometry.height {
            return Err(EINVAL);
        }
        Ok(())
    }
}

pub(crate) struct PresentFrame<'a> {
    pub(crate) geometry: DisplayGeometry,
    pub(crate) pixels: &'a [u8],
    pub(crate) damage: DamageRect,
}

impl PresentFrame<'_> {
    pub(crate) fn validate(&self) -> Result<(), u64> {
        let required = self.geometry.byte_len()?;
        if self.pixels.len() < required {
            return Err(EINVAL);
        }
        self.damage.validate(self.geometry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEOMETRY: DisplayGeometry = DisplayGeometry {
        width: 4,
        height: 3,
        stride: 6,
        format: PIXEL_FORMAT_XRGB8888,
    };

    #[test]
    fn geometry_requires_explicit_valid_stride_and_format() {
        assert_eq!(GEOMETRY.byte_len(), Ok(72));
        for invalid in [
            DisplayGeometry {
                width: 0,
                ..GEOMETRY
            },
            DisplayGeometry {
                height: 0,
                ..GEOMETRY
            },
            DisplayGeometry {
                stride: 3,
                ..GEOMETRY
            },
            DisplayGeometry {
                format: 2,
                ..GEOMETRY
            },
            DisplayGeometry {
                width: MAX_DIMENSION + 1,
                ..GEOMETRY
            },
        ] {
            assert_eq!(invalid.byte_len(), Err(EINVAL));
        }
    }

    #[test]
    fn damage_rejects_overflow_and_out_of_bounds_rectangles() {
        assert_eq!(DamageRect::default().validate(GEOMETRY), Ok(()));
        assert_eq!(DamageRect::full(GEOMETRY).validate(GEOMETRY), Ok(()));
        assert_eq!(
            DamageRect {
                x: 3,
                y: 0,
                width: 2,
                height: 1,
            }
            .validate(GEOMETRY),
            Err(EINVAL)
        );
        assert_eq!(
            DamageRect {
                x: u32::MAX,
                y: 0,
                width: 2,
                height: 1,
            }
            .validate(GEOMETRY),
            Err(ERANGE)
        );
    }

    #[test]
    fn frame_requires_complete_storage_and_accepts_extra_capacity() {
        let exact = [0u8; 72];
        let extra = [0u8; 76];
        let short = [0u8; 71];
        for pixels in [&exact[..], &extra[..]] {
            assert_eq!(
                PresentFrame {
                    geometry: GEOMETRY,
                    pixels,
                    damage: DamageRect::full(GEOMETRY),
                }
                .validate(),
                Ok(())
            );
        }
        assert_eq!(
            PresentFrame {
                geometry: GEOMETRY,
                pixels: &short,
                damage: DamageRect::full(GEOMETRY),
            }
            .validate(),
            Err(EINVAL)
        );
    }
}
