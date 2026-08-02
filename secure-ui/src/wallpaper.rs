use viewkit::draw_command::ImageSampling;
use viewkit::prelude::*;
use viewkit::view::{Constraints, MeasureContext, PaintContext};

const WALLPAPER_PATHS: [&str; 2] = [
    "/libraries/wallpapers/default.png",
    "/libraries/wallpapers/default.jpeg",
];

#[derive(Clone, Default)]
pub(crate) struct Wallpaper {
    image: Option<ImageData>,
}

impl Wallpaper {
    pub(crate) fn load_default() -> Self {
        let image = WALLPAPER_PATHS
            .iter()
            .find_map(|path| ImageData::from_path(path).ok());
        Self { image }
    }
}

impl View for Wallpaper {
    fn measure(&self, constraints: Constraints, _context: &mut MeasureContext<'_>) -> Size {
        constraints.maximum
    }

    fn paint(&self, bounds: Rect, context: &mut PaintContext<'_>) {
        Rectangle::new()
            .color(RectangleColor::Custom(Color::from_rgb_hex(0x29323a)))
            .paint(bounds, context);
        if let Some(image) = self.image.clone() {
            Image::new(image)
                .content_mode(ImageContentMode::Fill)
                .sampling(ImageSampling::Bicubic)
                .paint(bounds, context);
        }
        Rectangle::new()
            .color(RectangleColor::Custom(Color::rgba(0, 0, 0, 74)))
            .paint(bounds, context);
    }
}
