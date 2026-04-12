use swiftlib::fs;

const THEME_PATH: &str = "/Applications/Kagami.app/themes/default.toml";
const EMBEDDED_DEFAULT_THEME: &str = include_str!("../themes/default.toml");

#[derive(Clone, Copy)]
pub struct Theme {
    pub background_color: u32,
    pub status_bar_color: u32,
    pub window_border_color: u32,
    pub title_top_color: u32,
    pub title_bottom_color: u32,
    pub title_separator_color: u32,
    pub traffic_red: u32,
    pub traffic_yellow: u32,
    pub traffic_green: u32,
    pub traffic_ring: u32,
    pub traffic_diameter: usize,
    pub traffic_gap: usize,
    pub traffic_offset_x: usize,
    pub traffic_offset_y: usize,
    pub traffic_ring_width: usize,
    pub shadow_near_alpha: u8,
    pub shadow_far_alpha: u8,
    pub title_bar_height: usize,
    pub corner_radius: usize,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            background_color: 0x001E_1E2E,
            status_bar_color: 0xFF1A_1A24,
            window_border_color: 0xFFB9_BDCB,
            title_top_color: 0xFFE9_EAF1,
            title_bottom_color: 0xFFD7_DAE5,
            title_separator_color: 0xFFB6_BAC8,
            traffic_red: 0xFFFF_5F57,
            traffic_yellow: 0xFFFEB_C2E,
            traffic_green: 0xFF28_C840,
            traffic_ring: 0xFF95_95A2,
            traffic_diameter: 8,
            traffic_gap: 8,
            traffic_offset_x: 7,
            traffic_offset_y: 8,
            traffic_ring_width: 1,
            shadow_near_alpha: 56,
            shadow_far_alpha: 28,
            title_bar_height: 18,
            corner_radius: 4,
        }
    }
}

pub fn load_theme() -> Theme {
    let mut theme = Theme::default();
    apply_theme_text(&mut theme, EMBEDDED_DEFAULT_THEME);
    match fs::read_file_via_fs(THEME_PATH, 16 * 1024) {
        Ok(Some(bytes)) => match core::str::from_utf8(&bytes) {
            Ok(text) => {
                apply_theme_text(&mut theme, text);
                println!("[KAGAMI] theme loaded: {}", THEME_PATH);
            }
            Err(_) => {
                eprintln!("[KAGAMI] theme parse warning: invalid UTF-8, using embedded defaults");
            }
        },
        Ok(None) => {
            println!("[KAGAMI] theme file not found, using embedded defaults");
        }
        Err(errno) => {
            eprintln!(
                "[KAGAMI] theme read warning errno={} using embedded defaults",
                errno
            );
        }
    }
    theme
}

fn apply_theme_text(theme: &mut Theme, text: &str) {
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "background_color" => apply_u32(value, &mut theme.background_color),
            "status_bar_color" => apply_u32(value, &mut theme.status_bar_color),
            "window_border_color" => apply_u32(value, &mut theme.window_border_color),
            "title_top_color" => apply_u32(value, &mut theme.title_top_color),
            "title_bottom_color" => apply_u32(value, &mut theme.title_bottom_color),
            "title_separator_color" => apply_u32(value, &mut theme.title_separator_color),
            "traffic_red" => apply_u32(value, &mut theme.traffic_red),
            "traffic_yellow" => apply_u32(value, &mut theme.traffic_yellow),
            "traffic_green" => apply_u32(value, &mut theme.traffic_green),
            "traffic_ring" => apply_u32(value, &mut theme.traffic_ring),
            "traffic_diameter" => apply_usize_min(value, &mut theme.traffic_diameter, 2),
            "traffic_gap" => apply_usize(value, &mut theme.traffic_gap),
            "traffic_offset_x" => apply_usize(value, &mut theme.traffic_offset_x),
            "traffic_offset_y" => apply_usize(value, &mut theme.traffic_offset_y),
            "traffic_ring_width" => apply_usize(value, &mut theme.traffic_ring_width),
            "shadow_near_alpha" => apply_u8(value, &mut theme.shadow_near_alpha),
            "shadow_far_alpha" => apply_u8(value, &mut theme.shadow_far_alpha),
            "title_bar_height" => apply_usize(value, &mut theme.title_bar_height),
            "corner_radius" => apply_usize(value, &mut theme.corner_radius),
            _ => {}
        }
    }
}

fn apply_u32(src: &str, dst: &mut u32) {
    if let Some(v) = parse_u32(src) {
        *dst = if (v >> 24) == 0 { v | 0xFF00_0000 } else { v };
    }
}

fn apply_usize(src: &str, dst: &mut usize) {
    if let Some(v) = parse_u32(src) {
        *dst = v as usize;
    }
}

fn apply_usize_min(src: &str, dst: &mut usize, min: usize) {
    if let Some(v) = parse_u32(src) {
        *dst = (v as usize).max(min);
    }
}

fn apply_u8(src: &str, dst: &mut u8) {
    if let Some(v) = parse_u32(src) {
        *dst = v.min(255) as u8;
    }
}

fn parse_u32(src: &str) -> Option<u32> {
    let s = src.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}
