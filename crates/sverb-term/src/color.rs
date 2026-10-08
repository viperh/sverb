//! Color depth detection and 24-bit → 256-color downsampling (M0-11, SPEC §8.8).
//!
//! Shared by the UI theme (`sverb-tui::theme`, M0-11) and the terminal pane (M1-10),
//! which downsample RGB colors the same way when the outer terminal has no truecolor.
//! It lives here, not in `sverb-tui`, because `sverb-term` must not depend on the TUI
//! crate; `sverb_tui::theme::color` re-exports it.
//!
//! The target palette is xterm's: the 6×6×6 cube (16–231) and the gray ramp
//! (232–255). The 16 base colors (0–15) are never chosen for an RGB input, because
//! users re-theme them; named and indexed colors pass through unchanged. "Nearest"
//! is measured in CIELAB (ΔE*76), which matches perceived difference far better than
//! RGB distance (it keeps grays gray and doesn't drift saturated colors toward the cube's
//! dark corner).

use std::sync::OnceLock;

use ratatui_core::style::Color;
use sverb_core::config::TruecolorMode;

/// How many colors the outer terminal can show.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ColorDepth {
    /// 24-bit RGB.
    #[default]
    TrueColor,
    /// The xterm 256-color palette.
    Indexed256,
    // M1-10: terminal panes also render for 16-color and monochrome terminals.
    /// The 16 base colors only.
    Ansi16,
    /// No colors (`NO_COLOR`): attributes only.
    Mono,
}

impl ColorDepth {
    /// `ui.truecolor` plus the `COLORTERM` environment value: `on` → truecolor,
    /// `off` → 256, `auto` → truecolor only if `COLORTERM` is `truecolor` or `24bit`.
    pub fn detect(mode: TruecolorMode, colorterm: Option<&str>) -> Self {
        match mode {
            TruecolorMode::On => Self::TrueColor,
            TruecolorMode::Off => Self::Indexed256,
            TruecolorMode::Auto => match colorterm.map(str::trim) {
                Some(v)
                    if v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit") =>
                {
                    Self::TrueColor
                }
                _ => Self::Indexed256,
            },
        }
    }
}

/// `color` as the terminal at `depth` can show it. At 256 colors only [`Color::Rgb`]
/// changes; at 16 colors palette indices above 15 map to the nearest base color too
/// (M1-10); [`ColorDepth::Mono`] turns everything into [`Color::Reset`].
pub fn downsample(color: Color, depth: ColorDepth) -> Color {
    match (color, depth) {
        (_, ColorDepth::Mono) => Color::Reset,
        (Color::Rgb(r, g, b), ColorDepth::Indexed256) => Color::Indexed(rgb_to_ansi256(r, g, b)),
        (Color::Rgb(r, g, b), ColorDepth::Ansi16) => Color::Indexed(rgb_to_ansi16(r, g, b)),
        (Color::Indexed(i @ 16..), ColorDepth::Ansi16) => {
            let (r, g, b) = ansi256_to_rgb(i);
            Color::Indexed(rgb_to_ansi16(r, g, b))
        }
        (other, _) => other,
    }
}

// M1-10
/// The nearest of the 16 base colors (xterm's default values, 0–15) to an sRGB color,
/// by CIELAB distance.
pub fn rgb_to_ansi16(r: u8, g: u8, b: u8) -> u8 {
    static BASE: OnceLock<[Lab; 16]> = OnceLock::new();
    let base = BASE.get_or_init(|| {
        std::array::from_fn(|i| {
            let (r, g, b) = ansi256_to_rgb(u8::try_from(i).unwrap_or(0));
            Lab::from_rgb(r, g, b)
        })
    });
    let target = Lab::from_rgb(r, g, b);
    let mut best = (f32::INFINITY, 0u8);
    for (i, lab) in base.iter().enumerate() {
        let d = target.distance2(lab);
        if d < best.0 {
            best = (d, u8::try_from(i).unwrap_or(0));
        }
    }
    best.1
}

/// The nearest xterm palette index (16–255) to an sRGB color, by CIELAB distance.
///
/// M1-10: memoized in a lock-free, direct-mapped cache (64 Ki entries), because the terminal
/// pane maps every RGB cell of a frame. The cache only remembers exact results.
pub fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    use std::sync::atomic::{AtomicU32, Ordering};
    const SLOTS: usize = 1 << 16;
    static CACHE: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];
    let key = (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b);
    // Fibonacci hashing of the 24-bit key into 16 bits.
    let slot = (key.wrapping_mul(0x9E37_79B1) >> 16) as usize & (SLOTS - 1);
    // An entry is `key << 8 | index`; index ≥ 16, so 0 means empty.
    let entry = CACHE[slot].load(Ordering::Relaxed);
    if entry != 0 && entry >> 8 == key {
        return (entry & 0xff) as u8;
    }
    let index = rgb_to_ansi256_exhaustive(r, g, b);
    CACHE[slot].store((key << 8) | u32::from(index), Ordering::Relaxed);
    index
}

fn rgb_to_ansi256_exhaustive(r: u8, g: u8, b: u8) -> u8 {
    let target = Lab::from_rgb(r, g, b);
    let palette = palette_lab();
    let mut best = (f32::INFINITY, 16u8);
    for (i, lab) in palette.iter().enumerate() {
        let d = target.distance2(lab);
        if d < best.0 {
            // 16 + i fits: the palette has 240 entries.
            best = (d, u8::try_from(16 + i).unwrap_or(u8::MAX));
        }
    }
    best.1
}

/// The RGB value xterm uses for palette index `i` (16–255; 0–15 return xterm's defaults).
pub fn ansi256_to_rgb(i: u8) -> (u8, u8, u8) {
    const BASE: [(u8, u8, u8); 16] = [
        (0, 0, 0),
        (205, 0, 0),
        (0, 205, 0),
        (205, 205, 0),
        (0, 0, 238),
        (205, 0, 205),
        (0, 205, 205),
        (229, 229, 229),
        (127, 127, 127),
        (255, 0, 0),
        (0, 255, 0),
        (255, 255, 0),
        (92, 92, 255),
        (255, 0, 255),
        (0, 255, 255),
        (255, 255, 255),
    ];
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    match i {
        0..=15 => BASE[usize::from(i)],
        16..=231 => {
            let n = i - 16;
            (
                LEVELS[usize::from(n / 36)],
                LEVELS[usize::from((n / 6) % 6)],
                LEVELS[usize::from(n % 6)],
            )
        }
        _ => {
            let v = 8 + (i - 232) * 10;
            (v, v, v)
        }
    }
}

fn palette_lab() -> &'static [Lab; 240] {
    static PALETTE: OnceLock<[Lab; 240]> = OnceLock::new();
    PALETTE.get_or_init(|| {
        std::array::from_fn(|i| {
            let (r, g, b) = ansi256_to_rgb(u8::try_from(16 + i).unwrap_or(u8::MAX));
            Lab::from_rgb(r, g, b)
        })
    })
}

#[derive(Debug, Clone, Copy)]
struct Lab {
    l: f32,
    a: f32,
    b: f32,
}

impl Lab {
    fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        fn lin(c: u8) -> f32 {
            let c = f32::from(c) / 255.0;
            if c <= 0.040_45 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        }
        fn f(t: f32) -> f32 {
            if t > 0.008_856 {
                t.cbrt()
            } else {
                7.787 * t + 16.0 / 116.0
            }
        }
        let (r, g, b) = (lin(r), lin(g), lin(b));
        // sRGB → XYZ (D65), normalized by the white point.
        let x = (0.412_456_4 * r + 0.357_576_1 * g + 0.180_437_5 * b) / 0.950_47;
        let y = 0.212_672_9 * r + 0.715_152_2 * g + 0.072_175 * b;
        let z = (0.019_333_9 * r + 0.119_192 * g + 0.950_304_1 * b) / 1.088_83;
        let (fx, fy, fz) = (f(x), f(y), f(z));
        Self {
            l: 116.0 * fy - 16.0,
            a: 500.0 * (fx - fy),
            b: 200.0 * (fy - fz),
        }
    }

    fn distance2(&self, o: &Self) -> f32 {
        let (dl, da, db) = (self.l - o.l, self.a - o.a, self.b - o.b);
        dl * dl + da * da + db * db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // M0-11 T-17
    #[test]
    fn pure_red_maps_to_196() {
        assert_eq!(rgb_to_ansi256(0xff, 0, 0), 196);
        assert_eq!(
            downsample(Color::Rgb(0xff, 0, 0), ColorDepth::Indexed256),
            Color::Indexed(196)
        );
    }

    #[test]
    fn mid_gray_maps_to_the_gray_ramp() {
        let i = rgb_to_ansi256(0x80, 0x80, 0x80);
        assert!((232..=255).contains(&i), "{i}");
        assert_eq!(i, 244, "8 + 10·12 = 128 is exact");
    }

    #[test]
    fn base_colors_map_to_themselves() {
        let named = [
            Color::Black,
            Color::Red,
            Color::Green,
            Color::Yellow,
            Color::Blue,
            Color::Magenta,
            Color::Cyan,
            Color::Gray,
            Color::DarkGray,
            Color::LightRed,
            Color::LightGreen,
            Color::LightYellow,
            Color::LightBlue,
            Color::LightMagenta,
            Color::LightCyan,
            Color::White,
        ];
        for c in named {
            assert_eq!(downsample(c, ColorDepth::Indexed256), c);
        }
        for i in 0..=15 {
            assert_eq!(
                downsample(Color::Indexed(i), ColorDepth::Indexed256),
                Color::Indexed(i)
            );
        }
        assert_eq!(
            downsample(Color::Reset, ColorDepth::Indexed256),
            Color::Reset
        );
    }

    #[test]
    fn every_palette_color_maps_to_an_identical_entry() {
        for i in 16..=255u8 {
            let (r, g, b) = ansi256_to_rgb(i);
            let j = rgb_to_ansi256(r, g, b);
            assert_eq!(ansi256_to_rgb(j), (r, g, b), "{i} → {j}");
        }
    }

    #[test]
    fn truecolor_passes_rgb_through() {
        let c = Color::Rgb(1, 2, 3);
        assert_eq!(downsample(c, ColorDepth::TrueColor), c);
    }

    // M1-10: the cache never changes a result.
    #[test]
    fn cached_matches_exhaustive() {
        for r in (0..=255u8).step_by(15) {
            for g in (0..=255u8).step_by(17) {
                for b in (0..=255u8).step_by(5) {
                    let want = rgb_to_ansi256_exhaustive(r, g, b);
                    assert_eq!(rgb_to_ansi256(r, g, b), want);
                    assert_eq!(rgb_to_ansi256(r, g, b), want, "second (cached) lookup");
                }
            }
        }
    }

    #[test]
    fn sixteen_colors_and_mono() {
        assert_eq!(rgb_to_ansi16(0xff, 0, 0), 9);
        assert_eq!(rgb_to_ansi16(0, 0, 0), 0);
        assert_eq!(rgb_to_ansi16(0xff, 0xff, 0xff), 15);
        assert_eq!(
            downsample(Color::Indexed(196), ColorDepth::Ansi16),
            Color::Indexed(9)
        );
        assert_eq!(
            downsample(Color::Indexed(4), ColorDepth::Ansi16),
            Color::Indexed(4)
        );
        for c in [
            Color::Rgb(1, 2, 3),
            Color::Indexed(1),
            Color::Red,
            Color::Reset,
        ] {
            assert_eq!(downsample(c, ColorDepth::Mono), Color::Reset);
        }
    }

    // M0-11 T-18
    #[test]
    fn depth_detection() {
        use TruecolorMode::{Auto, Off, On};
        assert_eq!(
            ColorDepth::detect(Auto, Some("truecolor")),
            ColorDepth::TrueColor
        );
        assert_eq!(
            ColorDepth::detect(Auto, Some("24bit")),
            ColorDepth::TrueColor
        );
        assert_eq!(ColorDepth::detect(Auto, None), ColorDepth::Indexed256);
        assert_eq!(ColorDepth::detect(Auto, Some("")), ColorDepth::Indexed256);
        assert_eq!(
            ColorDepth::detect(Auto, Some("yes")),
            ColorDepth::Indexed256
        );
        assert_eq!(ColorDepth::detect(On, None), ColorDepth::TrueColor);
        assert_eq!(
            ColorDepth::detect(Off, Some("truecolor")),
            ColorDepth::Indexed256
        );
    }
}
