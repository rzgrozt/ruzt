//! Framebuffer diagnostics displayed during kernel startup.

use noto_sans_mono_bitmap::{get_raster, FontWeight, RasterHeight};
use ruzt_hal::boot::{Framebuffer, PixelFormat};
use spin::Mutex;

type Color = [u8; 3];

// Dark palette from the technical design report, section 19.
const CANVAS: Color = [0x0e, 0x10, 0x14];
const PANEL: Color = [0x16, 0x1a, 0x21];
const DIVIDER: Color = [0x1e, 0x23, 0x2c];
const TEXT: Color = [0xe8, 0xea, 0xee];
const MUTED: Color = [0xb8, 0xbd, 0xc7];
const WIND: Color = [0x8a, 0xb4, 0xff];
const BREEZE: Color = [0x7f, 0xe3, 0xc4];

const MILESTONES: [&str; 5] = [
    "Memory and heap",
    "Capability table",
    "Breakpoint returned",
    "Scheduler initialized",
    "First timer interrupt",
];

static WAITING_FOR_TIMER: Mutex<Option<BootScreen>> = Mutex::new(None);

pub(crate) fn wait_for_timer(screen: Option<BootScreen>) {
    *WAITING_FOR_TIMER.lock() = screen;
}

pub(crate) fn timer_started() {
    if let Some(mut screen) = WAITING_FOR_TIMER.lock().take() {
        screen.advance();
    }
}

pub(crate) struct BootScreen {
    fb: Framebuffer,
    left: usize,
    top: usize,
    width: usize,
    completed: usize,
}

impl BootScreen {
    pub(crate) fn new(fb: Framebuffer) -> Option<Self> {
        let width = fb.width as usize;
        let height = fb.height as usize;
        let stride = fb.stride as usize;
        let bytes = fb.bytes_per_pixel;
        let supported = match fb.pixel_format {
            PixelFormat::Rgb | PixelFormat::Bgr => bytes >= 3,
            PixelFormat::U8 => bytes == 1,
            _ => false,
        };
        if !supported
            || width > stride
            || stride.checked_mul(height)?.checked_mul(bytes)? > fb.buffer.len()
            || width < 480
            || height < 400
        {
            return None;
        }

        let content_width = (width - 64).min(960);
        let mut screen = Self {
            fb,
            left: (width - content_width) / 2,
            top: (height - 360) / 2,
            width: content_width,
            completed: 0,
        };
        screen.rect(0, 0, width, height, CANVAS);
        screen.draw();
        Some(screen)
    }

    pub(crate) fn advance(&mut self) {
        if self.completed < MILESTONES.len() {
            self.completed += 1;
            self.draw_progress();
        }
    }

    fn draw(&mut self) {
        let (x, y) = (self.left, self.top);
        // Three short strokes form the boot mark.
        for (offset, length) in [(0, 22), (8, 31), (16, 15)] {
            self.rect(x, y + 8 + offset, length, 3, WIND);
        }
        self.text(x + 47, y, "Ruzt", RasterHeight::Size32, WIND, CANVAS);
        self.text(
            x,
            y + 48,
            "x86_64 microkernel",
            RasterHeight::Size20,
            MUTED,
            CANVAS,
        );
        self.rect(x, y + 82, self.width, 1, DIVIDER);

        let wide = self.width >= 704;
        let panel_width = if wide { self.width * 3 / 5 } else { self.width };
        self.rounded_panel(x, y + 104, panel_width, 212);
        self.text(
            x + 20,
            y + 119,
            "Kernel startup",
            RasterHeight::Size20,
            TEXT,
            PANEL,
        );
        self.rect(x + 20, y + 149, panel_width - 40, 1, DIVIDER);

        if wide {
            let side = x + panel_width + 32;
            self.text(
                side,
                y + 120,
                "Privacy by design",
                RasterHeight::Size20,
                WIND,
                CANVAS,
            );
            self.text(
                side,
                y + 153,
                "Access through capabilities",
                RasterHeight::Size16,
                TEXT,
                CANVAS,
            );
            self.text(
                side,
                y + 179,
                "Telemetry off by default",
                RasterHeight::Size16,
                TEXT,
                CANVAS,
            );
            self.text(
                side,
                y + 205,
                "User controls app access",
                RasterHeight::Size16,
                MUTED,
                CANVAS,
            );
        }
        let footer = if wide {
            "Ring 0  /  User space pending"
        } else {
            "Ring 0  /  Telemetry off by default"
        };
        self.text(x, y + 340, footer, RasterHeight::Size16, MUTED, CANVAS);
        self.draw_progress();
    }

    fn draw_progress(&mut self) {
        let (x, y) = (self.left, self.top);
        let panel_width = if self.width >= 704 {
            self.width * 3 / 5
        } else {
            self.width
        };
        let track_width = panel_width - 40;
        for (index, label) in MILESTONES.iter().enumerate() {
            let row = y + 159 + index * 24;
            let (status, color) = if index < self.completed {
                ("OK", BREEZE)
            } else {
                ("WAIT", MUTED)
            };
            self.text(x + 20, row, label, RasterHeight::Size16, TEXT, PANEL);
            self.rect(x + panel_width - 60, row, 40, 16, PANEL);
            self.text(
                x + panel_width - 60,
                row,
                status,
                RasterHeight::Size16,
                color,
                PANEL,
            );
        }
        self.rect(x + 20, y + 290, track_width, 3, DIVIDER);
        self.rect(
            x + 20,
            y + 290,
            track_width * self.completed / MILESTONES.len(),
            3,
            BREEZE,
        );
    }

    fn rounded_panel(&mut self, x: usize, y: usize, width: usize, height: usize) {
        for (row, inset) in [5, 3, 2, 1, 1, 0, 0, 0].into_iter().enumerate() {
            self.rect(x + inset, y + row, width - 2 * inset, 1, PANEL);
            self.rect(x + inset, y + height - 1 - row, width - 2 * inset, 1, PANEL);
        }
        self.rect(x, y + 8, width, height - 16, PANEL);
    }

    fn text(
        &mut self,
        mut x: usize,
        y: usize,
        text: &str,
        height: RasterHeight,
        fg: Color,
        bg: Color,
    ) {
        let weight = if matches!(height, RasterHeight::Size32) {
            FontWeight::Bold
        } else {
            FontWeight::Regular
        };
        for ch in text.chars() {
            let Some(glyph) = get_raster(ch, weight, height) else {
                continue;
            };
            for (dy, row) in glyph.raster().iter().enumerate() {
                for (dx, &alpha) in row.iter().enumerate() {
                    if alpha != 0
                        && x + dx < self.fb.width as usize
                        && y + dy < self.fb.height as usize
                    {
                        let blend = |i: usize| {
                            let a = u16::from(alpha);
                            ((u16::from(fg[i]) * a + u16::from(bg[i]) * (255 - a)) / 255) as u8
                        };
                        self.pixel(x + dx, y + dy, [blend(0), blend(1), blend(2)]);
                    }
                }
            }
            x += glyph.width();
        }
    }

    fn rect(&mut self, x: usize, y: usize, width: usize, height: usize, color: Color) {
        for py in y..(y + height).min(self.fb.height as usize) {
            for px in x..(x + width).min(self.fb.width as usize) {
                self.pixel(px, py, color);
            }
        }
    }

    fn pixel(&mut self, x: usize, y: usize, [r, g, b]: Color) {
        let offset = (y * self.fb.stride as usize + x) * self.fb.bytes_per_pixel;
        match self.fb.pixel_format {
            PixelFormat::Rgb => self.fb.buffer[offset..offset + 3].copy_from_slice(&[r, g, b]),
            PixelFormat::Bgr => self.fb.buffer[offset..offset + 3].copy_from_slice(&[b, g, r]),
            PixelFormat::U8 => {
                self.fb.buffer[offset] =
                    ((u16::from(r) * 54 + u16::from(g) * 183 + u16::from(b) * 19) / 256) as u8;
            }
            _ => {}
        }
    }
}
