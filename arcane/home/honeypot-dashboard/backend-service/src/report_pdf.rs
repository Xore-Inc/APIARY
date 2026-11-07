//! PDF report composer, ported from dashboard/report_pdf.go +
//! report_pdf_brandmark.go + report_pdf_watermark.go (#1612 phase 4a),
//! now built on the vendored `printpdf` crate (#1612 follow-up) instead of
//! a hand-rolled raw-PDF-byte writer — printpdf handles object numbering,
//! xref/trailer assembly, and content-stream encoding, which removes an
//! entire class of "is this still a valid PDF" risk a hand-rolled writer
//! carries as new report elements get added over time.
//!
//! Both embedded emblems (`assets_pdf/watermark.maskdata` and
//! `assets_pdf/apiary-header-mark.maskdata`) are raw, pre-FlateDecode-
//! compressed 1-bit PDF image masks — copied byte-for-byte from the Go
//! source, same as phase 4a. printpdf's built-in image pipeline only
//! accepts 8/16-bit-per-channel raster data (no 1-bit `/ImageMask`
//! support), so both are registered as `XObject::External` — printpdf's
//! documented escape hatch for PDF content it doesn't model natively — with
//! the original PDF image-mask dictionary and the original compressed
//! stream reused verbatim. This keeps the original technique intact: one
//! shared XObject per emblem, tinted per report theme at draw time via the
//! current fill color (`SetFillColor` before `UseXobject`), exactly like
//! the hand-rolled version's `rg` before `Do`.
//!
//! Text uses printpdf's `BuiltinFont::Helvetica`/`HelveticaBold` — one of
//! the 14 standard PDF fonts every conforming reader must supply, needing
//! no embedding (this also means no Helvetica-substitute font file/license
//! question at all, simpler than embedding e.g. Liberation Sans).
//!
//! This module is pure: given an already-assembled [`ReportData`] plus a
//! theme/branding/element selection, it returns PDF bytes. It does not
//! touch Elasticsearch or HTTP — gathering `ReportData` from live telemetry
//! is reports_data.rs's job (phase 4b).

use printpdf::{
    BuiltinFont, Color, DictItem, ExtendedGraphicsState, ExternalStream, ExternalXObject, Line,
    LinePoint, Mm, Op, PaintMode, PdfDocument as PrintPdfDocument, PdfFontHandle, PdfPage as PrintPdfPage,
    PdfSaveOptions, Point as PrintPoint, Pt, Rect as PrintRect, Rgb as PrintRgb, TextItem, XObjectTransform,
};
use serde_json::Value;

const PDF_PAGE_WIDTH: f64 = 595.0;
const PDF_PAGE_HEIGHT: f64 = 842.0;

/// Bounds how much of a single event's alert/detail/command/path field
/// `event_appendix` renders — mirrors eventAppendixDetailCap (#885).
const EVENT_APPENDIX_DETAIL_CAP: usize = 2000;

/// Cuts `s` to at most `max` bytes without splitting a multi-byte UTF-8
/// character in half.
fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Clone, Copy, Debug)]
pub struct PdfRgb {
    pub r: f64,
    pub g: f64,
    pub b: f64,
}

impl PdfRgb {
    fn to_color(self) -> Color {
        Color::Rgb(PrintRgb { r: self.r as f32, g: self.g as f32, b: self.b as f32, icc_profile: None })
    }
}

/// Carries every palette decision of the rendered report, so a definition
/// can render dark (screen-style) or light (print-style) PDFs. Both
/// palettes are snapshots of the canonical Xore/theme tokens.
#[derive(Clone, Copy, Debug)]
pub struct PdfTheme {
    pub page: PdfRgb,
    pub header_band: PdfRgb,
    pub header_rule: PdfRgb,
    pub brand_text: PdfRgb,
    pub muted_text: PdfRgb,
    pub body_text: PdfRgb,
    pub accent: PdfRgb,
    pub card: PdfRgb,
    pub card_border: PdfRgb,
    pub alt_row: PdfRgb,
    pub table_header: PdfRgb,
    pub bar: PdfRgb,
    pub faint_text: PdfRgb,
    pub success: PdfRgb,
    pub warning: PdfRgb,
    pub danger: PdfRgb,
    #[allow(dead_code)] // ported 1:1 with the Go palette; not read by any element yet
    pub link: PdfRgb,
}

#[rustfmt::skip]
/// The canonical Xore/theme dark palette (theme.css :root). Kept as compact
/// one-liners (rustfmt disabled locally) so this stays a legible diff
/// against report_pdf.go's own pdfThemeDark table.
pub fn pdf_theme_dark() -> PdfTheme {
    PdfTheme {
        page:        PdfRgb { r: 0.125, g: 0.125, b: 0.122 }, // #20201f
        header_band: PdfRgb { r: 0.118, g: 0.118, b: 0.110 }, // #1e1e1c
        header_rule: PdfRgb { r: 0.204, g: 0.204, b: 0.196 }, // #343432
        brand_text:  PdfRgb { r: 0.914, g: 0.902, b: 0.875 }, // #e9e6df
        muted_text:  PdfRgb { r: 0.549, g: 0.561, b: 0.553 }, // #8c8f8d
        body_text:   PdfRgb { r: 0.740, g: 0.740, b: 0.710 },
        accent:      PdfRgb { r: 0.851, g: 0.467, b: 0.341 }, // #d97757
        card:        PdfRgb { r: 0.173, g: 0.173, b: 0.165 }, // #2c2c2a
        card_border: PdfRgb { r: 0.239, g: 0.239, b: 0.231 }, // #3d3d3b
        alt_row:     PdfRgb { r: 0.151, g: 0.151, b: 0.145 },
        table_header:PdfRgb { r: 0.220, g: 0.220, b: 0.208 }, // #383835
        bar:         PdfRgb { r: 0.427, g: 0.655, b: 0.925 }, // #6da7ec
        faint_text:  PdfRgb { r: 0.660, g: 0.670, b: 0.650 },
        success:     PdfRgb { r: 0.475, g: 0.788, b: 0.620 }, // #79c99e
        warning:     PdfRgb { r: 0.871, g: 0.702, b: 0.416 }, // #deb36a
        danger:      PdfRgb { r: 0.863, g: 0.467, b: 0.455 }, // #dc7774
        link:        PdfRgb { r: 0.427, g: 0.655, b: 0.925 }, // #6da7ec
    }
}

#[rustfmt::skip]
/// The canonical Xore/theme light palette — the print-safe token snapshot
/// from the Xore/Honeypot scan-report design (report.py).
pub fn pdf_theme_light() -> PdfTheme {
    PdfTheme {
        page:        PdfRgb { r: 0.969, g: 0.965, b: 0.949 }, // #f7f6f2
        header_band: PdfRgb { r: 0.957, g: 0.949, b: 0.929 }, // #f4f2ed
        header_rule: PdfRgb { r: 0.819, g: 0.813, b: 0.798 }, // border-strong composite
        brand_text:  PdfRgb { r: 0.184, g: 0.169, b: 0.153 }, // #2f2b27
        muted_text:  PdfRgb { r: 0.569, g: 0.541, b: 0.510 }, // #918a82
        body_text:   PdfRgb { r: 0.300, g: 0.280, b: 0.250 }, // primary/secondary blend
        accent:      PdfRgb { r: 0.780, g: 0.396, b: 0.282 }, // #c76548
        card:        PdfRgb { r: 0.984, g: 0.980, b: 0.969 }, // #fbfaf7
        card_border: PdfRgb { r: 0.908, g: 0.903, b: 0.891 }, // border-subtle composite
        alt_row:     PdfRgb { r: 0.961, g: 0.955, b: 0.937 }, // rgba(#f4f2ed, 0.65) on app-bg
        table_header:PdfRgb { r: 0.922, g: 0.914, b: 0.890 }, // #ebe9e3
        bar:         PdfRgb { r: 0.165, g: 0.471, b: 0.839 }, // #2a78d6
        faint_text:  PdfRgb { r: 0.569, g: 0.541, b: 0.510 },
        success:     PdfRgb { r: 0.247, g: 0.529, b: 0.392 }, // #3f8764
        warning:     PdfRgb { r: 0.608, g: 0.420, b: 0.145 }, // #9b6b25
        danger:      PdfRgb { r: 0.702, g: 0.310, b: 0.298 }, // #b34f4c
        link:        PdfRgb { r: 0.165, g: 0.471, b: 0.839 }, // #2a78d6
    }
}

pub fn pdf_theme_named(name: &str) -> PdfTheme {
    if name == "light" {
        pdf_theme_light()
    } else {
        pdf_theme_dark()
    }
}

impl PdfTheme {
    /// Maps a triage level to the theme's semantic color, mirroring the
    /// badge system of the canonical scan-report design.
    fn risk_color(&self, level: &str) -> PdfRgb {
        match level.to_lowercase().as_str() {
            "low" | "clean" | "minimal" => self.success,
            "medium" | "elevated" | "guard" => self.warning,
            "high" | "critical" | "severe" => self.danger,
            _ => self.brand_text,
        }
    }
}

/// The operator-configurable identity of a report: header/footer copy,
/// classification line, and author. Empty fields fall back to the
/// deployment defaults so existing output stays byte-identical.
#[derive(Clone, Debug, Default)]
pub struct PdfBranding {
    pub header_left: String,
    pub header_right: String,
    pub footer_left: String,
    pub classification: String,
    pub author: String,
}

pub fn default_pdf_branding() -> PdfBranding {
    PdfBranding {
        header_left: "APIARY".into(),
        header_right: "DEFENSIVE SECURITY OPERATIONS".into(),
        footer_left: "PRIVATE - APIARY".into(),
        classification: "PRIVATE - contains hostile-source telemetry and forensic indicators".into(),
        author: String::new(),
    }
}

impl PdfBranding {
    pub fn with_defaults(mut self) -> Self {
        let defaults = default_pdf_branding();
        if self.header_left.is_empty() {
            self.header_left = defaults.header_left;
        }
        if self.header_right.is_empty() {
            self.header_right = defaults.header_right;
        }
        if self.footer_left.is_empty() {
            self.footer_left = defaults.footer_left;
        }
        if self.classification.is_empty() {
            self.classification = defaults.classification;
        }
        self
    }
}

/// Element ID strings a report definition selects, in Reports studio order.
/// These exact string literals are also the wire values the definitions API
/// stores/accepts — keep them in sync with dashboard/reports_store.go's
/// elementCover/etc. constants.
pub const ELEMENT_COVER: &str = "cover";
pub const ELEMENT_METRICS: &str = "metrics";
pub const ELEMENT_ASSESSMENT: &str = "assessment";
pub const ELEMENT_FINDINGS: &str = "findings";
pub const ELEMENT_RECOMMENDATIONS: &str = "recommendations";
pub const ELEMENT_TOP_SENSORS: &str = "top_sensors";
pub const ELEMENT_TOP_SOURCES: &str = "top_sources";
pub const ELEMENT_TOP_SIGNATURES: &str = "top_signatures";
pub const ELEMENT_TOP_ASNS: &str = "top_asns";
pub const ELEMENT_TOP_COUNTRIES: &str = "top_countries";
pub const ELEMENT_TOP_PORTS: &str = "top_ports";
pub const ELEMENT_OPERATIONAL_ALERTS: &str = "operational_alerts";
pub const ELEMENT_EVENT_APPENDIX: &str = "event_appendix";
pub const ELEMENT_PARAMETERS: &str = "parameters";

/// One ranked key/count row (mirrors dashboard/pages_data.go's `kv`).
#[derive(Clone, Debug, Default)]
pub struct Kv {
    pub key: String,
    pub count: i64,
    #[allow(dead_code)] // ported for parity; no report element reads it yet
    pub link: String,
    /// Full value when `key` is shortened for display; falls back to `key`.
    pub title: String,
}

/// One operational dashboard alert record (dashboard-alert-state-v1 shape —
/// see src/worker.rs's Notifier::observe for the field names already in use
/// in this crate: Key/Message/Link/FirstSeen/LastSeen/Count/Acknowledged).
/// Only the fields `operational_alerts()` actually renders are kept here.
#[derive(Clone, Debug, Default)]
pub struct AlertRecord {
    pub message: String,
    pub count: i64,
    pub acknowledged: bool,
}

/// One representative event row for the evidence appendix. A local,
/// report-specific shape rather than this crate's ECS-oriented EventRow
/// (src/events.rs) — the appendix wants alert/detail/command/path as
/// distinct fallback fields, which EventRow doesn't carry.
#[derive(Clone, Debug, Default)]
pub struct ReportEventRow {
    pub time: String,
    pub sensor: String,
    pub src_ip: String,
    pub port: String,
    pub alert: String,
    pub detail: String,
    pub command: String,
    pub path: String,
}

#[derive(Clone, Debug, Default)]
pub struct ReportSummary {
    pub events: i64,
    pub alerts: i64,
    pub high_severity: i64,
    pub unique_sources: i64,
    pub logins: i64,
    pub payloads: i64,
    pub sessions: i64,
    pub commands: i64,
    pub sensors: i64,
    pub open_operational: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub risk_score: i64,
    pub risk_level: String,
}

#[derive(Clone, Debug, Default)]
pub struct ReportData {
    pub generated: chrono::DateTime<chrono::Utc>,
    pub title: String,
    pub scope: String,
    pub filters: Vec<String>,
    pub summary: ReportSummary,
    pub events: Vec<ReportEventRow>,
    pub top_sensors: Vec<Kv>,
    pub top_sources: Vec<Kv>,
    pub top_signatures: Vec<Kv>,
    pub top_asns: Vec<Kv>,
    pub top_countries: Vec<Kv>,
    pub top_ports: Vec<Kv>,
    pub operational_alerts: Vec<AlertRecord>,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

// -- watermark / header-mark assets (report_pdf_watermark.go / report_pdf_brandmark.go) --

const WATERMARK_IMAGE_WIDTH: u32 = 360;
const WATERMARK_IMAGE_HEIGHT: u32 = 360;
/// Intentionally very low — this sits behind every other element on the
/// page, so it must never compete with the report's own text.
const WATERMARK_OPACITY: f32 = 0.05;
/// On-page footprint in points, centered, larger than the printable column
/// so it reads as a background mark rather than a bounded illustration.
const WATERMARK_SIZE: f64 = 380.0;

const PDF_HEADER_MARK_WIDTH: u32 = 64;
const PDF_HEADER_MARK_HEIGHT: u32 = 64;
const PDF_HEADER_MARK_SIZE: f64 = 22.0;

/// The detailed APIARY emblem, a transparent 360x360 one-bit image mask.
/// Its color comes from the active report theme, applied via the current
/// fill color at draw time (see `draw_watermark`).
static WATERMARK_MASK_DATA: &[u8] = include_bytes!("../assets_pdf/watermark.maskdata");

/// The compact APIARY emblem, a 64x64 one-bit image mask for the header band.
static PDF_HEADER_MARK_DATA: &[u8] = include_bytes!("../assets_pdf/apiary-header-mark.maskdata");

/// Builds the PDF `/ImageMask` dictionary printpdf's own image pipeline
/// can't produce (it has no 1-bit stencil-mask path) — registered as an
/// `XObject::External` with the original, already-FlateDecode-compressed
/// mask bytes reused verbatim as the stream content.
fn image_mask_xobject(width: u32, height: u32, data: &'static [u8]) -> ExternalXObject {
    let mut dict = std::collections::BTreeMap::new();
    dict.insert("Type".to_string(), DictItem::Name(b"XObject".to_vec()));
    dict.insert("Subtype".to_string(), DictItem::Name(b"Image".to_vec()));
    dict.insert("Width".to_string(), DictItem::Int(width as i64));
    dict.insert("Height".to_string(), DictItem::Int(height as i64));
    dict.insert("ImageMask".to_string(), DictItem::Bool(true));
    dict.insert("BitsPerComponent".to_string(), DictItem::Int(1));
    dict.insert("Decode".to_string(), DictItem::Array(vec![DictItem::Int(1), DictItem::Int(0)]));
    dict.insert("Filter".to_string(), DictItem::Name(b"FlateDecode".to_vec()));
    ExternalXObject {
        stream: ExternalStream { dict, content: data.to_vec(), compress: false },
        width: Some(printpdf::Px(width as usize)),
        height: Some(printpdf::Px(height as usize)),
        dpi: None,
    }
}

/// A transform that places a `width_px`×`height_px` image at an exact
/// `target_pt`×`target_pt` on-page size, lower-left corner at (x, y).
/// printpdf's `XObjectTransform` scales an image by pixel-count at a given
/// DPI (`px * 72 / dpi` points) rather than accepting a target size
/// directly, so the DPI here is solved backwards from the target size.
fn exact_size_transform(width_px: u32, target_pt: f64, x: f64, y: f64) -> XObjectTransform {
    let dpi = width_px as f32 * 72.0 / target_pt as f32;
    XObjectTransform {
        translate_x: Some(Pt(x as f32)),
        translate_y: Some(Pt(y as f32)),
        rotate: None,
        scale_x: None,
        scale_y: None,
        dpi: Some(dpi),
        no_auto_scale: false,
    }
}

struct PdfReportWriter {
    doc: PrintPdfDocument,
    watermark_xobj: printpdf::XObjectId,
    watermark_gs: printpdf::ExtendedGraphicsStateId,
    header_mark_xobj: printpdf::XObjectId,
    theme: PdfTheme,
    branding: PdfBranding,
    footer_left: String,
    pages: Vec<Vec<Op>>,
    ops: Vec<Op>,
    page_started: bool,
    y: f64,
    /// Layout probe (#3524): ops on the page when the current element began,
    /// and whether its first page break left that page untouched.
    watch_ops: usize,
    watch_start: (usize, f64),
    break_untouched: Option<bool>,
}

impl PdfReportWriter {
    fn new(theme: PdfTheme, branding: PdfBranding) -> Self {
        let mut doc = PrintPdfDocument::new("APIARY Report");
        let watermark_xobj =
            doc.add_xobject(&image_mask_xobject(WATERMARK_IMAGE_WIDTH, WATERMARK_IMAGE_HEIGHT, WATERMARK_MASK_DATA));
        let header_mark_xobj = doc.add_xobject(&image_mask_xobject(
            PDF_HEADER_MARK_WIDTH,
            PDF_HEADER_MARK_HEIGHT,
            PDF_HEADER_MARK_DATA,
        ));
        let watermark_gs =
            doc.add_graphics_state(ExtendedGraphicsState::default().with_current_fill_alpha(WATERMARK_OPACITY));
        let footer_left = branding.footer_left.clone();
        PdfReportWriter {
            doc,
            watermark_xobj,
            watermark_gs,
            header_mark_xobj,
            theme,
            branding,
            footer_left,
            pages: Vec::new(),
            ops: Vec::new(),
            page_started: false,
            y: 0.0,
            watch_ops: 0,
            watch_start: (0, 0.0),
            break_untouched: None,
        }
    }

    fn begin_element(&mut self) {
        self.watch_ops = self.ops.len();
        self.watch_start = (self.page_count(), self.y);
        self.break_untouched = None;
    }

    fn push(&mut self, op: Op) {
        self.ops.push(op);
    }

    fn new_page(&mut self) {
        if self.break_untouched.is_none() {
            self.break_untouched = Some(self.ops.len() == self.watch_ops);
        }
        if self.page_started {
            self.pages.push(std::mem::take(&mut self.ops));
        }
        self.page_started = true;
        self.y = PDF_PAGE_HEIGHT - 68.0;
        let t = self.theme;
        self.rect(0.0, 0.0, PDF_PAGE_WIDTH, PDF_PAGE_HEIGHT, t.page);
        // Drawn immediately after the solid background and before anything
        // else -- content streams paint in the order they're written, so
        // everything below ends up visually on top of this, never the
        // reverse.
        self.draw_watermark();
        self.rect(0.0, PDF_PAGE_HEIGHT - 48.0, PDF_PAGE_WIDTH, 48.0, t.header_band);
        self.line(0.0, PDF_PAGE_HEIGHT - 48.0, PDF_PAGE_WIDTH, PDF_PAGE_HEIGHT - 48.0, t.header_rule);
        self.draw_header_mark();
        let header_left = self.branding.header_left.clone();
        let header_right = self.branding.header_right.clone();
        self.text(62.0, PDF_PAGE_HEIGHT - 29.0, 12.0, true, t.brand_text, &header_left);
        self.text(PDF_PAGE_WIDTH - 188.0, PDF_PAGE_HEIGHT - 29.0, 7.5, false, t.muted_text, &header_right);
    }

    fn ensure(&mut self, height: f64) {
        if self.y - height < 55.0 {
            self.new_page();
        }
    }

    fn cover(&mut self, data: &ReportData) {
        let t = self.theme;
        self.display_text(32.0, self.y, 25.0, t.brand_text, &data.title);
        self.y -= 29.0;
        self.text(32.0, self.y, 9.0, true, t.accent, "REPORT SCOPE");
        self.y -= 17.0;
        for line in wrap_pdf_text(&data.scope, 88) {
            self.text(32.0, self.y, 10.0, false, t.brand_text, &line);
            self.y -= 14.0;
        }
        self.y -= 4.0;
        if !self.branding.author.is_empty() {
            let line = format!("Author: {}", self.branding.author);
            self.text(32.0, self.y, 8.5, false, t.muted_text, &line);
            self.y -= 13.0;
        }
        let generated = format!("Generated: {}", data.generated.format("%Y-%m-%d %H:%M:%S UTC"));
        self.text(32.0, self.y, 8.5, false, t.muted_text, &generated);
        self.y -= 13.0;
        // #1567: "not available to not available" read as a copy bug --
        // when neither bound is known, say so once.
        let window = if !data.summary.first_seen.is_empty() || !data.summary.last_seen.is_empty() {
            format!(
                "{} to {}",
                first_non_empty(&[&data.summary.first_seen], "unknown"),
                first_non_empty(&[&data.summary.last_seen], "unknown"),
            )
        } else {
            "not available".to_string()
        };
        let observed = format!("Observed window: {window}");
        self.text(32.0, self.y, 8.5, false, t.muted_text, &observed);
        self.y -= 13.0;
        let classification = format!("Classification: {}", self.branding.classification);
        self.text(32.0, self.y, 8.5, false, t.accent, &classification);
        self.y -= 28.0;
    }

    fn section(&mut self, title: &str) {
        let t = self.theme;
        // Keep a section heading with at least one useful row or paragraph
        // beneath it.
        self.ensure(70.0);
        self.y -= 8.0;
        self.rect(32.0, self.y - 5.0, 4.0, 18.0, t.accent);
        self.display_text(44.0, self.y, 15.0, t.brand_text, title);
        self.y -= 25.0;
        self.line(32.0, self.y + 7.0, PDF_PAGE_WIDTH - 32.0, self.y + 7.0, t.header_rule);
    }

    fn paragraph(&mut self, value: &str) {
        let t = self.theme;
        let lines = wrap_pdf_text(value, 100);
        self.ensure(lines.len() as f64 * 13.0 + 10.0);
        for line in &lines {
            self.text(36.0, self.y, 9.0, false, t.body_text, line);
            self.y -= 13.0;
        }
        self.y -= 6.0;
    }

    fn metric_grid(&mut self, summary: &ReportSummary) {
        let t = self.theme;
        let risk_color = t.risk_color(&summary.risk_level);
        let metrics: [(&str, String, PdfRgb); 8] = [
            ("Matching events", summary.events.to_string(), t.brand_text),
            ("Unique sources", summary.unique_sources.to_string(), t.brand_text),
            ("Alert records", summary.alerts.to_string(), t.brand_text),
            ("High severity", summary.high_severity.to_string(), t.brand_text),
            ("Login attempts", summary.logins.to_string(), t.brand_text),
            ("Payload observations", summary.payloads.to_string(), t.brand_text),
            ("Sessions", summary.sessions.to_string(), t.brand_text),
            ("Risk rating", format!("{} - {}", summary.risk_score, summary.risk_level.to_uppercase()), risk_color),
        ];
        let (cell_w, cell_h) = (126.5, 54.0);
        for (i, (label, value, color)) in metrics.iter().enumerate() {
            if i % 4 == 0 {
                self.ensure(cell_h + 8.0);
            }
            let x = 32.0 + (i % 4) as f64 * (cell_w + 7.0);
            let y = self.y - cell_h;
            self.rect(x, y, cell_w, cell_h, t.card);
            self.stroke_rect(x, y, cell_w, cell_h, t.card_border);
            self.text(x + 10.0, y + 31.0, 15.0, true, *color, value);
            self.text(x + 10.0, y + 14.0, 7.5, true, t.muted_text, &label.to_uppercase());
            if i % 4 == 3 {
                self.y -= cell_h + 8.0;
            }
        }
        self.y -= 6.0;
    }

    fn bullets(&mut self, title: &str, items: &[String]) {
        let t = self.theme;
        if items.is_empty() {
            return;
        }
        self.ensure(28.0);
        self.text(36.0, self.y, 10.5, true, t.brand_text, title);
        self.y -= 17.0;
        for item in items {
            let lines = wrap_pdf_text(item, 92);
            self.ensure(lines.len() as f64 * 12.0 + 5.0);
            self.text(39.0, self.y, 9.0, true, t.accent, "-");
            for line in &lines {
                self.text(50.0, self.y, 8.7, false, t.body_text, line);
                self.y -= 12.0;
            }
            self.y -= 3.0;
        }
        self.y -= 3.0;
    }

    fn top_table(&mut self, title: &str, label: &str, rows: &[Kv]) {
        let t = self.theme;
        if rows.is_empty() {
            return;
        }
        let first_label = first_non_empty(&[&rows[0].title, &rows[0].key], "");
        let first_lines = wrap_pdf_text(first_label, 78);
        let first_height = (first_lines.len() as f64 * 11.0 + 9.0).max(25.0);
        self.ensure(33.0 + 24.0 + first_height);
        self.section(title);
        let max_count = rows[0].count.max(1);
        self.table_header(label, "Events");
        for (index, row) in rows.iter().enumerate() {
            let row_label = first_non_empty(&[&row.title, &row.key], "");
            let lines = wrap_pdf_text(row_label, 78);
            let height = (lines.len() as f64 * 11.0 + 9.0).max(25.0);
            self.ensure(height);
            if index % 2 == 1 {
                self.rect(32.0, self.y - height + 5.0, PDF_PAGE_WIDTH - 64.0, height, t.alt_row);
            }
            let bar_width = 115.0 * row.count as f64 / max_count as f64;
            self.rect(PDF_PAGE_WIDTH - 184.0, self.y - 12.0, bar_width, 5.0, t.bar);
            let line_count = lines.len();
            for line in &lines {
                self.text(38.0, self.y - 7.0, 8.3, false, t.body_text, line);
                self.y -= 11.0;
            }
            let count_str = row.count.to_string();
            self.text(PDF_PAGE_WIDTH - 55.0, self.y + line_count as f64 * 11.0 - 7.0, 8.5, true, t.brand_text, &count_str);
            self.y -= 8.0;
        }
        self.y -= 4.0;
    }

    fn table_header(&mut self, left: &str, right: &str) {
        let t = self.theme;
        self.ensure(23.0);
        self.rect(32.0, self.y - 17.0, PDF_PAGE_WIDTH - 64.0, 22.0, t.table_header);
        let left = left.to_uppercase();
        let right = right.to_uppercase();
        self.text(38.0, self.y - 10.0, 8.0, true, t.brand_text, &left);
        self.text(PDF_PAGE_WIDTH - 68.0, self.y - 10.0, 8.0, true, t.brand_text, &right);
        self.y -= 24.0;
    }

    fn operational_alerts(&mut self, alerts: &[AlertRecord]) {
        let t = self.theme;
        if alerts.is_empty() {
            return;
        }
        let first_lines = wrap_pdf_text(&format!("OPEN - {}", alerts[0].message), 82);
        let first_height = (first_lines.len() as f64 * 11.0 + 9.0).max(25.0);
        self.ensure(33.0 + 24.0 + first_height);
        self.section("Operational dashboard alerts");
        self.table_header("State / message", "Count");
        for (index, alert) in alerts.iter().take(40).enumerate() {
            let state = if alert.acknowledged { "ACKNOWLEDGED" } else { "OPEN" };
            let lines = wrap_pdf_text(&format!("{state} - {}", alert.message), 82);
            let height = (lines.len() as f64 * 11.0 + 9.0).max(25.0);
            self.ensure(height);
            if index % 2 == 1 {
                self.rect(32.0, self.y - height + 5.0, PDF_PAGE_WIDTH - 64.0, height, t.alt_row);
            }
            let line_count = lines.len();
            for line in &lines {
                self.text(38.0, self.y - 7.0, 8.2, false, t.body_text, line);
                self.y -= 11.0;
            }
            let count_str = alert.count.to_string();
            self.text(PDF_PAGE_WIDTH - 55.0, self.y + line_count as f64 * 11.0 - 7.0, 8.5, true, t.brand_text, &count_str);
            self.y -= 8.0;
        }
    }

    fn event_appendix(&mut self, events: &[ReportEventRow], appendix_limit: i64) {
        let t = self.theme;
        self.section("Evidence appendix - representative events");
        if events.is_empty() || appendix_limit <= 0 {
            self.paragraph("No matching event records were available.");
            return;
        }
        let limit = (appendix_limit as usize).min(events.len());
        let summary =
            format!("Showing the newest {limit} of {} matching records. Use the dashboard Event Explorer or Elasticsearch export for the complete machine-readable dataset.", events.len());
        self.paragraph(&summary);
        for (index, event) in events[..limit].iter().enumerate() {
            let mut detail = first_non_empty(&[&event.alert, &event.detail, &event.command, &event.path], "event").to_string();
            if detail.len() > EVENT_APPENDIX_DETAIL_CAP {
                detail = format!("{} …(truncated)", truncate_utf8(&detail, EVENT_APPENDIX_DETAIL_CAP));
            }
            let head = [event.time.as_str(), event.sensor.as_str(), event.src_ip.as_str(), event.port.as_str()].join("  |  ");
            let lines = wrap_pdf_text(&detail, 88);
            let height = 25.0 + lines.len() as f64 * 10.0;
            self.ensure(height);
            if index % 2 == 0 {
                self.rect(32.0, self.y - height + 7.0, PDF_PAGE_WIDTH - 64.0, height, t.alt_row);
            }
            self.text(38.0, self.y - 6.0, 7.8, true, t.brand_text, &head);
            self.y -= 14.0;
            for line in &lines {
                self.text(38.0, self.y - 5.0, 7.8, false, t.faint_text, line);
                self.y -= 10.0;
            }
            self.y -= 6.0;
        }
    }

    fn parameters(&mut self, data: &ReportData) {
        self.section("Report parameters and limitations");
        let filters =
            if data.filters.is_empty() { "none - executive overview".to_string() } else { data.filters.join("; ") };
        self.paragraph(&format!("Applied filters: {filters}"));
        self.paragraph("Data source: normalized in-memory dashboard telemetry and persistent operational alert state. Counts reflect the dashboard observation window, not an assertion that every historical Elasticsearch document is present.");
        self.paragraph("Limitations: honeypot interactions show hostile or suspicious activity directed at decoy services. GeoIP, ASN, provider, behavioral mappings, and risk scoring are contextual triage aids. They do not prove attribution, physical location, successful compromise, or impact to production systems.");
    }

    // -- artifact-report primitives (sandbox_pdf.go/ghidra_pdf.go/
    // payload_pdf.go's pdfReportWriter.sandboxMetricGrid/sandboxKeyValues —
    // both genuinely shared across all three Go renderers despite the
    // "sandbox" name, so shared here too rather than duplicated per
    // artifact type. `metric_grid` above stays untouched: it's specific to
    // the generic telemetry report's fixed 8-metric ReportSummary shape.)

    /// A variable-length grid of label/value tiles, 4 per row, shrinking
    /// the value's font (then wrapping to two lines) rather than ever
    /// truncating it — a print artifact has no hover/expand affordance to
    /// recover a cut-off value.
    fn variable_metric_grid(&mut self, metrics: &[(&str, String)]) {
        let t = self.theme;
        let (cell_w, cell_h) = (126.5, 54.0);
        let count = metrics.len();
        for (index, (label, value)) in metrics.iter().enumerate() {
            if index % 4 == 0 {
                self.ensure(cell_h + 8.0);
            }
            let x = 32.0 + (index % 4) as f64 * (cell_w + 7.0);
            let y = self.y - cell_h;
            self.rect(x, y, cell_w, cell_h, t.card);
            self.stroke_rect(x, y, cell_w, cell_h, t.card_border);
            let value = if value.is_empty() { "not available" } else { value.as_str() };
            match value.len() {
                0..=22 => self.text(x + 10.0, y + 31.0, 13.0, true, t.brand_text, value),
                23..=30 => self.text(x + 10.0, y + 31.0, 10.0, true, t.brand_text, value),
                _ => {
                    let lines = wrap_pdf_text(value, 30);
                    self.text(x + 10.0, y + 35.0, 8.5, true, t.brand_text, &lines[0]);
                    if let Some(second) = lines.get(1) {
                        self.text(x + 10.0, y + 25.0, 8.5, true, t.brand_text, second);
                    }
                }
            }
            self.text(x + 10.0, y + 14.0, 7.5, true, t.muted_text, &label.to_uppercase());
            if index % 4 == 3 || index == count - 1 {
                self.y -= cell_h + 8.0;
            }
        }
        self.y -= 6.0;
    }

    /// A titled section of label/value rows, alternating row background,
    /// silently skipping any row whose value is empty (Go's
    /// sandboxKeyValues: a field the artifact never populated is omitted,
    /// not shown blank).
    fn key_values(&mut self, title: &str, rows: &[(&str, String)]) {
        let t = self.theme;
        self.section(title);
        for (index, (label, value)) in rows.iter().filter(|(_, v)| !v.trim().is_empty()).enumerate() {
            let lines = wrap_pdf_text(value, 70);
            let height = (lines.len() as f64 * 11.0 + 10.0).max(24.0);
            self.ensure(height);
            if index % 2 == 0 {
                self.rect(32.0, self.y - height + 5.0, PDF_PAGE_WIDTH - 64.0, height, t.alt_row);
            }
            self.text(38.0, self.y - 7.0, 8.0, true, t.muted_text, &label.to_uppercase());
            for (line_index, line) in lines.iter().enumerate() {
                self.text(176.0, self.y - 7.0 - line_index as f64 * 11.0, 8.2, false, t.brand_text, line);
            }
            self.y -= height;
        }
        self.y -= 5.0;
    }

    /// Added/removed entries between two snapshots — sandbox_pdf.go's
    /// sandboxDifference, ported for the one artifact-report caller that
    /// has this shape (the sockets before/after comparison; see
    /// render_sandbox_pdf's own comment on why there's no process-diff
    /// equivalent here).
    fn difference(&mut self, title: &str, note: &str, added: &[String], removed: &[String]) {
        self.section(title);
        self.paragraph(note);
        if added.is_empty() && removed.is_empty() {
            self.paragraph("No added or removed entries were observed.");
            return;
        }
        self.bullets(&format!("Added ({})", added.len()), &limit_strings(added, 100));
        self.bullets(&format!("Removed ({})", removed.len()), &limit_strings(removed, 100));
    }

    // -- drawing primitives (report_pdf.go's pdfReportWriter.text/rect/line/…) --

    fn text(&mut self, x: f64, y: f64, size: f64, bold: bool, color: PdfRgb, value: &str) {
        let font = PdfFontHandle::Builtin(if bold { BuiltinFont::HelveticaBold } else { BuiltinFont::Helvetica });
        self.push(Op::StartTextSection);
        self.push(Op::SetFont { font, size: Pt(size as f32) });
        self.push(Op::SetFillColor { col: color.to_color() });
        self.push(Op::SetTextCursor { pos: PrintPoint { x: Pt(x as f32), y: Pt(y as f32) } });
        self.push(Op::ShowText { items: vec![TextItem::Text(value.to_string())] });
        self.push(Op::EndTextSection);
    }

    /// The original's third "display" font role — Go reused Helvetica-Bold
    /// for both bold body text and this larger heading role (see
    /// report_pdf.go's own "Portable sans display fallback" comment), so
    /// this is HelveticaBold at a larger size, same as the source.
    fn display_text(&mut self, x: f64, y: f64, size: f64, color: PdfRgb, value: &str) {
        self.push(Op::StartTextSection);
        self.push(Op::SetFont { font: PdfFontHandle::Builtin(BuiltinFont::HelveticaBold), size: Pt(size as f32) });
        self.push(Op::SetFillColor { col: color.to_color() });
        self.push(Op::SetTextCursor { pos: PrintPoint { x: Pt(x as f32), y: Pt(y as f32) } });
        self.push(Op::ShowText { items: vec![TextItem::Text(value.to_string())] });
        self.push(Op::EndTextSection);
    }

    fn rect(&mut self, x: f64, y: f64, width: f64, height: f64, color: PdfRgb) {
        self.push(Op::SetFillColor { col: color.to_color() });
        self.push(Op::DrawRectangle {
            rectangle: PrintRect {
                x: Pt(x as f32),
                y: Pt(y as f32),
                width: Pt(width as f32),
                height: Pt(height as f32),
                mode: Some(PaintMode::Fill),
                winding_order: None,
            },
        });
    }

    fn stroke_rect(&mut self, x: f64, y: f64, width: f64, height: f64, color: PdfRgb) {
        self.push(Op::SetOutlineColor { col: color.to_color() });
        self.push(Op::SetOutlineThickness { pt: Pt(0.6) });
        self.push(Op::DrawRectangle {
            rectangle: PrintRect {
                x: Pt(x as f32),
                y: Pt(y as f32),
                width: Pt(width as f32),
                height: Pt(height as f32),
                mode: Some(PaintMode::Stroke),
                winding_order: None,
            },
        });
    }

    fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, color: PdfRgb) {
        self.push(Op::SetOutlineColor { col: color.to_color() });
        self.push(Op::SetOutlineThickness { pt: Pt(0.6) });
        self.push(Op::DrawLine {
            line: Line {
                points: vec![
                    LinePoint { p: PrintPoint { x: Pt(x1 as f32), y: Pt(y1 as f32) }, bezier: false },
                    LinePoint { p: PrintPoint { x: Pt(x2 as f32), y: Pt(y2 as f32) }, bezier: false },
                ],
                is_closed: false,
            },
        });
    }

    // -- watermark / header-mark (report_pdf_watermark.go / report_pdf_brandmark.go) --

    fn draw_watermark(&mut self) {
        let x = (PDF_PAGE_WIDTH - WATERMARK_SIZE) / 2.0;
        let y = (PDF_PAGE_HEIGHT - WATERMARK_SIZE) / 2.0;
        let t = self.theme;
        // Outer save/restore brackets the low-opacity graphics state so it
        // never leaks into anything drawn after the watermark — UseXobject
        // already brackets its own inner q/Do/Q for the placement matrix.
        self.push(Op::SaveGraphicsState);
        self.push(Op::LoadGraphicsState { gs: self.watermark_gs.clone() });
        self.push(Op::SetFillColor { col: t.accent.to_color() });
        self.push(Op::UseXobject {
            id: self.watermark_xobj.clone(),
            transform: exact_size_transform(WATERMARK_IMAGE_WIDTH, WATERMARK_SIZE, x, y),
        });
        self.push(Op::RestoreGraphicsState);
    }

    fn draw_header_mark(&mut self) {
        let t = self.theme;
        let y = PDF_PAGE_HEIGHT - 35.0;
        self.push(Op::SetFillColor { col: t.accent.to_color() });
        self.push(Op::UseXobject {
            id: self.header_mark_xobj.clone(),
            transform: exact_size_transform(PDF_HEADER_MARK_WIDTH, PDF_HEADER_MARK_SIZE, 32.0, y),
        });
    }

    /// Finishes the current page, appends the page-number footer to every
    /// page now that the total count is known, and serializes the document.
    /// Pages laid out so far, counting the one being drawn.
    fn page_count(&self) -> usize {
        self.pages.len() + usize::from(self.page_started)
    }

    fn finish(mut self) -> Vec<u8> {
        if self.page_started {
            self.pages.push(std::mem::take(&mut self.ops));
        }
        let muted = self.theme.muted_text;
        let footer_left =
            if self.footer_left.is_empty() { default_pdf_branding().footer_left } else { self.footer_left.clone() };
        let page_count = self.pages.len();
        let mut pdf_pages = Vec::with_capacity(page_count);
        for (index, mut ops) in self.pages.into_iter().enumerate() {
            ops.push(Op::StartTextSection);
            ops.push(Op::SetFont { font: PdfFontHandle::Builtin(BuiltinFont::Helvetica), size: Pt(7.5) });
            ops.push(Op::SetFillColor { col: muted.to_color() });
            ops.push(Op::SetTextCursor { pos: PrintPoint { x: Pt(32.0), y: Pt(27.0) } });
            ops.push(Op::ShowText { items: vec![TextItem::Text(footer_left.clone())] });
            ops.push(Op::EndTextSection);
            ops.push(Op::StartTextSection);
            ops.push(Op::SetFont { font: PdfFontHandle::Builtin(BuiltinFont::Helvetica), size: Pt(7.5) });
            ops.push(Op::SetFillColor { col: muted.to_color() });
            ops.push(Op::SetTextCursor { pos: PrintPoint { x: Pt(516.0), y: Pt(27.0) } });
            ops.push(Op::ShowText { items: vec![TextItem::Text(format!("Page {} of {page_count}", index + 1))] });
            ops.push(Op::EndTextSection);
            pdf_pages.push(PrintPdfPage::new(Mm::from(Pt(PDF_PAGE_WIDTH as f32)), Mm::from(Pt(PDF_PAGE_HEIGHT as f32)), ops));
        }
        self.doc.with_pages(pdf_pages);
        let mut warnings = Vec::new();
        self.doc.save(&PdfSaveOptions::default(), &mut warnings)
    }
}

fn first_non_empty<'a>(values: &[&'a str], fallback: &'a str) -> &'a str {
    values.iter().copied().find(|v| !v.is_empty()).unwrap_or(fallback)
}

/// Caps a bounded-report list at `limit` entries, noting the omission
/// rather than silently dropping it — ported from sandbox_pdf.go's
/// limitStrings.
fn limit_strings(values: &[String], limit: usize) -> Vec<String> {
    if values.len() <= limit {
        return values.to_vec();
    }
    let mut out = values[..limit].to_vec();
    out.push(format!("... {} additional entries omitted from this bounded report", values.len() - limit));
    out
}

fn wrap_pdf_text(value: &str, width: usize) -> Vec<String> {
    let joined = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut remaining = joined.as_str();
    while remaining.len() > width {
        // Mirrors Go's strings.LastIndex(value[:width+1], " "): search for
        // the last space within the first width+1 bytes (byte-indexed, like
        // the Go source — this text is plain ASCII/UTF-8 prose, and printpdf
        // (unlike the old hand-rolled writer) needs no separate PDF-string
        // escaping pass, so byte and char boundaries coincide here too).
        let probe_end = (width + 1).min(remaining.len());
        let probe = &remaining[..probe_end];
        let mut cut = probe.rfind(' ').unwrap_or(usize::MAX);
        if cut == usize::MAX || cut < width / 2 {
            cut = width.min(remaining.len());
        }
        lines.push(remaining[..cut].trim().to_string());
        remaining = remaining[cut..].trim_start();
    }
    if !remaining.is_empty() {
        lines.push(remaining.to_string());
    }
    lines
}

/// Keeps the designer's ordering but anchors the cover at the start and the
/// parameters section at the end when selected.
fn normalize_report_elements(elements: &[String]) -> Vec<String> {
    let mut body = Vec::new();
    let (mut has_cover, mut has_parameters) = (false, false);
    for element in elements {
        match element.as_str() {
            ELEMENT_COVER => has_cover = true,
            ELEMENT_PARAMETERS => has_parameters = true,
            _ => body.push(element.clone()),
        }
    }
    let mut out = Vec::new();
    if has_cover {
        out.push(ELEMENT_COVER.to_string());
    }
    out.extend(body);
    if has_parameters {
        out.push(ELEMENT_PARAMETERS.to_string());
    }
    out
}

/// Renders a report from an already-assembled dataset: the public entry
/// point every caller (Reports studio definitions, the one-click
/// payload/sandbox/ghidra reports once those land) drives the writer
/// through, exactly the sections the operator selected.
pub fn render_report_pdf(
    data: &ReportData,
    theme: PdfTheme,
    branding: PdfBranding,
    elements: &[String],
    appendix_limit: i64,
) -> Vec<u8> {
    let mut writer = PdfReportWriter::new(theme, branding.with_defaults());
    draw_report_elements(&mut writer, data, elements, appendix_limit, |_, _| {});
    writer.finish()
}

/// Where one selected element landed in the laid-out document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElementPlacement {
    pub id: String,
    /// Pages the element touches; 0 when it draws nothing (an empty table
    /// is skipped by the renderer).
    pub pages: usize,
}

/// The page count and per-element placement the PDF for this dataset would
/// have (#3524). Runs the very same drawing code as `render_report_pdf`
/// (`draw_report_elements`), then stops before serialising, so a preview's
/// page numbers cannot drift from the generated document's.
pub fn report_layout(
    data: &ReportData,
    theme: PdfTheme,
    branding: PdfBranding,
    elements: &[String],
    appendix_limit: i64,
) -> (usize, Vec<ElementPlacement>) {
    let mut writer = PdfReportWriter::new(theme, branding.with_defaults());
    let mut placements = Vec::new();
    draw_report_elements(&mut writer, data, elements, appendix_limit, |id, w| {
        let before = w.watch_start;
        let after = (w.page_count(), w.y);
        let pages = if after == before {
            0
        } else {
            // Pages from where the element began to where it ended; when it
            // broke to a fresh page before drawing anything, the page it
            // started on is not one of its own.
            let started_on_fresh_page = w.break_untouched == Some(true);
            (after.0 - before.0 + 1).saturating_sub(usize::from(started_on_fresh_page)).max(1)
        };
        placements.push(ElementPlacement { id: id.to_string(), pages });
    });
    (writer.page_count(), placements)
}

/// The one element loop both the PDF and its layout run through.
/// `after_element` is called after each element with its id.
fn draw_report_elements(
    writer: &mut PdfReportWriter,
    data: &ReportData,
    elements: &[String],
    appendix_limit: i64,
    mut after_element: impl FnMut(&str, &PdfReportWriter),
) {
    writer.new_page();
    for element in normalize_report_elements(elements) {
        writer.begin_element();
        match element.as_str() {
            ELEMENT_COVER => writer.cover(data),
            ELEMENT_METRICS => {
                writer.section("Executive summary");
                writer.metric_grid(&data.summary);
            }
            ELEMENT_ASSESSMENT => {
                writer.section("Assessment");
                let text = format!(
                    "Overall triage score: {}/100 ({}). This deterministic score prioritizes alert volume, severity, payload observations, sensor spread, commands, and open operational alerts; it is not an attribution or compromise verdict.",
                    data.summary.risk_score,
                    data.summary.risk_level.to_uppercase()
                );
                writer.paragraph(&text);
            }
            ELEMENT_FINDINGS => writer.bullets("Key findings", &data.findings),
            ELEMENT_RECOMMENDATIONS => writer.bullets("Recommended actions", &data.recommendations),
            ELEMENT_TOP_SENSORS => writer.top_table("Top sensors", "Sensor", &data.top_sensors),
            ELEMENT_TOP_SOURCES => writer.top_table("Top source addresses", "Source IP", &data.top_sources),
            ELEMENT_TOP_SIGNATURES => writer.top_table("Top alert signatures", "Signature", &data.top_signatures),
            ELEMENT_TOP_ASNS => writer.top_table("Top autonomous systems", "ASN / organization", &data.top_asns),
            ELEMENT_TOP_COUNTRIES => writer.top_table("Top countries", "Country", &data.top_countries),
            ELEMENT_TOP_PORTS => writer.top_table("Top destination ports", "Port", &data.top_ports),
            ELEMENT_OPERATIONAL_ALERTS => writer.operational_alerts(&data.operational_alerts),
            ELEMENT_EVENT_APPENDIX => writer.event_appendix(&data.events, appendix_limit),
            ELEMENT_PARAMETERS => writer.parameters(data),
            _ => {}
        }
        after_element(&element, writer);
    }
}

// ---------------------------------------------------------------------------
// Artifact-scoped reports (sandbox_pdf.go / payload_pdf.go / ghidra_pdf.go):
// one referenced artifact rendered as its own themed/branded PDF, rather
// than the generic telemetry report above. Each takes the already-fetched
// raw ES document(s) — working off `&Value` directly rather than a fully
// typed struct per artifact, matching this crate's established posture for
// producer-controlled JSON this deep (detail.rs's summarize_cape_report
// takes the same approach) — and is otherwise pure, same contract as
// render_report_pdf: reports_api.rs does the fetching, these do the
// rendering.

fn v_str(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

fn v_bool_str(value: &Value) -> String {
    value.as_bool().map(|b| b.to_string()).unwrap_or_default()
}

fn v_i64(value: &Value) -> i64 {
    value.as_i64().unwrap_or(0)
}

fn v_i64_str(value: &Value) -> String {
    value.as_i64().map(|n| n.to_string()).unwrap_or_default()
}

fn v_f64(value: &Value) -> f64 {
    value.as_f64().unwrap_or(0.0)
}

fn v_strings(value: &Value) -> Vec<String> {
    value.as_array().into_iter().flatten().filter_map(|item| item.as_str().map(str::to_string)).collect()
}

fn slash_join(values: &[String]) -> String {
    values.iter().filter(|v| !v.is_empty()).cloned().collect::<Vec<_>>().join(" / ")
}

fn render_windows_forensics(writer: &mut PdfReportWriter, forensics: &Value) {
    writer.key_values(
        "Windows PE forensics",
        &[
            ("Format / machine", slash_join(&[v_str(&forensics["pe_type"]), v_str(&forensics["machine"])])),
            ("Execution mode", v_str(&forensics["execution_mode"])),
            ("Compile timestamp", v_str(&forensics["compile_timestamp"])),
            ("Entry point", v_i64_str(&forensics["entry_point"])),
            ("Image base", v_i64_str(&forensics["image_base"])),
            ("Import hash", v_str(&forensics["imp_hash"])),
            ("Embedded signature", v_bool_str(&forensics["signature_present"])),
        ],
    );
    let imports: Vec<String> = forensics["imports"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| format!("{}: {}", v_str(&item["dll"]), limit_strings(&v_strings(&item["symbols"]), 30).join(", ")))
        .collect();
    writer.bullets("Imported libraries and symbols", &limit_strings(&imports, 80));
    let mut suspicious: Vec<String> = forensics["suspicious_imports"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(key, values)| format!("{key}: {}", v_strings(values).join(", ")))
        .collect();
    suspicious.sort();
    writer.bullets("Suspicious Windows API imports", &limit_strings(&suspicious, 60));
    writer.bullets("Parser warnings", &limit_strings(&v_strings(&forensics["warnings"]), 40));
}

/// Renders one sandbox dynamic-analysis run, ported from sandbox_pdf.go's
/// renderThemedSandboxReportPDF. `doc` is detail::sandbox_run's response
/// (the raw sandbox-analysis-v1 `_source`, both the promoted top-level
/// fields and the full nested `sandbox` object).
///
/// One gap from Go: sandbox_pdf.go's "Process difference" section (added/
/// removed process rows between pre/post-execution snapshots) has no
/// equivalent here — this tier's sandbox-analysis-v1 documents carry
/// sockets_before/sockets_after but no processes_before/processes_after
/// snapshot pair (confirmed against a live document), so there is nothing
/// to diff. "Sockets difference", which does have real data, is computed
/// from sockets_before/after and rendered in full.
pub fn render_sandbox_pdf(doc: &Value, generated: chrono::DateTime<chrono::Utc>, theme: PdfTheme, branding: PdfBranding) -> Vec<u8> {
    let branding = branding.with_defaults();
    let s = &doc["sandbox"];
    let job = v_str(&s["job"]);
    let sha256 = v_str(&s["sha256"]);
    let mut writer = PdfReportWriter::new(theme, branding);
    writer.new_page();
    let data = ReportData {
        generated,
        title: "Sandbox Dynamic Analysis Report".to_string(),
        scope: format!("{job} | SHA-256 {sha256}"),
        summary: ReportSummary {
            first_seen: first_non_empty(&[&v_str(&s["started_at"]), &v_str(&s["requested_at"])], "").to_string(),
            last_seen: v_str(&s["completed_at"]),
            ..Default::default()
        },
        ..Default::default()
    };
    writer.cover(&data);

    let risk_score = v_i64(&s["risk_score"]);
    let risk_level = v_str(&s["risk_level"]);
    let run_status = v_str(&s["run_status"]);
    let net = &s["network_summary"];
    writer.section("Run assessment");
    writer.variable_metric_grid(&[
        ("Dynamic risk", format!("{risk_score} - {}", first_non_empty(&[&risk_level], "not rated").to_uppercase())),
        ("Run status", first_non_empty(&[&run_status], "unknown").to_uppercase()),
        ("Duration", format!("{:.1} seconds", v_f64(&s["duration_seconds"]))),
        ("Guest started", v_bool_str(&s["guest_started"])),
        ("Sockets before", v_strings(&s["sockets_before"]).len().to_string()),
        ("Sockets after", v_strings(&s["sockets_after"]).len().to_string()),
        ("DNS names", v_strings(&net["dns_queries"]).len().to_string()),
        ("Changed files", v_strings(&s["changed_files"]).len().to_string()),
    ]);
    let assessment = if run_status != "completed" {
        "Analysis did not run to completion. Empty evidence sections indicate an infrastructure or execution failure and must not be interpreted as a clean payload result.".to_string()
    } else {
        format!(
            "The isolated guest completed the selected {} path. The deterministic dynamic risk score is {risk_score}/100 ({}); review the evidence sections before drawing a verdict.",
            first_non_empty(&[&v_str(&s["analysis_path"])], "sandbox analysis"),
            first_non_empty(&[&risk_level], "not rated").to_uppercase(),
        )
    };
    writer.paragraph(&assessment);

    writer.key_values(
        "Sample and execution identity",
        &[
            ("SHA-256", sha256.clone()),
            ("SHA-1", v_str(&s["hashes"]["sha1"])),
            ("MD5", v_str(&s["hashes"]["md5"])),
            ("Capture name", v_str(&s["capture_name"])),
            ("Source", v_str(&s["source"])),
            ("File type", v_str(&s["file_type"])),
            ("Classification", slash_join(&[v_str(&s["classification"]["label"]), v_str(&s["classification"]["code"])])),
            ("Platform / category", slash_join(&[v_str(&s["platform"]), v_str(&s["classification"]["category"])])),
            ("Selected analysis path", first_non_empty(&[&v_str(&s["analysis_path"]), &v_str(&s["classification"]["analysis_path"])], "").to_string()),
            ("Execution mode", v_str(&s["execution_mode"])),
            ("Exit status", v_str(&s["exit_status"])),
        ],
    );
    let infra_evidence: Vec<String> =
        [v_str(&s["failure_reason"]), v_str(&s["timeout_reason"])].into_iter().filter(|v| !v.is_empty()).collect();
    if !infra_evidence.is_empty() {
        writer.bullets("Infrastructure failure evidence", &infra_evidence);
    }

    let sockets_before = v_strings(&s["sockets_before"]);
    let sockets_after = v_strings(&s["sockets_after"]);
    let added: Vec<String> = sockets_after.iter().filter(|v| !sockets_before.contains(v)).cloned().collect();
    let removed: Vec<String> = sockets_before.iter().filter(|v| !sockets_after.contains(v)).cloned().collect();
    writer.difference(
        "Sockets difference",
        "Socket rows added or removed between pre- and post-execution snapshots.",
        &added,
        &removed,
    );

    writer.section("Network and DNS evidence");
    writer.variable_metric_grid(&[
        ("Host packets", v_i64_str(&net["packets"])),
        ("Host bytes", v_i64_str(&net["bytes"])),
        ("Guest packets", v_i64_str(&net["guest_packets"])),
        ("Guest PCAP bytes", v_i64_str(&net["guest_pcap_bytes"])),
    ]);
    writer.bullets("Captured DNS names", &limit_strings(&v_strings(&net["dns_queries"]), 80));
    writer.bullets("Network attempts", &limit_strings(&v_strings(&net["attempts"]), 80));
    writer.bullets("Host capture events", &limit_strings(&v_strings(&net["events"]), 60));
    writer.bullets("Guest capture events", &limit_strings(&v_strings(&net["guest_events"]), 60));

    let techniques: Vec<String> = s["techniques"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| format!("{} {} - {}", v_str(&item["id"]), v_str(&item["name"]), v_str(&item["evidence"])).trim().to_string())
        .collect();
    if !techniques.is_empty() {
        writer.bullets("ATT&CK behavior mapping", &limit_strings(&techniques, 60));
    }
    writer.bullets("Changed files", &limit_strings(&v_strings(&s["changed_files"]), 100));
    let syscalls: Vec<String> = s["top_syscalls"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| format!("{} - {} calls", v_str(&item["name"]), v_i64(&item["count"])))
        .collect();
    if !syscalls.is_empty() {
        writer.bullets("Top system calls", &limit_strings(&syscalls, 50));
    }

    if s["windows_forensics"].as_object().is_some_and(|object| !object.is_empty()) {
        render_windows_forensics(&mut writer, &s["windows_forensics"]);
    }

    writer.ensure(150.0);
    writer.section("Evidence access and limitations");
    writer.paragraph("The administrator dashboard provides the sanitized JSON result and, when retained, host PCAP, guest PCAP, and a bounded diagnostics bundle. Use the SHA-256 on the result page to open the corresponding VirusTotal file record.");
    writer.paragraph("Dynamic analysis records what this bounded isolated run observed. Missing evidence is not proof of benign behavior. Emulation, guest time limits, environment checks, unsupported formats, encrypted traffic, and delayed execution can reduce visibility. Risk scoring and ATT&CK mappings are deterministic triage aids, not attribution or a compromise verdict.");
    writer.finish()
}

/// Renders one Ghidra static-analysis result, ported from ghidra_pdf.go's
/// renderThemedGhidraReportPDF. `doc` is detail::ghidra_run's response
/// (the raw ghidra-analysis-v1 `_source`, still under its own `ghidra`
/// wrapper key — unwrapped here, not by the caller, so the same document
/// detail.rs already hands the frontend straight through works here too).
///
/// One gap from Go: ghidraResult.IOCCorrelation (FLOSS-decoded strings
/// cross-referenced against Windows-sandbox runs of the same SHA-256) has
/// no equivalent field on this tier's ghidra-analysis-v1 documents
/// (confirmed against a live document: no ioc_correlation key) — that
/// cross-referencing is computed by ghidra.go at read time from a separate
/// sandbox-run lookup this port's ghidra worker/detail route doesn't
/// perform. Omitted rather than guessed at.
pub fn render_ghidra_pdf(doc: &Value, generated: chrono::DateTime<chrono::Utc>, theme: PdfTheme, branding: PdfBranding) -> Vec<u8> {
    let branding = branding.with_defaults();
    let g = &doc["ghidra"];
    let sha256 = v_str(&g["sha256"]);
    let exit_status = v_str(&g["exit_status"]);
    let mut writer = PdfReportWriter::new(theme, branding);
    writer.new_page();
    let data = ReportData {
        generated,
        title: "Ghidra Static Analysis Report".to_string(),
        scope: format!("SHA-256 {sha256}"),
        summary: ReportSummary {
            first_seen: first_non_empty(&[&v_str(&g["requested_at"]), &v_str(&g["started_at"])], "").to_string(),
            last_seen: v_str(&g["completed_at"]),
            ..Default::default()
        },
        ..Default::default()
    };
    writer.cover(&data);

    let functions = g["functions"].as_array().cloned().unwrap_or_default();
    let strings_list = v_strings(&g["strings"]);
    let imports = v_strings(&g["imports"]);

    writer.section("Analysis assessment");
    let assessment = if exit_status == "error" || v_str(&g["completed_at"]).is_empty() {
        "Analysis did not complete successfully. Empty evidence sections indicate an infrastructure or execution failure and must not be interpreted as a clean payload result.".to_string()
    } else {
        format!(
            "Headless decompilation completed: {} function(s), {} string(s), and {} import(s) recovered. Review the evidence sections below before drawing a verdict.",
            functions.len(),
            strings_list.len(),
            imports.len(),
        )
    };
    writer.paragraph(&assessment);

    if !g["ai_triage"].is_null() {
        let triage = &g["ai_triage"];
        writer.key_values(
            "AI triage",
            &[
                ("Family guess", v_str(&triage["family_guess"])),
                ("Risk level", first_non_empty(&[&v_str(&triage["risk_level"])], "not rated").to_uppercase()),
                ("Model", v_str(&triage["model"])),
                ("Evidence shown to model", v_str(&triage["evidence_shown"])),
            ],
        );
        writer.bullets("Behaviors noted", &limit_strings(&v_strings(&triage["behaviors"]), 40));
    }

    writer.key_values(
        "Sample identity",
        &[
            ("SHA-256", sha256.clone()),
            ("Exit status", exit_status.clone()),
            ("Requested", v_str(&g["requested_at"])),
            ("Completed", v_str(&g["completed_at"])),
        ],
    );
    let error = v_str(&g["error"]);
    if !error.is_empty() {
        writer.bullets("Failure evidence", &[error]);
    }

    if !g["lief"].is_null() {
        let l = &g["lief"];
        writer.key_values(
            "Structural info (lief)",
            &[
                ("Format", v_str(&l["format"])),
                ("Architecture", v_str(&l["architecture"])),
                ("Entry point", v_str(&l["entrypoint"])),
                ("Position-independent", v_bool_str(&l["is_pie"])),
                ("Sections", v_i64_str(&l["section_count"])),
                ("Stripped", v_bool_str(&l["stripped"])),
                ("Is DLL", v_bool_str(&l["is_dll"])),
                ("Compile timestamp", v_i64_str(&l["compile_timestamp"])),
            ],
        );
        writer.bullets("Linked libraries", &limit_strings(&v_strings(&l["libraries"]), 60));
    }

    writer.section("Functions, strings, and imports");
    writer.variable_metric_grid(&[
        ("Functions", functions.len().to_string()),
        ("Strings", strings_list.len().to_string()),
        ("Imports", imports.len().to_string()),
        ("Crypto constants", g["findcrypt"].as_array().map_or(0, Vec::len).to_string()),
    ]);
    let function_lines: Vec<String> = functions
        .iter()
        .map(|f| {
            let raw_name = v_str(&f["name"]);
            let name = first_non_empty(&[&raw_name], "(unnamed)");
            format!("{} {name} - {} ({} bytes)", v_str(&f["address"]), v_str(&f["signature"]), v_i64(&f["size"]))
        })
        .collect();
    writer.bullets(&format!("Functions ({})", functions.len()), &limit_strings(&function_lines, 80));
    writer.bullets(&format!("Strings ({})", strings_list.len()), &limit_strings(&strings_list, 100));
    writer.bullets(&format!("Imports ({})", imports.len()), &limit_strings(&imports, 100));
    let findcrypt: Vec<String> = g["findcrypt"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| format!("{}: {} ({})", v_str(&item["address"]), v_str(&item["algorithm"]), v_str(&item["constant"])))
        .collect();
    if !findcrypt.is_empty() {
        writer.bullets("Cryptographic constants", &limit_strings(&findcrypt, 60));
    }

    if !g["capa"].is_null() {
        writer.section("Capabilities (capa)");
        let capa = &g["capa"];
        let unsupported = v_str(&capa["unsupported"]);
        let capabilities = capa["capabilities"].as_array().cloned().unwrap_or_default();
        if !unsupported.is_empty() {
            writer.paragraph(&format!("capa declined this sample: {unsupported}"));
        } else if capabilities.is_empty() {
            writer.paragraph("No capabilities observed.");
        } else {
            let items: Vec<String> = capabilities
                .iter()
                .map(|c| format!("{} ({}) - {} match(es)", v_str(&c["name"]), v_str(&c["namespace"]), v_i64(&c["matches"])))
                .collect();
            writer.bullets(&format!("Capabilities ({})", capabilities.len()), &limit_strings(&items, 80));
            let attack: Vec<String> = capa["attack"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|a| {
                    format!("{} {} - {} {}", v_str(&a["id"]), v_str(&a["tactic"]), v_str(&a["technique"]), v_str(&a["subtechnique"]))
                        .trim()
                        .to_string()
                })
                .collect();
            if !attack.is_empty() {
                writer.bullets("ATT&CK mapping", &limit_strings(&attack, 60));
            }
            let mbc: Vec<String> = capa["mbc"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|m| {
                    format!("{} {} - {} {}", v_str(&m["id"]), v_str(&m["objective"]), v_str(&m["behavior"]), v_str(&m["method"]))
                        .trim()
                        .to_string()
                })
                .collect();
            if !mbc.is_empty() {
                writer.bullets("Malware Behavior Catalog mapping", &limit_strings(&mbc, 60));
            }
        }
    }

    if !g["floss"].is_null() {
        writer.section("Deobfuscated strings (FLOSS)");
        let floss = &g["floss"];
        let unsupported = v_str(&floss["unsupported"]);
        if !unsupported.is_empty() {
            writer.paragraph(&format!("FLOSS declined this sample: {unsupported}"));
        } else {
            for (label, list_key, total_key) in [
                ("Static strings", "static_strings", "static_strings_total"),
                ("Stack strings", "stack_strings", "stack_strings_total"),
                ("Tight strings", "tight_strings", "tight_strings_total"),
                ("Decoded strings", "decoded_strings", "decoded_strings_total"),
            ] {
                let items = v_strings(&floss[list_key]);
                writer.bullets(&format!("{label} ({} of {})", items.len(), v_i64(&floss[total_key])), &limit_strings(&items, 60));
            }
        }
    }

    if !g["fuzzy_hashes"].is_null() {
        let fh = &g["fuzzy_hashes"];
        writer.key_values(
            "Fuzzy hashes",
            &[
                ("ssdeep", first_non_empty(&[&v_str(&fh["ssdeep"]), &v_str(&fh["ssdeep_error"])], "").to_string()),
                ("TLSH", first_non_empty(&[&v_str(&fh["tlsh"]), &v_str(&fh["tlsh_error"])], "").to_string()),
            ],
        );
    }

    let revdeck_answer = v_str(&g["revdeck"]["answer"]);
    if !revdeck_answer.is_empty() {
        writer.section("Rev·Deck assisted analysis");
        writer.key_values(
            "Run",
            &[
                ("Workflow", v_str(&g["revdeck"]["workflow"])),
                ("Status", v_str(&g["revdeck"]["status"])),
                ("Tool calls", v_i64_str(&g["revdeck"]["tool_calls"])),
            ],
        );
        writer.paragraph(&revdeck_answer);
        writer.bullets("Warnings", &limit_strings(&v_strings(&g["revdeck"]["warnings"]), 20));
    }

    writer.ensure(150.0);
    writer.section("Evidence access and limitations");
    writer.paragraph("The administrator dashboard provides the sanitized JSON result, the rendered call graph (when graphviz is installed on the analysis host), and the raw sample. Use the SHA-256 above to open the corresponding VirusTotal file record.");
    writer.paragraph("This is a static analysis: it describes what the sample contains, not what it does when run. capa and FLOSS each cover a bounded set of formats/architectures - \"unsupported\" above means the tool declined this sample's format, not that it found nothing. AI triage and Rev·Deck answers are model output over attacker-influenced content and must be reviewed, not trusted as fact.");
    writer.finish()
}

/// Renders one captured payload's static/dynamic analysis, ported from
/// payload_pdf.go's renderThemedPayloadReportPDF. Assembled from the same
/// three-index read payload_detail.rs's own GET /api/v1/payloads/{hash}
/// already does (inventory/analysis/yara — `inventory`/`analysis` are the
/// raw `_source` docs, `yara` the raw hit `_source`s), plus two pieces
/// payload_detail.rs doesn't need: sandbox runs matching this hash (raw
/// `_source` docs, same shape render_sandbox_pdf reads) and any
/// GitHub-analysis verdict (detail::github_analysis_run's response shape,
/// or `Value::Null` if there is none) — both queried by reports_api.rs's
/// dispatcher and passed in pre-fetched, keeping this function pure like
/// its siblings.
#[allow(clippy::too_many_arguments)]
pub fn render_payload_pdf(
    hash: &str,
    inventory: &Value,
    analysis: &Value,
    yara: &[Value],
    sandbox_runs: &[Value],
    github_analysis: &Value,
    generated: chrono::DateTime<chrono::Utc>,
    theme: PdfTheme,
    branding: PdfBranding,
) -> Vec<u8> {
    let branding = branding.with_defaults();
    let a = &analysis["Analysis"];
    let classification = &a["Classification"];
    let sha256 = first_non_empty(&[&v_str(&a["SHA256"])], hash).to_string();
    let mut writer = PdfReportWriter::new(theme, branding);
    writer.new_page();
    let origin_label = v_str(&inventory["OriginLabel"]);
    let data = ReportData {
        generated,
        title: "Payload Analysis Report".to_string(),
        scope: format!("SHA-256 {sha256}"),
        summary: ReportSummary { first_seen: origin_label.clone(), ..Default::default() },
        ..Default::default()
    };
    writer.cover(&data);

    let risk_score = v_i64(&a["StaticRiskScore"]);
    let risk_level = v_str(&a["StaticRiskLevel"]);
    let entropy_value = v_f64(&a["EntropyValue"]);
    let packed_likely = a["PackedLikely"].as_bool().unwrap_or(false);
    let yara_matches: Vec<String> = yara.iter().flat_map(|item| v_strings(&item["yara"]["matches"])).collect();
    let iocs = v_strings(&a["IOCs"]);
    let github_label = if github_analysis.is_null() {
        "not queued".to_string()
    } else if let Some(verdict) = github_analysis.get("verdict").filter(|v| !v.is_null()) {
        format!("{}/{} {}", v_i64(&verdict["malicious"]), v_i64(&verdict["total"]), v_str(&verdict["level"]))
    } else {
        first_non_empty(&[&v_str(&github_analysis["exit_status"])], "queued").to_string()
    };

    writer.section("Assessment");
    writer.variable_metric_grid(&[
        ("Static risk", format!("{risk_score} - {}", first_non_empty(&[&risk_level], "not rated").to_uppercase())),
        ("Classification", slash_join(&[v_str(&classification["Label"]), v_str(&classification["Code"])])),
        ("Entropy", format!("{entropy_value:.3} ({})", if packed_likely { "packed likely" } else { "not packed-like" })),
        ("Size", v_str(&a["Size"])),
        ("YARA matches", yara_matches.len().to_string()),
        ("IOCs extracted", iocs.len().to_string()),
        ("Sandbox runs", sandbox_runs.len().to_string()),
        ("GitHub verdict", github_label),
    ]);
    let assessment = format!(
        "Static analysis classifies this sample as {} ({risk_score}/100, {}). Review the evidence sections below, and any linked dynamic-analysis run, before drawing a verdict.",
        first_non_empty(&[&v_str(&classification["Label"])], "an unclassified file"),
        first_non_empty(&[&risk_level], "not rated").to_uppercase(),
    );
    writer.paragraph(&assessment);

    writer.key_values(
        "Sample identity",
        &[
            ("Capture id", hash.to_string()),
            ("SHA-256", sha256.clone()),
            ("SHA-1", v_str(&a["SHA1"])),
            ("MD5", v_str(&a["MD5"])),
            ("MIME / magic", slash_join(&[v_str(&a["MIME"]), v_str(&a["Magic"])])),
            ("Platform", v_str(&classification["Platform"])),
            ("Suggested analysis path", v_str(&classification["AnalysisPath"])),
            ("Script type", v_str(&a["ScriptType"])),
            ("Family attribution", v_str(&inventory["Family"])),
            ("First observed", origin_label),
        ],
    );

    let format_info = v_strings(&a["FormatInfo"]);
    if !format_info.is_empty() {
        writer.bullets("Executable format details", &limit_strings(&format_info, 60));
    }
    let indicators = v_strings(&a["Indicators"]);
    if !indicators.is_empty() {
        writer.bullets("Script indicators", &limit_strings(&indicators, 60));
    }
    writer.bullets("Indicators of compromise", &limit_strings(&iocs, 80));
    let rules: Vec<String> = a["Rules"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| format!("{} [{}] - {}", v_str(&r["name"]), v_str(&r["severity"]).to_uppercase(), v_str(&r["description"])))
        .collect();
    if !rules.is_empty() {
        writer.bullets("Static rule matches", &limit_strings(&rules, 60));
    }

    writer.section("YARA and dynamic analysis");
    if yara_matches.is_empty() {
        writer.paragraph("No YARA rule matched this sample as of the last scan.");
    } else {
        let scanned = yara.first().map(|item| v_str(&item["yara"]["scanned_at"])).unwrap_or_default();
        writer.bullets(&format!("YARA matches (scanned {})", first_non_empty(&[&scanned], "unknown time")), &limit_strings(&yara_matches, 60));
    }
    if sandbox_runs.is_empty() {
        writer.paragraph("No isolated dynamic-analysis run has been queued for this sample yet.");
    } else {
        let items: Vec<String> = sandbox_runs
            .iter()
            .map(|run| {
                let s = &run["sandbox"];
                format!(
                    "{} - {} - risk {} ({})",
                    v_str(&s["completed_at"]),
                    first_non_empty(&[&v_str(&s["run_status"])], "unknown").to_uppercase(),
                    v_i64(&s["risk_score"]),
                    first_non_empty(&[&v_str(&s["risk_level"])], "not rated").to_uppercase(),
                )
            })
            .collect();
        writer.bullets("Sandbox runs", &limit_strings(&items, 40));
    }
    if !github_analysis.is_null() {
        writer.key_values(
            "GitHub-analysis verdict",
            &[("Exit status", v_str(&github_analysis["exit_status"])), ("Family", v_str(&github_analysis["family"]))],
        );
    }

    writer.ensure(150.0);
    writer.section("Evidence access and limitations");
    writer.paragraph("The administrator dashboard provides the raw sample (read-only, sandboxed access), the full static analysis, and links to any queued Ghidra/sandbox/GitHub-analysis results. Use the SHA-256 above to open the corresponding VirusTotal file record.");
    writer.paragraph("Static analysis characterizes the file as captured; it does not execute it. Missing evidence (no YARA match, no sandbox run yet) is not proof of benign behavior. Risk scoring is a deterministic triage aid, not attribution or a compromise verdict.");
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_minimal_valid_looking_pdf() {
        let data = ReportData {
            generated: chrono::Utc::now(),
            title: "Test Report".into(),
            scope: "All normalized telemetry".into(),
            summary: ReportSummary { events: 3, risk_score: 12, risk_level: "low".into(), ..Default::default() },
            top_sources: vec![Kv { key: "1.2.3.4".into(), count: 5, title: "1.2.3.4".into(), ..Default::default() }],
            findings: vec!["3 matching events.".into()],
            ..Default::default()
        };
        let elements = vec![
            ELEMENT_COVER.to_string(),
            ELEMENT_METRICS.to_string(),
            ELEMENT_FINDINGS.to_string(),
            ELEMENT_TOP_SOURCES.to_string(),
            ELEMENT_PARAMETERS.to_string(),
        ];
        let bytes = render_report_pdf(&data, pdf_theme_dark(), PdfBranding::default(), &elements, 120);
        assert!(bytes.starts_with(b"%PDF"));
        assert!(bytes.len() > 1000);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("/Catalog"));
        assert!(text.contains("trailer"));
    }

    #[test]
    fn renders_light_theme_and_both_themes_differ() {
        let data = ReportData {
            generated: chrono::Utc::now(),
            title: "Theme Test".into(),
            summary: ReportSummary { risk_level: "high".into(), ..Default::default() },
            ..Default::default()
        };
        let elements = vec![ELEMENT_COVER.to_string(), ELEMENT_METRICS.to_string()];
        let dark = render_report_pdf(&data, pdf_theme_dark(), PdfBranding::default(), &elements, 10);
        let light = render_report_pdf(&data, pdf_theme_light(), PdfBranding::default(), &elements, 10);
        assert!(dark.starts_with(b"%PDF"));
        assert!(light.starts_with(b"%PDF"));
        assert_ne!(dark, light);
    }

    #[test]
    #[ignore = "scratch: dumps a multi-page PDF to /tmp for manual inspection"]
    fn scratch_dump_multi_page_pdf() {
        let mut top_sources = Vec::new();
        for i in 0..300 {
            top_sources.push(Kv { key: format!("10.0.0.{i}"), count: 300 - i, title: format!("10.0.0.{i}"), ..Default::default() });
        }
        let mut events = Vec::new();
        for i in 0..300 {
            events.push(ReportEventRow {
                time: format!("2026-01-01T00:00:{i:02}Z"),
                sensor: "cowrie".into(),
                src_ip: format!("10.0.0.{i}"),
                port: "22".into(),
                detail: "login attempt with a moderately long detail string to force wrapping".into(),
                ..Default::default()
            });
        }
        let data = ReportData {
            generated: chrono::Utc::now(),
            title: "Scratch Multi-Page Report".into(),
            scope: "test".into(),
            summary: ReportSummary { events: 300, risk_score: 80, risk_level: "high".into(), ..Default::default() },
            top_sources,
            events,
            findings: vec!["finding one".into(), "finding two".into()],
            recommendations: vec!["do the thing".into()],
            ..Default::default()
        };
        let elements = vec![
            ELEMENT_COVER.to_string(),
            ELEMENT_METRICS.to_string(),
            ELEMENT_ASSESSMENT.to_string(),
            ELEMENT_FINDINGS.to_string(),
            ELEMENT_RECOMMENDATIONS.to_string(),
            ELEMENT_TOP_SOURCES.to_string(),
            ELEMENT_EVENT_APPENDIX.to_string(),
            ELEMENT_PARAMETERS.to_string(),
        ];
        let bytes = render_report_pdf(&data, pdf_theme_dark(), PdfBranding::default(), &elements, 300);
        std::fs::write("/tmp/report_pdf_scratch.pdf", &bytes).unwrap();
        eprintln!("wrote {} bytes", bytes.len());
    }

    #[test]
    fn wraps_text_without_splitting_words() {
        let lines = wrap_pdf_text("the quick brown fox jumps over the lazy dog", 10);
        assert!(lines.iter().all(|l| l.len() <= 10 || !l.contains(' ')));
        assert_eq!(lines.join(" ").split_whitespace().collect::<Vec<_>>(), vec![
            "the", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"
        ]);
    }
}
