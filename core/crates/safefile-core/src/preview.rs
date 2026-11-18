//! 安全预览：把已解密的明文文件解析成受限的结构化内容，交给界面渲染。
//!
//! 设计原则：
//! - **只读解析**，绝不执行宏、脚本、外部程序或嵌入对象；
//! - **有界**：所有输出都有字符数/行数/页数上限，压缩包按需读取并限制解压体积，
//!   防止 zip 炸弹与超大文档拖垮 UI；
//! - **不落盘、不联网**，返回值里只有文本与表格结构，不含路径以外的元数据；
//! - 解析失败时返回可读的说明，而不是把原始二进制塞给界面。
//!
//! 支持范围：docx / xlsx / pptx（OOXML）、odt / ods / odp（ODF）、pdf（文本层）、
//! 以及 txt/md/csv/json/xml 等纯文本。旧版二进制 Office（.doc/.xls/.ppt）与
//! 扫描件 PDF 只能给出提示。

use std::collections::HashMap;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Serialize;
use zip::ZipArchive;

use crate::error::{Error, Result};

/// 单个预览文档允许输出的最大字符数。
pub const MAX_CHARS: usize = 200_000;
/// 从压缩包里读取单个条目的体积上限。
const MAX_ENTRY_BYTES: u64 = 24 * 1024 * 1024;
/// 纯文本最多读取的字节数。
const MAX_TEXT_BYTES: u64 = 8 * 1024 * 1024;
/// 单个文件的读取上限：再大就不适合在内存里解析了。
pub const MAX_PREVIEW_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// 表格最多展示的行数与列数。
const MAX_ROWS: usize = 300;
const MAX_COLS: usize = 40;
/// 演示文稿最多展示的页数。
const MAX_SLIDES: usize = 60;
/// PDF 最多提取的页数。
const MAX_PDF_PAGES: usize = 30;

/// 一个工作表。
#[derive(Serialize, Debug, Clone, Default)]
pub struct Sheet {
    pub name: String,
    pub rows: Vec<Vec<String>>,
    pub truncated: bool,
}

/// 一页演示文稿。
#[derive(Serialize, Debug, Clone, Default)]
pub struct Slide {
    pub index: usize,
    pub title: String,
    pub lines: Vec<String>,
}

/// 预览结果。字段为空表示该类型没有此项。
#[derive(Serialize, Debug, Clone, Default)]
pub struct PreviewDoc {
    /// 实际使用的解析器：docx / xlsx / pptx / odt / ods / odp / pdf / text / none。
    pub format: String,
    /// 文档类内容的正文。
    pub text: Option<String>,
    /// 表格类内容。
    pub sheets: Vec<Sheet>,
    /// 演示文稿内容。
    pub slides: Vec<Slide>,
    /// PDF 逐页文本。
    pub pdf_pages: Vec<String>,
    /// 面向用户的提示（例如「旧版 .doc 不支持」）。
    pub notes: Vec<String>,
    /// 是否因为上限而截断。
    pub truncated: bool,
}

impl PreviewDoc {
    fn note(mut self, msg: impl Into<String>) -> Self {
        self.notes.push(msg.into());
        self
    }
}

/// 按文件类型解析预览内容。`kind` 取 [`crate::meta::FileKind`] 的名称或小写扩展名。
///
/// 这里读整个文件：调用方已限定体积（见 [`crate::preview_mem`] 的上限），
/// 而且所有解析器都要在内存里做，不做任何临时落地。
pub fn preview_file(path: &Path, kind: &str) -> Result<PreviewDoc> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut data = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_PREVIEW_FILE_BYTES)
        .read_to_end(&mut data)?;
    preview_bytes(&data, &name, &ext, kind)
}

/// 直接从内存字节解析预览内容，不接触磁盘。
pub fn preview_bytes(data: &[u8], name: &str, ext: &str, kind: &str) -> Result<PreviewDoc> {
    let ext = ext.to_ascii_lowercase();
    let kind = if kind.trim().is_empty() {
        match crate::meta::FileKind::detect(name, None) {
            crate::meta::FileKind::Image => "image",
            crate::meta::FileKind::Pdf => "pdf",
            crate::meta::FileKind::Word => "word",
            crate::meta::FileKind::Excel => "excel",
            crate::meta::FileKind::PowerPoint => "powerpoint",
            crate::meta::FileKind::Text => "text",
            crate::meta::FileKind::Markdown => "markdown",
            crate::meta::FileKind::Csv => "csv",
            crate::meta::FileKind::Json => "json",
            crate::meta::FileKind::Xml => "xml",
            crate::meta::FileKind::Archive => "archive",
            crate::meta::FileKind::Audio => "audio",
            crate::meta::FileKind::Video => "video",
            crate::meta::FileKind::Unknown => "unknown",
        }
        .to_string()
    } else {
        kind.to_ascii_lowercase()
    };
    let fmt = if matches!(ext.as_str(), "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp") {
        ext.clone()
    } else {
        kind.clone()
    };

    match fmt.as_str() {
        "docx" | "word" => docx(data),
        "xlsx" | "excel" => xlsx(data),
        "pptx" | "powerpoint" => pptx(data),
        "odt" => odf(data, OdfKind::Text),
        "ods" => odf(data, OdfKind::Sheet),
        "odp" => odf(data, OdfKind::Slides),
        "pdf" => pdf_text(data),
        "text" | "markdown" | "csv" | "json" | "xml" | "txt" | "md" | "log" | "ini" => plain_text(data),
        "image" | "video" | "audio" => Ok(PreviewDoc {
            format: "none".into(),
            ..Default::default()
        }
        .note("该类型交给播放器解码（内存数据源），不做文本提取")),
        "archive" => Ok(PreviewDoc {
            format: "none".into(),
            ..Default::default()
        }
        .note("压缩包不展开预览，避免解压炸弹；请解密后自行解压")),
        other => Ok(PreviewDoc {
            format: "none".into(),
            ..Default::default()
        }
        .note(format!("暂不支持预览该格式（{other}），请解密后用本机应用打开"))),
    }
}

// ---------------------------------------------------------------------------
// 纯文本
// ---------------------------------------------------------------------------

fn plain_text(data: &[u8]) -> Result<PreviewDoc> {
    let take = std::cmp::min(data.len() as u64, MAX_TEXT_BYTES) as usize;
    let buf = data[..take].to_vec();
    let mut truncated = (data.len() as u64) > MAX_TEXT_BYTES;
    if buf.contains(&0) {
        return Ok(PreviewDoc {
            format: "none".into(),
            ..Default::default()
        }
        .note("文件包含 NUL 字节，判定为二进制内容，不做文本预览"));
    }
    let mut text = String::from_utf8_lossy(&buf).to_string();
    if text.chars().count() > MAX_CHARS {
        text = text.chars().take(MAX_CHARS).collect();
        truncated = true;
    }
    Ok(PreviewDoc {
        format: "text".into(),
        text: Some(text),
        truncated,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// 压缩包工具
// ---------------------------------------------------------------------------

fn open_zip(data: &[u8]) -> Result<ZipArchive<Cursor<&[u8]>>> {
    ZipArchive::new(Cursor::new(data))
        .map_err(|e| Error::Preview(format!("无法解析 Office 文档（zip）：{e}")))
}

/// 把 workbook rels 里的 Target 归一成包内条目名。
///
/// 规范允许 `worksheets/sheet1.xml`（相对 `xl/`）与 `/xl/worksheets/sheet1.xml`
/// （包内绝对路径）两种写法，Excel、WPS、openpyxl 各有偏好；不归一就会读空。
fn worksheet_entry(target: &str) -> String {
    let t = target.trim_start_matches('/');
    let t = t.strip_prefix("./").unwrap_or(t);
    if t.starts_with("xl/") {
        t.to_string()
    } else {
        format!("xl/{t}")
    }
}

fn read_entry<R: Read + Seek>(zip: &mut ZipArchive<R>, name: &str) -> Result<Option<Vec<u8>>> {
    let mut entry = match zip.by_name(name) {
        Ok(e) => e,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(e) => return Err(Error::Preview(format!("读取 {name} 失败：{e}"))),
    };
    let mut buf = Vec::new();
    entry
        .by_ref()
        .take(MAX_ENTRY_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| Error::Preview(format!("解压 {name} 失败：{e}")))?;
    Ok(Some(buf))
}

fn xml_reader(bytes: &[u8]) -> Reader<&[u8]> {
    let mut r = Reader::from_reader(bytes);
    r.config_mut().trim_text(false);
    r
}

fn local_name(name: &[u8]) -> Vec<u8> {
    match name.iter().rposition(|b| *b == b':') {
        Some(i) => name[i + 1..].to_vec(),
        None => name.to_vec(),
    }
}

fn attr_value(e: &quick_xml::events::BytesStart<'_>, key: &[u8]) -> Option<String> {
    for a in e.attributes().flatten() {
        if a.key.as_ref() == key {
            return Some(String::from_utf8_lossy(&a.value).to_string());
        }
    }
    None
}

/// 收集器：统一处理字符上限与截断标记。
struct Sink {
    text: String,
    truncated: bool,
}

impl Sink {
    fn new() -> Self {
        Self {
            text: String::new(),
            truncated: false,
        }
    }

    fn push(&mut self, s: &str) {
        if self.truncated {
            return;
        }
        for ch in s.chars() {
            if self.text.chars().count() >= MAX_CHARS {
                self.truncated = true;
                return;
            }
            self.text.push(ch);
        }
    }

    /// 行数已经很多时压缩连续空行，避免大文档出现整屏空白。
    fn tidy(self) -> (String, bool) {
        let mut out = String::with_capacity(self.text.len());
        let mut blank = 0usize;
        for line in self.text.lines() {
            if line.trim().is_empty() {
                blank += 1;
                if blank > 1 {
                    continue;
                }
            } else {
                blank = 0;
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        (out, self.truncated)
    }
}

// ---------------------------------------------------------------------------
// docx
// ---------------------------------------------------------------------------

fn docx(data: &[u8]) -> Result<PreviewDoc> {
    let mut zip = open_zip(data)?;
    let body = match read_entry(&mut zip, "word/document.xml")? {
        Some(b) => b,
        None => {
            return Ok(PreviewDoc {
                format: "docx".into(),
                ..Default::default()
            }
            .note("文档缺少 word/document.xml，可能不是有效的 docx"))
        }
    };
    let mut sink = Sink::new();
    let mut reader = xml_reader(&body);
    let mut buf = Vec::new();
    let mut in_text = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match local_name(e.name().as_ref()).as_slice() {
                b"t" => in_text = true,
                b"tab" => sink.push("\t"),
                _ => {}
            },
            Ok(Event::Empty(e)) => match local_name(e.name().as_ref()).as_slice() {
                b"tab" => sink.push("\t"),
                b"br" | b"cr" => sink.push("\n"),
                _ => {}
            },
            Ok(Event::End(e)) => match local_name(e.name().as_ref()).as_slice() {
                b"t" => in_text = false,
                b"p" => sink.push("\n"),
                b"tc" => sink.push("\t"),
                b"tr" => sink.push("\n"),
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if in_text {
                    if let Ok(t) = e.unescape() {
                        sink.push(&t);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(Error::Preview(format!("解析 docx 正文失败：{e}"))),
            _ => {}
        }
        buf.clear();
    }
    let (text, truncated) = sink.tidy();
    Ok(PreviewDoc {
        format: "docx".into(),
        text: Some(text),
        truncated,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// xlsx
// ---------------------------------------------------------------------------

fn xlsx(data: &[u8]) -> Result<PreviewDoc> {
    let mut zip = open_zip(data)?;
    let shared = match read_entry(&mut zip, "xl/sharedStrings.xml")? {
        Some(b) => parse_shared_strings(&b),
        None => Vec::new(),
    };
    let workbook = read_entry(&mut zip, "xl/workbook.xml")?
        .ok_or_else(|| Error::Preview("工作簿缺少 xl/workbook.xml".into()))?;
    let rels = read_entry(&mut zip, "xl/_rels/workbook.xml.rels")?
        .map(|b| parse_rels(&b))
        .unwrap_or_default();

    let sheets_meta = parse_workbook_sheets(&workbook);
    let mut sheets = Vec::new();
    let mut truncated = false;
    for (name, rid) in sheets_meta.into_iter().take(12) {
        let target = match rels.get(&rid) {
            Some(t) => t.clone(),
            None => continue,
        };
        // rels 里的 Target 有两种写法：``worksheets/sheet1.xml``（相对 ``xl/``）
        // 与 ``/xl/worksheets/sheet1.xml``（包内绝对路径，openpyxl 就这么写）。
        let entry = worksheet_entry(&target);
        let Some(bytes) = read_entry(&mut zip, &entry)? else {
            continue;
        };
        let (rows, t) = parse_sheet(&bytes, &shared);
        truncated |= t;
        sheets.push(Sheet {
            name,
            rows,
            truncated: t,
        });
        if sheets.len() >= 12 {
            break;
        }
    }
    if sheets.is_empty() {
        return Ok(PreviewDoc {
            format: "xlsx".into(),
            ..Default::default()
        }
        .note("没有找到可解析的工作表"));
    }
    Ok(PreviewDoc {
        format: "xlsx".into(),
        sheets,
        truncated,
        ..Default::default()
    })
}

fn parse_shared_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut reader = xml_reader(bytes);
    let mut buf = Vec::new();
    let mut cur = String::new();
    let mut in_t = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match local_name(e.name().as_ref()).as_slice() {
                b"si" => cur.clear(),
                b"t" => in_t = true,
                _ => {}
            },
            Ok(Event::End(e)) => match local_name(e.name().as_ref()).as_slice() {
                b"t" => in_t = false,
                b"si" => out.push(std::mem::take(&mut cur)),
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if in_t {
                    if let Ok(t) = e.unescape() {
                        cur.push_str(&t);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

fn parse_rels(bytes: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut reader = xml_reader(bytes);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) | Ok(Event::Start(e)) => {
                if local_name(e.name().as_ref()) == b"Relationship" {
                    if let (Some(id), Some(target)) = (
                        attr_value(&e, b"Id"),
                        attr_value(&e, b"Target"),
                    ) {
                        map.insert(id, target);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    map
}

fn parse_workbook_sheets(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut reader = xml_reader(bytes);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) | Ok(Event::Start(e)) => {
                if local_name(e.name().as_ref()) == b"sheet" {
                    if let (Some(name), Some(rid)) = (
                        attr_value(&e, b"name"),
                        attr_value(&e, b"r:id").or_else(|| attr_value(&e, b"id")),
                    ) {
                        out.push((name, rid));
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

fn col_index(reference: &str) -> Option<usize> {
    let mut n = 0usize;
    let mut saw = false;
    for ch in reference.chars() {
        if ch.is_ascii_alphabetic() {
            n = n * 26 + (ch.to_ascii_uppercase() as usize - 'A' as usize + 1);
            saw = true;
        } else {
            break;
        }
    }
    if saw {
        Some(n.saturating_sub(1))
    } else {
        None
    }
}

fn parse_sheet(bytes: &[u8], shared: &[String]) -> (Vec<Vec<String>>, bool) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut truncated = false;
    let mut reader = xml_reader(bytes);
    let mut buf = Vec::new();
    let mut row: Vec<(usize, String)> = Vec::new();
    let mut in_cell = false;
    let mut cell_kind = String::new();
    let mut cell_text = String::new();
    let mut in_value = false;
    let mut cell_col = 0usize;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match local_name(e.name().as_ref()).as_slice() {
                b"row" => row.clear(),
                b"c" => {
                    in_cell = true;
                    cell_text.clear();
                    cell_kind = attr_value(&e, b"t").unwrap_or_default();
                    cell_col = attr_value(&e, b"r")
                        .and_then(|r| col_index(&r))
                        .unwrap_or(row.len());
                }
                b"v" | b"t" => in_value = true,
                _ => {}
            },
            Ok(Event::End(e)) => match local_name(e.name().as_ref()).as_slice() {
                b"v" | b"t" => in_value = false,
                b"c" => {
                    in_cell = false;
                    let raw = std::mem::take(&mut cell_text);
                    let value = match cell_kind.as_str() {
                        "s" => raw
                            .trim()
                            .parse::<usize>()
                            .ok()
                            .and_then(|i| shared.get(i).cloned())
                            .unwrap_or_default(),
                        "b" => {
                            if raw.trim() == "1" {
                                "TRUE".into()
                            } else {
                                "FALSE".into()
                            }
                        }
                        _ => raw,
                    };
                    if !value.is_empty() {
                        row.push((cell_col, value));
                    }
                }
                b"row" => {
                    if rows.len() < MAX_ROWS {
                        let width = row.iter().map(|(c, _)| c + 1).max().unwrap_or(0).min(MAX_COLS);
                        let mut cells = vec![String::new(); width];
                        for (c, v) in row.drain(..) {
                            if c < width {
                                cells[c] = v;
                            }
                        }
                        if cells.iter().any(|c| !c.is_empty()) {
                            rows.push(cells);
                        }
                    } else {
                        truncated = true;
                    }
                }
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if in_cell && in_value {
                    if let Ok(t) = e.unescape() {
                        cell_text.push_str(&t);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => {
                truncated = true;
                break;
            }
            _ => {}
        }
        buf.clear();
    }
    (rows, truncated)
}

// ---------------------------------------------------------------------------
// pptx
// ---------------------------------------------------------------------------

fn pptx(data: &[u8]) -> Result<PreviewDoc> {
    let mut zip = open_zip(data)?;
    let pres = read_entry(&mut zip, "ppt/presentation.xml")?
        .ok_or_else(|| Error::Preview("演示文稿缺少 ppt/presentation.xml".into()))?;
    let rels = read_entry(&mut zip, "ppt/_rels/presentation.xml.rels")?
        .map(|b| parse_rels(&b))
        .unwrap_or_default();
    let order = parse_slide_order(&pres);
    let mut slides = Vec::new();
    let mut truncated = false;
    let list = if order.is_empty() {
        // 没有 sldIdLst 时退化为按文件名扫描
        fallback_slides(&zip)
    } else {
        order
            .into_iter()
            .filter_map(|rid| rels.get(&rid).cloned())
            .collect()
    };
    for (i, target) in list.into_iter().take(MAX_SLIDES).enumerate() {
        let entry = format!("ppt/{}", target.trim_start_matches('/'));
        let Some(bytes) = read_entry(&mut zip, &entry)? else {
            continue;
        };
        let lines = slide_lines(&bytes);
        let title = lines.first().cloned().unwrap_or_else(|| format!("第 {} 页", i + 1));
        slides.push(Slide {
            index: i + 1,
            title,
            lines,
        });
    }
    if slides.is_empty() {
        return Ok(PreviewDoc {
            format: "pptx".into(),
            ..Default::default()
        }
        .note("没有找到可解析的幻灯片"));
    }
    if order_len_more_than(&zip, &slides) {
        truncated = true;
    }
    Ok(PreviewDoc {
        format: "pptx".into(),
        slides,
        truncated,
        ..Default::default()
    })
}

fn order_len_more_than<R: Read + Seek>(_zip: &ZipArchive<R>, slides: &[Slide]) -> bool {
    slides.len() >= MAX_SLIDES
}

fn fallback_slides<R: Read + Seek>(zip: &ZipArchive<R>) -> Vec<String> {
    let mut names: Vec<String> = zip
        .file_names()
        .filter(|n| n.starts_with("ppt/slides/slide") && n.ends_with(".xml"))
        .map(|n| n.trim_start_matches("ppt/").to_string())
        .collect();
    names.sort_by(|a, b| {
        let na = slide_number(a);
        let nb = slide_number(b);
        na.cmp(&nb)
    });
    names
}

fn slide_number(name: &str) -> usize {
    name.chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

fn parse_slide_order(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut reader = xml_reader(bytes);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) | Ok(Event::Start(e)) => {
                if local_name(e.name().as_ref()) == b"sldId" {
                    if let Some(rid) = attr_value(&e, b"r:id").or_else(|| attr_value(&e, b"id")) {
                        out.push(rid);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

fn slide_lines(bytes: &[u8]) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_t = false;
    let mut reader = xml_reader(bytes);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if local_name(e.name().as_ref()) == b"t" {
                    in_t = true;
                }
            }
            Ok(Event::End(e)) => match local_name(e.name().as_ref()).as_slice() {
                b"t" => in_t = false,
                b"p" => {
                    let line = cur.trim().to_string();
                    if !line.is_empty() {
                        lines.push(line);
                    }
                    cur.clear();
                    if lines.len() > 400 || lines.iter().map(|l| l.len()).sum::<usize>() > MAX_CHARS {
                        break;
                    }
                }
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if in_t {
                    if let Ok(t) = e.unescape() {
                        cur.push_str(&t);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    lines
}

// ---------------------------------------------------------------------------
// ODF
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum OdfKind {
    Text,
    Sheet,
    Slides,
}

fn odf(data: &[u8], kind: OdfKind) -> Result<PreviewDoc> {
    let mut zip = open_zip(data)?;
    let body = read_entry(&mut zip, "content.xml")?
        .ok_or_else(|| Error::Preview("ODF 文档缺少 content.xml".into()))?;
    match kind {
        OdfKind::Text => {
            let mut sink = Sink::new();
            let mut reader = xml_reader(&body);
            let mut buf = Vec::new();
            let mut in_p = false;
            let mut has_content = false;
            loop {
                match reader.read_event_into(&mut buf) {
                    Ok(Event::Start(e)) => {
                        if local_name(e.name().as_ref()) == b"p" {
                            in_p = true;
                            if has_content {
                                sink.push("\n");
                            }
                        }
                    }
                    Ok(Event::End(e)) => {
                        if local_name(e.name().as_ref()) == b"p" {
                            in_p = false;
                            has_content = true;
                        }
                    }
                    Ok(Event::Text(e)) => {
                        if in_p {
                            if let Ok(t) = e.unescape() {
                                sink.push(&t);
                            }
                        }
                    }
                    Ok(Event::Empty(e)) => {
                        if matches!(local_name(e.name().as_ref()).as_slice(), b"line-break" | b"br") {
                            sink.push("\n");
                        }
                    }
                    Ok(Event::Eof) => break,
                    Err(e) => return Err(Error::Preview(format!("解析 ODF 失败：{e}"))),
                    _ => {}
                }
                buf.clear();
            }
            let (text, truncated) = sink.tidy();
            Ok(PreviewDoc {
                format: "odf-text".into(),
                text: Some(text),
                truncated,
                ..Default::default()
            })
        }
        OdfKind::Sheet => {
            let mut sheets = Vec::new();
            let mut reader = xml_reader(&body);
            let mut buf = Vec::new();
            let mut name = String::new();
            let mut rows: Vec<Vec<String>> = Vec::new();
            let mut row: Vec<String> = Vec::new();
            let mut cell = String::new();
            let mut in_cell = false;
            let mut in_text = false;
            loop {
                match reader.read_event_into(&mut buf) {
                    Ok(Event::Start(e)) => match local_name(e.name().as_ref()).as_slice() {
                        b"table" => {
                            name = attr_value(&e, b"table:name")
                                .or_else(|| attr_value(&e, b"name"))
                                .unwrap_or_else(|| "表格".into());
                            rows.clear();
                        }
                        b"table-cell" => {
                            in_cell = true;
                            cell.clear();
                        }
                        b"p" => in_text = true,
                        _ => {}
                    },
                    Ok(Event::End(e)) => match local_name(e.name().as_ref()).as_slice() {
                        b"p" => in_text = false,
                        b"table-cell" => {
                            in_cell = false;
                            row.push(std::mem::take(&mut cell));
                        }
                        b"table-row" => {
                            if !row.is_empty() && rows.len() < MAX_ROWS {
                                let mut r = std::mem::take(&mut row);
                                r.truncate(MAX_COLS);
                                rows.push(r);
                            }
                        }
                        b"table" => {
                            if !rows.is_empty() {
                                sheets.push(Sheet {
                                    name: name.clone(),
                                    rows: std::mem::take(&mut rows),
                                    truncated: false,
                                });
                            }
                        }
                        _ => {}
                    },
                    Ok(Event::Text(e)) => {
                        if in_cell && in_text {
                            if let Ok(t) = e.unescape() {
                                cell.push_str(&t);
                            }
                        }
                    }
                    Ok(Event::Eof) => break,
                    Err(_) => break,
                    _ => {}
                }
                buf.clear();
            }
            let truncated = sheets.len() > 12;
            sheets.truncate(12);
            if sheets.is_empty() {
                Ok(PreviewDoc {
                    format: "odf-sheet".into(),
                    ..Default::default()
                }
                .note("没有找到可解析的表格"))
            } else {
                Ok(PreviewDoc {
                    format: "odf-sheet".into(),
                    sheets,
                    truncated,
                    ..Default::default()
                })
            }
        }
        OdfKind::Slides => {
            let mut slides = Vec::new();
            let mut reader = xml_reader(&body);
            let mut buf = Vec::new();
            let mut in_p = false;
            let mut lines: Vec<String> = Vec::new();
            let mut cur = String::new();
            loop {
                match reader.read_event_into(&mut buf) {
                    Ok(Event::Start(e)) => {
                        if local_name(e.name().as_ref()) == b"p" {
                            in_p = true;
                        }
                    }
                    Ok(Event::End(e)) => {
                        if local_name(e.name().as_ref()) == b"p" {
                            in_p = false;
                            let line = cur.trim().to_string();
                            if !line.is_empty() {
                                lines.push(line);
                            }
                            cur.clear();
                        }
                    }
                    Ok(Event::Text(e)) => {
                        if in_p {
                            if let Ok(t) = e.unescape() {
                                cur.push_str(&t);
                            }
                        }
                    }
                    Ok(Event::Eof) => break,
                    Err(_) => break,
                    _ => {}
                }
                buf.clear();
            }
            // ODF 的页分隔在 draw:page 上；这里退化为按段落数切分。
            let chunk = 8usize;
            for (i, group) in lines.chunks(chunk).enumerate().take(MAX_SLIDES) {
                let title = group
                    .first()
                    .cloned()
                    .unwrap_or_else(|| format!("第 {} 页", i + 1));
                slides.push(Slide {
                    index: i + 1,
                    title,
                    lines: group.to_vec(),
                });
            }
            Ok(PreviewDoc {
                format: "odf-slides".into(),
                truncated: slides.len() >= MAX_SLIDES,
                slides,
                ..Default::default()
            })
        }
    }
}

// ---------------------------------------------------------------------------
// PDF（提取文本层，不做渲染）
// ---------------------------------------------------------------------------

fn pdf_text(data: &[u8]) -> Result<PreviewDoc> {
    use pdf::content::{Op, TextDrawAdjusted};
    use pdf::font::{FontType, ToUnicodeMap};
    use pdf::object::MaybeRef;

    let file = pdf::file::FileOptions::cached()
        .load(data.to_vec())
        .map_err(|e| Error::Preview(format!("无法解析 PDF：{e}")))?;
    let resolver = file.resolver();

    let mut pages: Vec<String> = Vec::new();
    let mut truncated = false;
    let mut suspect_any = false;
    for (i, page) in file.pages().enumerate() {
        if i >= MAX_PDF_PAGES {
            truncated = true;
            break;
        }
        let Ok(page) = page else { continue };
        // Font 不是 Clone，load() 返回的 MaybeRef 必须保活，才能安全借出 &Font。
        let mut held: Vec<MaybeRef<pdf::font::Font>> = Vec::new();
        let mut font_index: HashMap<String, usize> = HashMap::new();
        if let Ok(res) = page.resources() {
            for (name, lazy) in res.fonts.iter() {
                if let Ok(font) = lazy.load(&resolver) {
                    if std::env::var_os("SF_PDF_DEBUG").is_some() {
                        eprintln!(
                            "[pdf] font {name} subtype={:?} to_unicode={}",
                            font.subtype,
                            font.to_unicode(&resolver).is_some()
                        );
                    }
                    font_index.insert(name.as_str().to_string(), held.len());
                    held.push(font);
                }
            }
        }
        let mut current: Option<(bool, Option<ToUnicodeMap>)> = None;
        let mut suspect = false;
        let mut text = String::new();
        if let Some(contents) = page.contents.as_ref() {
            if let Ok(ops) = contents.operations(&resolver) {
                for op in ops {
                    match op {
                        Op::TextFont { name, .. } => {
                            current = font_index.get(name.as_str()).map(|idx| {
                                let font: &pdf::font::Font = &held[*idx];
                                let two_byte = matches!(font.subtype, FontType::Type0);
                                let map = font.to_unicode(&resolver).and_then(|m| m.ok());
                                (two_byte, map)
                            });
                        }
                        Op::TextDraw { text: t } => {

                            let (piece, lossy) = decode_pdf_string(t.as_bytes(), current.as_ref());
                            suspect |= lossy;
                            text.push_str(&piece);
                        }
                        Op::TextDrawAdjusted { array } => {
                            for item in array {
                                match item {
                                    TextDrawAdjusted::Text(t) => {

                                        let (piece, lossy) =
                                            decode_pdf_string(t.as_bytes(), current.as_ref());
                                        suspect |= lossy;
                                        text.push_str(&piece);
                                    }
                                    TextDrawAdjusted::Spacing(sp) if sp < -120.0 => {
                                        text.push(' ');
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Op::TextNewline => text.push('\n'),
                        _ => {}
                    }
                }
            }
        }
        let cleaned: String = text
            .lines()
            .map(|l| l.trim_end())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        pages.push(cleaned);
        if suspect {
            suspect_any = true;
        }
    }
    let total: usize = pages.iter().map(|p| p.chars().count()).sum();
    if total == 0 {
        return Ok(PreviewDoc {
            format: "pdf".into(),
            ..Default::default()
        }
        .note("该 PDF 没有可提取的文本层（可能是扫描件或纯图片），请解密后用 PDF 阅读器打开"));
    }
    let mut doc = PreviewDoc {
        format: "pdf".into(),
        pdf_pages: pages,
        truncated,
        ..Default::default()
    };
    if suspect_any {
        doc.notes.push(
            "部分字体缺少 Unicode 映射，提取的文本可能乱码；排版与图片不在预览范围内".into(),
        );
    }
    Ok(doc)
}

fn decode_pdf_string(
    bytes: &[u8],
    current: Option<&(bool, Option<pdf::font::ToUnicodeMap>)>,
) -> (String, bool) {
    let (two_byte, map) = match current {
        Some((two, map)) => (*two, map.as_ref()),
        None => (false, None),
    };
    let mut out = String::new();
    if let Some(map) = map {
        if two_byte {
            // PDF 的多字节字符码是**大端**：高字节在前。
            for chunk in bytes.chunks(2) {
                let hi = chunk[0] as u16;
                let lo = if chunk.len() > 1 { chunk[1] as u16 } else { 0 };
                let code = (hi << 8) | lo;
                match map.get(code) {
                    Some(s) => out.push_str(s),
                    None => out.push('\u{FFFD}'),
                }
            }
        } else {
            for b in bytes {
                match map.get(*b as u16) {
                    Some(s) => out.push_str(s),
                    None => out.push('\u{FFFD}'),
                }
            }
        }
        // 映射存在但大部分码位缺失，说明这个子集字体没有完整 ToUnicode。
        let missing = out.chars().filter(|c| *c == '\u{FFFD}').count();
        let total = out.chars().count();
        if total > 0 && missing * 2 > total {
            return decode_without_map(bytes, two_byte);
        }
    } else {
        return decode_without_map(bytes, two_byte);
    }
    (out, false)
}

/// 没有 ToUnicode 时的兜底。中文 PDF 常见三种情况：
/// ① Identity-H + UCS2（按 UTF-16BE 能直接还原）；
/// ② 用 GBK/GB18030 编码的双字节 CID（需要按中文编码试解）；
/// ③ 纯西文用 Latin-1。
/// 这里逐个尝试，只有「像正常文字且含 CJK」才采用，否则退回 Latin-1。
fn decode_without_map(bytes: &[u8], _two_byte: bool) -> (String, bool) {
    // 全 ASCII 的一串（字体子集里西文常用单字节码）直接按 ASCII 还原，
    // 不要再拿去做 GBK/UTF-16 猜测，否则 "Origin" 会被拼成「佲楧楮」。
    if bytes.iter().all(|b| (0x20..0x7F).contains(b) || *b == b'\n' || *b == b'\t' || *b == b'\r') {
        return (bytes.iter().map(|b| *b as char).collect(), false);
    }
    if bytes.len() >= 2 && bytes.len() % 2 == 0 {
        let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks(2) {
            let hi = chunk[0] as u16;
            let lo = if chunk.len() > 1 { chunk[1] as u16 } else { 0 };
            units.push((hi << 8) | lo);
        }
        if let Ok(s) = String::from_utf16(&units) {
            if has_cjk(&s) && looks_like_text(&s) {
                return (s, true);
            }
        }
    }
    if bytes.iter().any(|b| *b >= 0x80) {
        let (cow, _, had_errors) = encoding_rs::GBK.decode(bytes);
        if !had_errors && has_cjk(&cow) && looks_like_text(&cow) {
            return (cow.into_owned(), true);
        }
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        if looks_like_text(s) {
            return (s.to_string(), !s.is_ascii());
        }
    }
    (bytes.iter().map(|b| *b as char).collect(), bytes.iter().any(|b| *b >= 0x80))
}

fn has_cjk(s: &str) -> bool {
    s.chars().any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c))
}

/// 粗判解码结果是否像正常文字：控制字符占比低，且不含大量替换符。
fn looks_like_text(s: &str) -> bool {
    let total = s.chars().count();
    if total == 0 {
        return false;
    }
    let mut good = 0usize;
    let mut bad = 0usize;
    for c in s.chars() {
        if c == '\u{FFFD}' || (c.is_control() && c != '\n' && c != '\t' && c != '\r') {
            bad += 1;
        } else if c.is_ascii() || ('\u{4E00}'..='\u{9FFF}').contains(&c) || ('\u{3000}'..='\u{303F}').contains(&c)
            || ('\u{FF00}'..='\u{FFEF}').contains(&c) || ('\u{0400}'..='\u{04FF}').contains(&c)
            || ('\u{0370}'..='\u{03FF}').contains(&c) || c.is_whitespace()
            || ('\u{00A0}'..='\u{00FF}').contains(&c)
        {
            good += 1;
        } else {
            bad += 1;
        }
    }
    good * 10 >= total * 9 && bad * 20 <= total.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn test_root(name: &str) -> std::path::PathBuf {
        let base = std::env::var_os("SAFEFILE_TEST_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!("preview-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("创建测试目录");
        dir
    }

    fn make_zip(name: &str, entries: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = test_root(name);
        let path = dir.join(format!("{name}.zip"));
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buf);
            let opts: SimpleFileOptions = SimpleFileOptions::default();
            for (entry, body) in entries {
                zip.start_file(*entry, opts).expect("写入条目");
                zip.write_all(body.as_bytes()).expect("写入内容");
            }
            zip.finish().expect("完成 zip");
        }
        std::fs::write(&path, buf.into_inner()).expect("落盘 zip");
        path
    }

    #[test]
    fn docx_paragraphs_and_table() {
        let xml = r#"<?xml version="1.0"?><w:document xmlns:w="w"><w:body>
<w:p><w:r><w:t>项目报告</w:t></w:r></w:p>
<w:p><w:r><w:t>第一列</w:t></w:r><w:r><w:tab/></w:r><w:r><w:t>第二列</w:t></w:r></w:p>
<w:tbl><w:tr><w:tc><w:p><w:r><w:t>单元格</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
</w:body></w:document>"#;
        let path = make_zip("docx", &[("word/document.xml", xml)]);
        let doc = preview_file(&path, "Word").expect("解析 docx");
        let text = doc.text.unwrap_or_default();
        assert!(text.contains("项目报告"), "缺少段落文本：{text}");
        assert!(text.contains("第一列\t第二列"), "缺少制表符：{text}");
        assert!(text.contains("单元格"), "缺少表格文本：{text}");
        assert_eq!(doc.format, "docx");
    }

    #[test]
    fn xlsx_shared_strings_and_numbers() {
        let shared = r#"<?xml version="1.0"?><sst><si><t>姓名</t></si><si><t>张三</t></si></sst>"#;
        let workbook = r#"<?xml version="1.0"?><workbook xmlns:r="r"><sheets><sheet name="成绩" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
        let rels = r#"<?xml version="1.0"?><Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>"#;
        let sheet = r#"<?xml version="1.0"?><worksheet><sheetData>
<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>0</v></c></row>
<row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2"><v>92</v></c></row>
</sheetData></worksheet>"#;
        let path = make_zip(
            "xlsx",
            &[
                ("xl/sharedStrings.xml", shared),
                ("xl/workbook.xml", workbook),
                ("xl/_rels/workbook.xml.rels", rels),
                ("xl/worksheets/sheet1.xml", sheet),
            ],
        );
        let doc = preview_file(&path, "Excel").expect("解析 xlsx");
        assert_eq!(doc.sheets.len(), 1);
        let sheet = &doc.sheets[0];
        assert_eq!(sheet.name, "成绩");
        assert_eq!(sheet.rows[0], vec!["姓名".to_string(), "姓名".to_string()]);
        assert_eq!(sheet.rows[1], vec!["张三".to_string(), "92".to_string()]);
    }

    #[test]
    fn xlsx_absolute_rels_target() {
        // openpyxl / 部分导出工具把 Target 写成包内绝对路径。
        let workbook = r#"<?xml version="1.0"?><workbook xmlns:r="r"><sheets><sheet name="成绩" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
        let rels = r#"<?xml version="1.0"?><Relationships><Relationship Id="rId1" Target="/xl/worksheets/sheet1.xml"/></Relationships>"#;
        let sheet = r#"<?xml version="1.0"?><worksheet><sheetData>
<row r="1"><c r="A1" t="inlineStr"><is><t>姓名</t></is></c><c r="B1" t="inlineStr"><is><t>分数</t></is></c></row>
<row r="2"><c r="A2" t="inlineStr"><is><t>张三</t></is></c><c r="B2"><v>92</v></c></row>
</sheetData></worksheet>"#;
        let path = make_zip(
            "xlsx-absolute",
            &[
                ("xl/workbook.xml", workbook),
                ("xl/_rels/workbook.xml.rels", rels),
                ("xl/worksheets/sheet1.xml", sheet),
            ],
        );
        let doc = preview_file(&path, "Excel").expect("解析 xlsx");
        assert_eq!(doc.sheets.len(), 1, "绝对路径的 Target 必须能找到工作表");
        assert_eq!(doc.sheets[0].rows[1], vec!["张三".to_string(), "92".to_string()]);
    }

    #[test]
    fn pptx_slides_in_order() {
        let pres = r#"<?xml version="1.0"?><presentation xmlns:r="r"><sldIdLst><sldId id="256" r:id="rId2"/></sldIdLst></presentation>"#;
        let rels = r#"<?xml version="1.0"?><Relationships><Relationship Id="rId2" Target="slides/slide1.xml"/></Relationships>"#;
        let slide = r#"<?xml version="1.0"?><p:sld xmlns:a="a"><a:p><a:r><a:t>封面标题</a:t></a:r></a:p><a:p><a:r><a:t>副标题</a:t></a:r></a:p></p:sld>"#;
        let path = make_zip(
            "pptx",
            &[
                ("ppt/presentation.xml", pres),
                ("ppt/_rels/presentation.xml.rels", rels),
                ("ppt/slides/slide1.xml", slide),
            ],
        );
        let doc = preview_file(&path, "PowerPoint").expect("解析 pptx");
        assert_eq!(doc.slides.len(), 1);
        assert_eq!(doc.slides[0].title, "封面标题");
        assert!(doc.slides[0].lines.iter().any(|l| l == "副标题"));
    }

    #[test]
    fn text_rejects_binary_and_truncates() {
        let dir = test_root("text");
        let txt = dir.join("note.txt");
        std::fs::write(&txt, "第一行\n第二行\n").unwrap();
        let doc = preview_file(&txt, "Text").unwrap();
        assert!(doc.text.unwrap().contains("第一行"));

        let bin = dir.join("bin.dat");
        std::fs::write(&bin, [0u8, 1, 2, 3]).unwrap();
        let doc = preview_file(&bin, "Text").unwrap();
        assert_eq!(doc.format, "none");
        assert!(doc.notes.iter().any(|n| n.contains("二进制")));

        let big = dir.join("big.md");
        let body = "x".repeat(MAX_CHARS + 100);
        std::fs::write(&big, body).unwrap();
        let doc = preview_file(&big, "Markdown").unwrap();
        assert!(doc.truncated);
        assert_eq!(doc.text.unwrap().chars().count(), MAX_CHARS);
    }

    #[test]
    fn unknown_format_is_reported() {
        let dir = test_root("unknown");
        let p = dir.join("setup.exe");
        std::fs::write(&p, [1u8, 2, 3]).unwrap();
        let doc = preview_file(&p, "Unknown").unwrap();
        assert_eq!(doc.format, "none");
        assert!(doc.notes.iter().any(|n| n.contains("暂不支持")));
    }
    #[test]
    fn pdf_ascii_runs_stay_ascii() {
        // 字体子集里的西文常是单字节码，不能被 GBK 猜成汉字。
        let (s, lossy) = decode_without_map(b"Origin", false);
        assert_eq!(s, "Origin");
        assert!(!lossy);
    }

    #[test]
    fn pdf_utf16be_cjk_is_recovered() {
        // “中文” 的 UCS2 大端字节
        let (s, lossy) = decode_without_map(&[0x4E, 0x2D, 0x65, 0x87], true);
        assert_eq!(s, "中文");
        assert!(lossy);
    }

    #[test]
    fn pdf_gbk_cjk_is_recovered() {
        // “中文” 的 GBK 字节
        let (s, lossy) = decode_without_map(&[0xD6, 0xD0, 0xCE, 0xC4], false);
        assert_eq!(s, "中文");
        assert!(lossy);
    }

    #[test]
    fn pdf_text_quality_guard() {
        assert!(looks_like_text("实验报告 Origin 2341"));
        assert!(!looks_like_text("\u{1}\u{2}\u{3}"));
        assert!(!looks_like_text(""));
    }
}
