//! 加密元数据（明文块 0 的内容）：TLV 编码，整体位于加密块内，不暴露在明文头中。

use crate::error::{Error, Result};

pub const META_VERSION: u16 = 1;

pub const TAG_END: u8 = 0;
pub const TAG_FILENAME: u8 = 1;
pub const TAG_ORIGINAL_SIZE: u8 = 2;
pub const TAG_MTIME_SECS: u8 = 3;
pub const TAG_MTIME_NANOS: u8 = 4;
pub const TAG_MIME: u8 = 5;
pub const TAG_FILE_KIND: u8 = 6;

pub const MAX_FILENAME_LEN: usize = 1024;
pub const MAX_MIME_LEN: usize = 128;

/// 文件大类，供预览引擎选择解码器。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Unknown = 0,
    Image = 1,
    Pdf = 2,
    Word = 3,
    Excel = 4,
    PowerPoint = 5,
    Text = 6,
    Markdown = 7,
    Csv = 8,
    Json = 9,
    Xml = 10,
    Archive = 11,
    Audio = 12,
    Video = 13,
}

impl FileKind {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => FileKind::Image,
            2 => FileKind::Pdf,
            3 => FileKind::Word,
            4 => FileKind::Excel,
            5 => FileKind::PowerPoint,
            6 => FileKind::Text,
            7 => FileKind::Markdown,
            8 => FileKind::Csv,
            9 => FileKind::Json,
            10 => FileKind::Xml,
            11 => FileKind::Archive,
            12 => FileKind::Audio,
            13 => FileKind::Video,
            _ => FileKind::Unknown,
        }
    }

    /// 按扩展名推断类型（不读取文件内容）。
    pub fn detect(filename: &str, mime: Option<&str>) -> Self {
        let ext = std::path::Path::new(filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match ext.as_str() {
            "png" | "jpg" | "jpeg" | "webp" | "bmp" | "gif" | "tif" | "tiff" | "heic" | "heif" => FileKind::Image,
            "pdf" => FileKind::Pdf,
            "doc" | "docx" | "rtf" | "odt" => FileKind::Word,
            "xls" | "xlsx" | "ods" => FileKind::Excel,
            "ppt" | "pptx" | "odp" => FileKind::PowerPoint,
            "txt" | "log" | "ini" | "conf" | "yaml" | "yml" | "toml" => FileKind::Text,
            "md" | "markdown" => FileKind::Markdown,
            "csv" | "tsv" => FileKind::Csv,
            "json" => FileKind::Json,
            "xml" | "html" | "htm" | "svg" => FileKind::Xml,
            "zip" | "7z" | "rar" | "tar" | "gz" => FileKind::Archive,
            "mp3" | "wav" | "flac" | "aac" | "m4a" | "ogg" => FileKind::Audio,
            "mp4" | "mkv" | "mov" | "webm" | "avi" => FileKind::Video,
            _ => {
                if let Some(m) = mime {
                    if m.starts_with("image/") {
                        return FileKind::Image;
                    }
                    if m.starts_with("audio/") {
                        return FileKind::Audio;
                    }
                    if m.starts_with("video/") {
                        return FileKind::Video;
                    }
                    if m.starts_with("text/") {
                        return FileKind::Text;
                    }
                }
                FileKind::Unknown
            }
        }
    }
}

/// 加密前记录、解密后还原的元数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub filename: String,
    pub original_size: u64,
    pub mtime_secs: Option<i64>,
    pub mtime_nanos: Option<u32>,
    pub mime: Option<String>,
    pub kind: FileKind,
}

impl Metadata {
    pub fn new(filename: impl Into<String>, original_size: u64) -> Self {
        let filename = filename.into();
        let kind = FileKind::detect(&filename, None);
        Self { filename, original_size, mtime_secs: None, mtime_nanos: None, mime: None, kind }
    }

    /// 序列化为 TLV 字节串。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let name = self.filename.as_bytes();
        if name.len() > MAX_FILENAME_LEN {
            return Err(Error::BadMetadata("文件名过长"));
        }
        let mut out = Vec::with_capacity(64 + name.len());
        out.extend_from_slice(&META_VERSION.to_le_bytes());
        push_field(&mut out, TAG_FILENAME, name)?;
        push_field(&mut out, TAG_ORIGINAL_SIZE, &self.original_size.to_le_bytes())?;
        if let Some(secs) = self.mtime_secs {
            push_field(&mut out, TAG_MTIME_SECS, &secs.to_le_bytes())?;
            if let Some(nanos) = self.mtime_nanos {
                push_field(&mut out, TAG_MTIME_NANOS, &nanos.to_le_bytes())?;
            }
        }
        if let Some(mime) = &self.mime {
            let bytes = mime.as_bytes();
            if bytes.len() <= MAX_MIME_LEN {
                push_field(&mut out, TAG_MIME, bytes)?;
            }
        }
        push_field(&mut out, TAG_FILE_KIND, &[self.kind as u8])?;
        out.push(TAG_END);
        Ok(out)
    }

    /// 从 TLV 字节串解析，容忍未来新增字段（未知 tag 跳过）。
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 3 {
            return Err(Error::BadMetadata("长度不足"));
        }
        let version = u16::from_le_bytes([buf[0], buf[1]]);
        if version != META_VERSION {
            return Err(Error::BadMetadata("元数据版本不支持"));
        }
        let mut idx = 2;
        let mut filename: Option<String> = None;
        let mut size: Option<u64> = None;
        let mut mtime_secs = None;
        let mut mtime_nanos = None;
        let mut mime = None;
        let mut kind = FileKind::Unknown;

        while idx < buf.len() {
            let tag = buf[idx];
            idx += 1;
            if tag == TAG_END {
                break;
            }
            if idx + 4 > buf.len() {
                return Err(Error::BadMetadata("字段长度截断"));
            }
            let len = u32::from_le_bytes([buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]]) as usize;
            idx += 4;
            if idx + len > buf.len() {
                return Err(Error::BadMetadata("字段内容截断"));
            }
            let value = &buf[idx..idx + len];
            idx += len;
            match tag {
                TAG_FILENAME => {
                    let s = std::str::from_utf8(value).map_err(|_| Error::BadMetadata("文件名非 UTF-8"))?;
                    filename = Some(s.to_string());
                }
                TAG_ORIGINAL_SIZE => {
                    if value.len() != 8 {
                        return Err(Error::BadMetadata("文件大小字段长度非法"));
                    }
                    let mut a = [0u8; 8];
                    a.copy_from_slice(value);
                    size = Some(u64::from_le_bytes(a));
                }
                TAG_MTIME_SECS => {
                    if value.len() == 8 {
                        let mut a = [0u8; 8];
                        a.copy_from_slice(value);
                        mtime_secs = Some(i64::from_le_bytes(a));
                    }
                }
                TAG_MTIME_NANOS => {
                    if value.len() == 4 {
                        let mut a = [0u8; 4];
                        a.copy_from_slice(value);
                        mtime_nanos = Some(u32::from_le_bytes(a));
                    }
                }
                TAG_MIME => {
                    if let Ok(s) = std::str::from_utf8(value) {
                        mime = Some(s.to_string());
                    }
                }
                TAG_FILE_KIND => {
                    if value.len() == 1 {
                        kind = FileKind::from_u8(value[0]);
                    }
                }
                _ => {} // 未知字段：向前兼容，直接跳过
            }
        }

        let filename = filename.ok_or(Error::BadMetadata("缺少文件名字段"))?;
        let original_size = size.ok_or(Error::BadMetadata("缺少大小字段"))?;
        if mtime_secs.is_none() {
            mtime_nanos = None;
        }
        Ok(Self { filename, original_size, mtime_secs, mtime_nanos, mime, kind })
    }
}

fn push_field(out: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<()> {
    if value.len() > u32::MAX as usize {
        return Err(Error::BadMetadata("字段过大"));
    }
    out.push(tag);
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// 把元数据中的文件名收敛成安全的单层文件名。
///
/// 防御：路径穿越（`..`、绝对路径）、Windows 保留字符与设备名、控制字符、
/// 尾随点与空格、超长名称。
pub fn sanitize_filename(name: &str) -> String {
    let basename = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim_matches('\0');

    let mut cleaned: String = basename
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();

    cleaned = cleaned.trim_matches(' ').to_string();
    while cleaned.ends_with('.') || cleaned.ends_with(' ') {
        cleaned.pop();
    }
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "decrypted".to_string();
    }

    // 保留设备名（CON、NUL 等）加前缀规避
    let stem_upper = cleaned
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    if WINDOWS_RESERVED.contains(&stem_upper.as_str()) {
        cleaned = format!("_{}", cleaned);
    }

    // 限制长度（按字符计，保留扩展名）
    const MAX_CHARS: usize = 180;
    if cleaned.chars().count() > MAX_CHARS {
        let ext = std::path::Path::new(&cleaned)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_string());
        let mut truncated: String = cleaned.chars().take(MAX_CHARS).collect();
        if let Some(ext) = ext {
            if !truncated.to_ascii_lowercase().ends_with(&ext.to_ascii_lowercase()) {
                truncated.push('.');
                truncated.push_str(&ext);
            }
        }
        cleaned = truncated;
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut meta = Metadata::new("报告 2024 版.docx", 123456);
        meta.mtime_secs = Some(1_700_000_000);
        meta.mtime_nanos = Some(500);
        meta.mime = Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document".into());
        let buf = meta.encode().unwrap();
        let back = Metadata::decode(&buf).unwrap();
        assert_eq!(meta, back);
        assert_eq!(back.kind, FileKind::Word);
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&META_VERSION.to_le_bytes());
        buf.push(TAG_FILENAME);
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(b"a.b");
        buf.push(99); // 未知字段
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&[7, 7]);
        buf.push(TAG_ORIGINAL_SIZE);
        buf.extend_from_slice(&8u32.to_le_bytes());
        buf.extend_from_slice(&42u64.to_le_bytes());
        buf.push(TAG_END);
        let meta = Metadata::decode(&buf).unwrap();
        assert_eq!(meta.filename, "a.b");
        assert_eq!(meta.original_size, 42);
    }

    #[test]
    fn sanitize_blocks_traversal() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("C:\\Windows\\System32\\evil.dll"), "evil.dll");
        assert_eq!(sanitize_filename(".."), "decrypted");
        assert_eq!(sanitize_filename(""), "decrypted");
        assert_eq!(sanitize_filename("a<b>c:d.txt"), "a_b_c_d.txt");
        assert_eq!(sanitize_filename("NUL.txt"), "_NUL.txt");
        assert_eq!(sanitize_filename("名字 .txt"), "名字 .txt");
        assert!(sanitize_filename(&"x".repeat(300)).chars().count() <= 180);
    }
}
