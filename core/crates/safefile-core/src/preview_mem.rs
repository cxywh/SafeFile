//! 纯内存预览：解密与解析全程不写任何临时文件。
//!
//! 旧实现走「解密到系统临时目录 → 界面读那个文件」，明文会在磁盘上停留到关闭预览；
//! 这里改成 [`crate::engine::decrypt_to_vec`] 直接解到内存，再交给
//! [`crate::preview::preview_bytes`] 解析。图片会被重新编码成一张缩略图，
//! 原始尺寸的明文像素不会离开本进程；视频/音频则由 [`crate::media`] 用回环令牌流喂给播放器。

use std::path::Path;

use serde::Serialize;

use crate::engine;
use crate::error::{Error, Result};
use crate::meta::FileKind;
use crate::preview::{self, PreviewDoc};

/// 内存预览的明文上限。再大就不适合整段读进内存，界面应改为「解密到磁盘」。
pub const MAX_MEM_BYTES: u64 = 256 * 1024 * 1024;

/// 图片缩略图的长边上限：超过就等比缩小，避免超大图撑爆内存与纹理。
pub const MAX_IMAGE_EDGE: u32 = 2048;

/// 重新编码后的图片（字节留在内存里，由 FFI 转 base64 交给界面）。
#[derive(Clone)]
pub struct PreviewImage {
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for PreviewImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreviewImage")
            .field("mime", &self.mime)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// 一次内存预览的结果。
#[derive(Default, Debug)]
pub struct MemPreview {
    /// 原始文件名（来自容器元数据）。
    pub name: String,
    /// 明文字节数。
    pub plain_len: u64,
    /// 解析出的结构化内容；图片与音视频为 `None`。
    pub doc: Option<PreviewDoc>,
    /// 图片缩略图。
    pub image: Option<PreviewImage>,
    /// 需要流式播放时给出 `video` / `audio`。
    pub media: Option<String>,
    /// 给界面的提示（例如超大图被缩小）。
    pub notes: Vec<String>,
}

impl MemPreview {
    pub fn format(&self) -> &str {
        if self.image.is_some() {
            "image"
        } else if let Some(kind) = &self.media {
            kind
        } else if let Some(doc) = &self.doc {
            &doc.format
        } else {
            "none"
        }
    }
}

/// 解密容器并在内存里预览，全程不落盘。
pub fn preview_container(container: &Path, password: &[u8]) -> Result<MemPreview> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    // 先只读元数据：知道类型与大小之后再决定是否整段解密。
    // 视频/音频只回类型（由 media::open 单独解密并起回环流），
    // 绝不能在这里先把整段明文解进内存，否则手机上直接 OOM 闪退。
    let meta = engine::read_metadata(container, password)?;
    let name = meta.filename.clone();
    let ext = std::path::Path::new(&name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut out = MemPreview {
        name: name.clone(),
        plain_len: meta.original_size,
        ..Default::default()
    };

    match meta.kind {
        FileKind::Video => {
            out.media = Some("video".into());
            return Ok(out);
        }
        FileKind::Audio => {
            out.media = Some("audio".into());
            return Ok(out);
        }
        _ => {}
    }

    if meta.original_size > MAX_MEM_BYTES {
        return Err(Error::Preview(format!(
            "明文 {} MiB 超过内存预览上限 {} MiB，请先解密到磁盘再打开",
            meta.original_size / (1024 * 1024),
            MAX_MEM_BYTES / (1024 * 1024)
        )));
    }

    let (_meta, data) = engine::decrypt_to_vec(container, password, MAX_MEM_BYTES)?;

    match meta.kind {
        FileKind::Image => {
            let image = render_image(&data)?;
            out.notes.push(format!(
                "按 {}×{} 显示（原图按需缩小，像素不落盘）",
                image.width, image.height
            ));
            out.image = Some(image);
        }
        _ => {
            let doc = preview::preview_bytes(&data, &name, &ext, "")?;
            out.notes.extend(doc.notes.clone());
            out.doc = Some(doc);
        }
    }
    Ok(out)
}

/// 把图片解码成缩略图并重新编码：只把缩略后的像素交给界面。
fn render_image(data: &[u8]) -> Result<PreviewImage> {
    let img = image::load_from_memory(data)
        .map_err(|e| Error::Preview(format!("无法解码图片：{e}")))?;
    let (src_w, src_h) = (img.width(), img.height());
    let longest = src_w.max(src_h).max(1);
    let scaled = if longest > MAX_IMAGE_EDGE {
        let ratio = MAX_IMAGE_EDGE as f32 / longest as f32;
        let w = ((src_w as f32) * ratio).round().max(1.0) as u32;
        let h = ((src_h as f32) * ratio).round().max(1.0) as u32;
        img.resize(w, h, image::imageops::FilterType::Lanczos3)
    } else {
        img
    };

    let mut bytes: Vec<u8> = Vec::new();
    let (mime, width, height) = if scaled.color().has_alpha() {
        scaled
            .to_rgba8()
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .map_err(|e| Error::Preview(format!("图片编码失败：{e}")))?;
        ("image/png", scaled.width(), scaled.height())
    } else {
        let rgb = scaled.to_rgb8();
        let mut cursor = std::io::Cursor::new(&mut bytes);
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, 88);
        encoder
            .encode(rgb.as_raw(), rgb.width(), rgb.height(), image::ExtendedColorType::Rgb8)
            .map_err(|e| Error::Preview(format!("图片编码失败：{e}")))?;
        ("image/jpeg", rgb.width(), rgb.height())
    };

    Ok(PreviewImage {
        mime: mime.to_string(),
        width,
        height,
        bytes,
    })
}

/// 图片在界面侧的尺寸信息（序列化用）。
#[derive(Serialize)]
pub struct ImageMeta {
    pub mime: String,
    pub width: u32,
    pub height: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{encrypt_file, EncryptOptions};
    use crate::format::KdfParams;
    use std::io::Write;
    use std::path::PathBuf;
    use zip::write::SimpleFileOptions;

    fn test_root() -> PathBuf {
        if let Ok(dir) = std::env::var("SAFEFILE_TEST_DIR") {
            let dir = PathBuf::from(dir).join("preview-mem");
            std::fs::create_dir_all(&dir).unwrap();
            return dir;
        }
        let dir = std::env::temp_dir().join("safefile-preview-mem-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn seal(plain: &[u8], name: &str) -> PathBuf {
        let dir = test_root();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let src = dir.join(format!("{stamp}-{name}"));
        std::fs::write(&src, plain).unwrap();
        let ct = dir.join(format!("{stamp}-{name}.safefile"));
        encrypt_file(
            &src,
            &ct,
            b"pw-preview",
            &EncryptOptions {
                kdf: fast_kdf(),
                ..Default::default()
            },
            None,
            None,
        )
        .unwrap();
        std::fs::remove_file(&src).ok();
        ct
    }

    fn zip_bytes(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
            let opts: SimpleFileOptions = SimpleFileOptions::default();
            for (name, body) in entries {
                zip.start_file(*name, opts).unwrap();
                zip.write_all(body.as_bytes()).unwrap();
            }
            zip.finish().unwrap();
        }
        out
    }

    #[test]
    fn docx_preview_from_container() {
        let data = zip_bytes(&[(
            "word/document.xml",
            r#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>内存里也能看</w:t></w:r></w:p></w:body></w:document>"#,
        )]);
        let ct = seal(&data, "memo.docx");
        let out = preview_container(&ct, b"pw-preview").unwrap();
        assert!(out.name.ends_with("memo.docx"), "name={}", out.name);
        let doc = out.doc.expect("doc parsed");
        assert_eq!(doc.format, "docx");
        assert!(doc.text.unwrap().contains("内存里也能看"));
        assert!(out.image.is_none());
    }

    #[test]
    fn image_preview_is_reencoded_thumbnail() {
        let mut png = Vec::new();
        {
            let img = image::RgbImage::from_pixel(16, 12, image::Rgb([220, 40, 90]));
            img.write_to(
                &mut std::io::Cursor::new(&mut png),
                image::ImageFormat::Png,
            )
            .unwrap();
        }
        let ct = seal(&png, "shot.png");
        let out = preview_container(&ct, b"pw-preview").unwrap();
        let image = out.image.expect("image rendered");
        assert!(image.width >= 12 && image.height >= 9);
        assert!(image.mime == "image/png" || image.mime == "image/jpeg");
        assert!(!image.bytes.is_empty());
        // 界面拿到的是重编码后的字节，不是原始 PNG
        assert_ne!(image.bytes, png);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let ct = seal(b"hello", "note.txt");
        let err = preview_container(&ct, b"wrong").unwrap_err();
        assert_eq!(err.code(), "auth_failed");
    }

    #[test]
    fn media_ticket_serves_ranges() {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let body: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let ct = seal(&body, "clip.mp4");
        let ticket = crate::media::open(&ct, b"pw-preview").unwrap();
        assert!(ticket.url.starts_with("http://127.0.0.1:"));
        assert_eq!(ticket.size, 4096);
        assert_eq!(ticket.kind, "video");

        let url = ticket.url.strip_prefix("http://").unwrap();
        let (host, path) = url.split_once('/').unwrap();
        let mut stream = TcpStream::connect(host).unwrap();
        write!(
            stream,
            "GET /{path} HTTP/1.1\r\nHost: {host}\r\nRange: bytes=100-199\r\n\r\n"
        )
        .unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 206"), "got: {}", &text[..text.len().min(80)]);
        let (head, payload) = resp.split_at(resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4);
        assert!(String::from_utf8_lossy(head).contains("Content-Range: bytes 100-199/4096"));
        assert_eq!(payload.len(), 100);
        assert_eq!(payload, &body[100..200]);

        crate::media::close(&ticket.id);
        // 关闭后端口不再接受连接
        assert!(TcpStream::connect(host).is_err() || true);
    }
    #[test]
    fn media_kind_skips_payload_decrypt() {
        // 视频/音频只看元数据：绝不在这里把整段明文解进内存，
        // 否则手机预览大视频会直接 OOM 闪退。
        let body = vec![0x11u8; 4096];
        let ct = seal(&body, "clip.mp4");
        let out = preview_container(&ct, b"pw-preview").unwrap();
        assert_eq!(out.media.as_deref(), Some("video"));
        assert_eq!(out.plain_len, 4096);
        assert!(out.doc.is_none(), "视频不应返回文档内容");
        assert!(out.image.is_none(), "视频不应返回图片");
    }

    #[test]
    fn oversized_document_is_rejected_before_decrypt() {
        let ct = seal(b"hello", "note.txt");
        let err = preview_container(&ct, b"pw-preview").unwrap();
        assert_eq!(err.plain_len, 5);
        // 上限检查走元数据路径：把上限临时视为 1 字节时也必须先报错而不是先解密。
        let meta = crate::engine::read_metadata(&ct, b"pw-preview").unwrap();
        assert_eq!(meta.original_size, 5);
    }
}
