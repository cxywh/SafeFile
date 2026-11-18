//! 视频/音频的内存数据源。
//!
//! 播放器（ExoPlayer / Media Foundation）需要可随机访问的字节流，而 `video_player`
//! 只认 URL。这里在 `127.0.0.1` 上起一个只服务一个文件、URL 带 128 位随机令牌的
//! 临时 HTTP 服务：明文只在进程内存里，磁盘上不会出现任何片段。
//!
//! 安全边界：
//! - 只绑定回环地址，外网/局域网访问不到；
//! - 令牌不可猜，`URL` 一旦随会话销毁，端口立刻关闭（线程与监听都退出）；
//! - 支持 `Range` 以便拖动进度条；响应带 `Cache-Control: no-store`，
//!   并拒绝任何路径不是本会话令牌的请求；
//! - 由界面在退出预览/切换文件时调用 [`close`]，不依赖进程退出兜底。

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crate::engine;
use crate::error::{Error, Result};
use crate::meta::FileKind;

/// 内存流的上限。短视频没问题；更长的视频请先解密到磁盘。
pub const MAX_MEDIA_BYTES: u64 = 512 * 1024 * 1024;

/// 一次内存媒体的凭据。
#[derive(Clone, Debug)]
pub struct MediaTicket {
    pub id: String,
    pub url: String,
    pub kind: String,
    pub size: u64,
}

struct Session {
    data: Arc<Vec<u8>>,
    stop: Arc<AtomicBool>,
}

static SESSIONS: OnceLock<Mutex<HashMap<String, Arc<Session>>>> = OnceLock::new();
/// Android/Linux 上从 `/proc/meminfo` 读可用内存；其它平台返回 `None`（不做限制）。
fn available_memory() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kib: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kib * 1024);
        }
    }
    None
}

fn sessions() -> &'static Mutex<HashMap<String, Arc<Session>>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 解密容器到内存，并起一个只服务它的回环 HTTP 端点。
pub fn open(container: &Path, password: &[u8]) -> Result<MediaTicket> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    // 先看大小，再看可用内存：手机上一部 200 MiB 的视频整段解进内存很容易被系统杀掉，
    // 与其闪退，不如提前给出可操作的提示。
    let head = engine::read_metadata(container, password)?;
    if head.original_size > MAX_MEDIA_BYTES {
        return Err(Error::Preview(format!(
            "视频 {} MiB 超过内存播放上限 {} MiB，请先解密到磁盘再播放",
            head.original_size / (1024 * 1024),
            MAX_MEDIA_BYTES / (1024 * 1024)
        )));
    }
    if let Some(available) = available_memory() {
        let need = head.original_size + 128 * 1024 * 1024;
        if available < need {
            return Err(Error::Preview(format!(
                "可用内存不足：播放需要约 {} MiB，当前可用 {} MiB，请先解密到磁盘再播放",
                need / (1024 * 1024),
                available / (1024 * 1024)
            )));
        }
    }
    let (meta, data) = engine::decrypt_to_vec(container, password, MAX_MEDIA_BYTES)?;
    let kind = match meta.kind {
        FileKind::Audio => "audio",
        _ => "video",
    }
    .to_string();
    let mime = meta
        .mime
        .clone()
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| guess_mime(&meta.filename, &kind));

    let token = random_token()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();

    let data = Arc::new(data);
    let stop = Arc::new(AtomicBool::new(false));
    let id = token.clone();
    let session = Arc::new(Session {
        data: data.clone(),
        stop: stop.clone(),
    });
    sessions().lock().unwrap().insert(id.clone(), session);

    let serve_data = data.clone();
    let serve_stop = stop.clone();
    let serve_token = token.clone();
    thread::Builder::new()
        .name("safefile-media".into())
        .spawn(move || serve(listener, serve_data, serve_stop, serve_token, mime))
        .map_err(|_| Error::Internal("无法启动媒体线程"))?;

    Ok(MediaTicket {
        id,
        url: format!("http://127.0.0.1:{port}/m/{token}"),
        kind,
        size: data_len(&data),
    })
}

fn data_len(data: &Arc<Vec<u8>>) -> u64 {
    data.len() as u64
}

/// 关闭会话：停止监听线程，并让数据随最后一个引用释放。
pub fn close(id: &str) {
    let removed = sessions().lock().unwrap().remove(id);
    if let Some(session) = removed {
        session.stop.store(true, Ordering::SeqCst);
    }
}

/// 进程退出前清理所有会话（FFI 卸载时用）。
pub fn close_all() {
    let mut map = sessions().lock().unwrap();
    for (_, session) in map.drain() {
        session.stop.store(true, Ordering::SeqCst);
    }
}

fn random_token() -> Result<String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|_| Error::Internal("随机数生成失败"))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

fn serve(
    listener: TcpListener,
    data: Arc<Vec<u8>>,
    stop: Arc<AtomicBool>,
    token: String,
    mime: String,
) {
    let want = format!("/m/{token}");
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let data = data.clone();
                let want = want.clone();
                let mime = mime.clone();
                thread::Builder::new()
                    .name("safefile-media-conn".into())
                    .spawn(move || {
                        let _ = handle(stream, &data, &want, &mime);
                    })
                    .ok();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(80));
            }
            Err(_) => break,
        }
    }
}

fn handle(mut stream: TcpStream, data: &[u8], want: &str, mime: &str) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut method = String::new();
    let mut path = String::new();
    let mut range: Option<(u64, u64)> = None;
    let mut budget = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        budget += line.len();
        if budget > 16 * 1024 {
            return respond(&mut stream, 431, "Too Many Headers", mime, &[], b"");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let trimmed = line.trim_end();
        if method.is_empty() {
            let mut parts = trimmed.split_whitespace();
            method = parts.next().unwrap_or("").to_string();
            path = parts.next().unwrap_or("").to_string();
            continue;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("range") {
                range = parse_range(value.trim(), data.len() as u64);
            }
        }
    }

    if method != "GET" && method != "HEAD" {
        return respond(&mut stream, 405, "Method Not Allowed", mime, &[], b"");
    }
    if path != want {
        return respond(&mut stream, 403, "Forbidden", "text/plain", &[], b"forbidden");
    }

    let total = data.len() as u64;
    let (start, end) = match range {
        Some((s, e)) => (s, e.min(total.saturating_sub(1))),
        None => (0, total.saturating_sub(1)),
    };
    if total == 0 || start > end {
        return respond(&mut stream, 416, "Range Not Satisfiable", mime, &[], b"");
    }

    let body = &data[start as usize..=end as usize];
    let partial = range.is_some();
    let mut head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nAccept-Ranges: bytes\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n",
        if partial { "206 Partial Content" } else { "200 OK" },
        mime,
        body.len()
    );
    if partial {
        head.push_str(&format!("Content-Range: bytes {start}-{end}/{total}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if method == "GET" {
        stream.write_all(body)?;
    }
    Ok(stream.flush()?)
}

fn parse_range(value: &str, total: u64) -> Option<(u64, u64)> {
    let spec = value.strip_prefix("bytes=")?;
    let first = spec.split(',').next()?.trim();
    let (a, b) = first.split_once('-')?;
    if a.is_empty() {
        // bytes=-N：末尾 N 字节
        let n: u64 = b.trim().parse().ok()?;
        if n == 0 || total == 0 {
            return None;
        }
        let n = n.min(total);
        return Some((total - n, total - 1));
    }
    let start: u64 = a.trim().parse().ok()?;
    let end = if b.trim().is_empty() {
        total.saturating_sub(1)
    } else {
        b.trim().parse().ok()?
    };
    Some((start, end))
}

fn respond(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    mime: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Result<()> {
    let mut head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    Ok(stream.flush()?)
}

fn guess_mime(name: &str, kind: &str) -> String {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mime = match ext.as_str() {
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "ogg" | "opus" => "audio/ogg",
        _ if kind == "audio" => "audio/mpeg",
        _ => "video/mp4",
    };
    mime.to_string()
}

/// 便于调用方判断是否是可流式播放的类型。
pub fn is_media_kind(kind: FileKind) -> bool {
    matches!(kind, FileKind::Video | FileKind::Audio)
}

/// 测试用：直接读取一段字节（不经过 HTTP）。
pub fn peek(id: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
    let map = sessions().lock().unwrap();
    let session = map.get(id)?;
    let mut cur = std::io::Cursor::new(session.data.as_slice());
    cur.seek(std::io::SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; len];
    let mut read = 0;
    while read < len {
        let n = cur.read(&mut buf[read..]).ok()?;
        if n == 0 {
            break;
        }
        read += n;
    }
    buf.truncate(read);
    Some(buf)
}
