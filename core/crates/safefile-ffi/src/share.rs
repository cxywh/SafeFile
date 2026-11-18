//! 局域网共享的 C ABI（v2：无配对码）。
//!
//! 约定与加密接口一致：返回值是 UTF-8 JSON，调用方用 `sf_free_string` 释放。
//! 收/发都在独立线程里跑，Dart 侧通过 `*_poll` 拿快照，UI 不会被网络阻塞。

use std::ffi::{c_char, c_void};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use safefile_core::transfer::{send_files, Progress, ShareInfo, ShareServer};
use safefile_core::{lan, CancelToken, Verdict};

use crate::{err_json, str_arg, to_c};

fn progress_json(p: &Progress, extra: serde_json::Value) -> String {
    let mut obj = serde_json::json!({
        "ok": true,
        "files_total": p.files_total,
        "files_done": p.files_done,
        "total_bytes": p.total_bytes,
        "done_bytes": p.done_bytes,
        "current": p.current,
        "skipped": p.skipped,
        "finished": p.finished,
        "error": p.error,
        "elapsed_ms": p.elapsed_ms,
        "speed_bps": p.speed_bps(),
        "peer": p.peer,
        "peer_id": p.peer_id,
        "sas": p.sas,
        "encrypted": p.encrypted,
    });
    if let (Some(map), Some(extra_map)) = (obj.as_object_mut(), extra.as_object()) {
        for (k, v) in extra_map {
            map.insert(k.clone(), v.clone());
        }
    }
    obj.to_string()
}

fn trust_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Trusted => "trusted",
        Verdict::New => "new",
        Verdict::Changed => "changed",
    }
}

fn peers_json() -> String {
    let node = match lan::global() {
        Ok(n) => n,
        Err(e) => return err_json(&e),
    };
    let list: Vec<serde_json::Value> = node
        .peers()
        .into_iter()
        .map(|p| {
            let pk = safefile_core::identity::hex_decode(&p.public_key).and_then(|b| {
                if b.len() == 32 {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&b);
                    Some(out)
                } else {
                    None
                }
            });
            let trust = pk
                .map(|k| trust_label(node.trust_verdict(&p.id, &k)))
                .unwrap_or("new");
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "addr": p.addr,
                "fingerprint": p.fingerprint,
                "accepting": p.accepting,
                "last_seen_ms": p.last_seen_ms,
                "trust": trust,
            })
        })
        .collect();
    serde_json::json!({ "ok": true, "peers": list }).to_string()
}

/// 初始化本机局域网节点（幂等）。`config_dir` 用来保存身份与信任库。
///
/// # Safety
/// `config_dir` 必须是 NUL 结尾的 UTF-8 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn sf_lan_init(
    config_dir: *const c_char,
    discovery_port: u16,
) -> *mut c_char {
    let dir = str_arg(config_dir).to_string();
    if dir.trim().is_empty() {
        return to_c(err_json(&safefile_core::Error::Internal(
            "配置目录不能为空",
        )));
    }
    let port = if discovery_port == 0 {
        lan::DISCOVERY_PORT
    } else {
        discovery_port
    };
    match lan::init(std::path::Path::new(&dir), Some(port)) {
        Ok(_) => to_c(lan_status_json()),
        Err(e) => to_c(err_json(&e)),
    }
}

fn lan_status_json() -> String {
    match lan::global() {
        Ok(node) => {
            let s = node.status();
            serde_json::json!({
                "ok": true,
                "id": s.id,
                "name": s.name,
                "fingerprint": s.fingerprint,
                "public_key": s.public_key,
                "port": s.port,
                "discovery_port": s.discovery_port,
                "addrs": s.addrs,
                "accepting": s.accepting,
                "discovery_ok": s.discovery_ok,
                "discovery_error": s.discovery_error,
                "trusted_peer_count": s.trusted_peer_count,
                "peer_count": s.peer_count,
            })
            .to_string()
        }
        Err(e) => err_json(&e),
    }
}

/// 本机节点状态（名字、id、指纹、地址、发现端口）。
#[no_mangle]
pub extern "C" fn sf_lan_status() -> *mut c_char {
    to_c(lan_status_json())
}

/// 当前看到的设备列表（含信任状态）。
#[no_mangle]
pub extern "C" fn sf_lan_peers() -> *mut c_char {
    to_c(peers_json())
}

/// 立刻发一次探测并返回当前列表（结果仍可能稍后补齐）。
#[no_mangle]
pub extern "C" fn sf_lan_refresh() -> *mut c_char {
    if let Ok(node) = lan::global() {
        node.probe();
    }
    to_c(peers_json())
}

/// 接收端句柄。会话信息直接挂在句柄上，避免跨线程共享全局表。
pub struct ShareHandle {
    server: Arc<ShareServer>,
    info: ShareInfo,
    progress: Arc<Mutex<Progress>>,
    cancel: CancelToken,
    stop: Arc<AtomicBool>,
    sessions: Arc<AtomicU64>,
    last_error: Arc<Mutex<Option<String>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// 发送端句柄。
pub struct SendHandle {
    progress: Arc<Mutex<Progress>>,
    cancel: CancelToken,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// 启动接收端并立即监听。`port = 0` 使用固定端口 47778。
///
/// # Safety
/// `save_dir` 必须是 NUL 结尾的 UTF-8 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn sf_share_start(
    save_dir: *const c_char,
    port: u16,
    overwrite: bool,
    durable: bool,
) -> *mut c_void {
    let dir = str_arg(save_dir).to_string();
    if dir.trim().is_empty() {
        return std::ptr::null_mut();
    }
    let server = match ShareServer::bind(PathBuf::from(dir), port, overwrite, durable) {
        Ok(s) => Arc::new(s),
        Err(_) => return std::ptr::null_mut(),
    };
    let info = server.info();
    let progress = Arc::new(Mutex::new(Progress::default()));
    let cancel = CancelToken::new();
    let stop = Arc::new(AtomicBool::new(false));
    let sessions = Arc::new(AtomicU64::new(0));
    let last_error = Arc::new(Mutex::new(None));

    let srv = Arc::clone(&server);
    let p2 = Arc::clone(&progress);
    let c2 = cancel.clone();
    let s2 = Arc::clone(&stop);
    let n2 = Arc::clone(&sessions);
    let e2 = Arc::clone(&last_error);
    let t = std::thread::spawn(move || {
        while !s2.load(Ordering::Relaxed) {
            match srv.accept_once_timeout(&p2, &c2, Duration::from_millis(200)) {
                Ok(true) => {
                    n2.fetch_add(1, Ordering::Relaxed);
                }
                Ok(false) => {}
                Err(safefile_core::Error::Cancelled) => {}
                Err(e) => {
                    if let Ok(mut g) = e2.lock() {
                        *g = Some(format!("{} [{}]", e, e.code()));
                    }
                }
            }
        }
    });

    let handle = Box::new(ShareHandle {
        server,
        info,
        progress,
        cancel,
        stop,
        sessions,
        last_error,
        thread: Mutex::new(Some(t)),
    });
    Box::into_raw(handle) as *mut c_void
}

/// 接收端信息：名字、id、指纹、端口、本机地址。
///
/// # Safety
/// `h` 必须是 `sf_share_start` 的返回值。
#[no_mangle]
pub unsafe extern "C" fn sf_share_info(h: *mut c_void) -> *mut c_char {
    if h.is_null() {
        return to_c(err_json(&safefile_core::Error::Internal("句柄为空")));
    }
    let handle = &*(h as *const ShareHandle);
    to_c(
        serde_json::json!({
            "ok": true,
            "name": handle.info.name,
            "id": handle.info.id,
            "fingerprint": handle.info.fingerprint,
            "port": handle.info.port,
            "addrs": handle.info.addrs,
        })
        .to_string(),
    )
}

/// 接收进度快照。
///
/// # Safety
/// `h` 必须是 `sf_share_start` 的返回值。
#[no_mangle]
pub unsafe extern "C" fn sf_share_poll(h: *mut c_void) -> *mut c_char {
    if h.is_null() {
        return to_c(err_json(&safefile_core::Error::Internal("句柄为空")));
    }
    let handle = &*(h as *const ShareHandle);
    let snap = handle.progress.lock().map(|g| g.clone()).unwrap_or_default();
    let reason = handle.last_error.lock().ok().and_then(|g| g.clone());
    to_c(progress_json(
        &snap,
        serde_json::json!({
            "sessions": handle.sessions.load(Ordering::Relaxed),
            "running": !handle.stop.load(Ordering::Relaxed),
            "reason": reason,
        }),
    ))
}

/// 停止接收并释放句柄（阻塞到接收线程退出）。
///
/// # Safety
/// `h` 必须是 `sf_share_start` 的返回值，且只能释放一次。
#[no_mangle]
pub unsafe extern "C" fn sf_share_free(h: *mut c_void) {
    if h.is_null() {
        return;
    }
    let boxed = Box::from_raw(h as *mut ShareHandle);
    boxed.stop.store(true, Ordering::Relaxed);
    boxed.cancel.cancel();
    boxed.server.stop();
    let thread = boxed.thread.lock().ok().and_then(|mut g| g.take());
    drop(boxed);
    if let Some(t) = thread {
        let _ = t.join();
    }
}

/// 发送文件。`paths_json` 是 JSON 字符串数组（绝对路径）。
///
/// # Safety
/// 两个入参都必须是 NUL 结尾的 UTF-8 指针。
#[no_mangle]
pub unsafe extern "C" fn sf_send_start(
    peer: *const c_char,
    paths_json: *const c_char,
) -> *mut c_void {
    let peer = str_arg(peer).to_string();
    let paths: Vec<String> = match serde_json::from_str(str_arg(paths_json)) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };
    if peer.is_empty() || paths.is_empty() {
        return std::ptr::null_mut();
    }
    let files: Vec<(PathBuf, String)> = paths
        .into_iter()
        .map(|p| {
            let name = PathBuf::from(&p)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unnamed".into());
            (PathBuf::from(p), name)
        })
        .collect();

    let progress = Arc::new(Mutex::new(Progress::default()));
    let cancel = CancelToken::new();
    let p2 = Arc::clone(&progress);
    let c2 = cancel.clone();
    let t = std::thread::spawn(move || {
        let outcome = send_files(&peer, &files, &p2, &c2);
        if let Ok(mut g) = p2.lock() {
            if let Err(e) = outcome {
                g.error = Some(format!("{} [{}]", e, e.code()));
            }
            g.finished = true;
        }
    });

    let handle = Box::new(SendHandle {
        progress,
        cancel,
        thread: Mutex::new(Some(t)),
    });
    Box::into_raw(handle) as *mut c_void
}

/// 发送进度快照。
///
/// # Safety
/// `h` 必须是 `sf_send_start` 的返回值。
#[no_mangle]
pub unsafe extern "C" fn sf_send_poll(h: *mut c_void) -> *mut c_char {
    if h.is_null() {
        return to_c(err_json(&safefile_core::Error::Internal("句柄为空")));
    }
    let handle = &*(h as *const SendHandle);
    let snap = handle.progress.lock().map(|g| g.clone()).unwrap_or_default();
    let running = handle.thread.lock().map(|g| g.is_some()).unwrap_or(false) && !snap.finished;
    to_c(progress_json(&snap, serde_json::json!({ "running": running })))
}

/// 取消发送。
///
/// # Safety
/// `h` 必须是 `sf_send_start` 的返回值。
#[no_mangle]
pub unsafe extern "C" fn sf_send_cancel(h: *mut c_void) {
    if h.is_null() {
        return;
    }
    let handle = &*(h as *const SendHandle);
    handle.cancel.cancel();
}

/// 释放发送句柄（等待线程收尾）。
///
/// # Safety
/// `h` 必须是 `sf_send_start` 的返回值，且只能释放一次。
#[no_mangle]
pub unsafe extern "C" fn sf_send_free(h: *mut c_void) {
    if h.is_null() {
        return;
    }
    let boxed = Box::from_raw(h as *mut SendHandle);
    boxed.cancel.cancel();
    let thread = boxed.thread.lock().ok().and_then(|mut g| g.take());
    drop(boxed);
    if let Some(t) = thread {
        let _ = t.join();
    }
}

/// 本机 IPv4 地址，供接收页展示。
#[no_mangle]
pub extern "C" fn sf_local_addrs() -> *mut c_char {
    to_c(serde_json::json!({ "ok": true, "addrs": lan::local_addrs() }).to_string())
}

/// 本机身份公钥指纹（UI 展示用）。
#[no_mangle]
pub extern "C" fn sf_lan_fingerprint() -> *mut c_char {
    match lan::global() {
        Ok(node) => to_c(
            serde_json::json!({
                "ok": true,
                "name": node.name(),
                "id": node.id(),
                "fingerprint": node.identity().fingerprint,
            })
            .to_string(),
        ),
        Err(e) => to_c(err_json(&e)),
    }
}
