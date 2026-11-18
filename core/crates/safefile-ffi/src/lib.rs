//! SafeFile C ABI：Flutter 通过 dart:ffi 调用。
//!
//! 约定：
//! - 所有返回 `*mut c_char` 的函数返回 UTF-8 JSON 字符串，调用方必须用
//!   [`sf_free_string`] 释放。
//! - JSON 统一包含 `ok: bool`；失败时附带 `code` 与 `message`（不含敏感信息）。
//! - 传入的字符串指针必须是 NUL 结尾的 UTF-8（Windows 侧由 Dart 以 UTF-8 传递，
//!   避免宽字符在 ABI 上的差异）。

use std::ffi::{c_char, c_void, CStr, CString};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use safefile_core::batch::{BatchConfig, BatchEngine, ItemKind, PerfMode};
use safefile_core::format::KdfParams;
use safefile_core::scan::{scan_paths, ScanOptions};
use safefile_core::{
    decrypt_file, encrypt_file, inspect, verify_path, DecryptOptions, EncryptOptions, Metadata,
    Result, SecretBytes,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;

mod share;
pub use share::*;

fn to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => CString::new(r#"{"ok":false,"code":"internal","message":"invalid utf8"}"#)
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut()),
    }
}

fn err_json(e: &safefile_core::Error) -> String {
    json!({ "ok": false, "code": e.code(), "message": e.to_string() }).to_string()
}

unsafe fn str_arg<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    CStr::from_ptr(p).to_str().unwrap_or("")
}

/// 释放由本库分配的字符串。
#[no_mangle]
pub unsafe extern "C" fn sf_free_string(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

#[no_mangle]
pub extern "C" fn sf_version() -> *mut c_char {
    to_c(json!({ "ok": true, "core": safefile_core::version(), "format": safefile_core::FORMAT_VERSION }).to_string())
}

/// 密码强度 0..=4。
#[no_mangle]
pub unsafe extern "C" fn sf_password_strength(password: *const c_char) -> i32 {
    let pw = str_arg(password);
    safefile_core::password_strength(pw) as i32
}

/// KDF 预设描述。
#[no_mangle]
pub unsafe extern "C" fn sf_kdf_preset(name: *const c_char) -> *mut c_char {
    let p = match str_arg(name) {
        "mobile" => KdfParams::mobile(),
        "maximum" => KdfParams::maximum(),
        _ => KdfParams::desktop(),
    };
    to_c(
        json!({
            "ok": true,
            "m_cost_kib": p.m_cost_kib,
            "t_cost": p.t_cost,
            "p_cost": p.p_cost,
            "description": p.describe(),
        })
        .to_string(),
    )
}

/// 读取容器公开信息。
#[no_mangle]
pub unsafe extern "C" fn sf_inspect(path: *const c_char) -> *mut c_char {
    let path = PathBuf::from(str_arg(path));
    match inspect(&path) {
        Ok(info) => to_c(
            json!({
                "ok": true,
                "container_size": info.container_size,
                "version": info.header.version,
                "cipher": info.cipher_name(),
                "kdf": info.kdf_name(),
                "kdf_description": info.kdf_description(),
                "m_cost_kib": info.header.kdf_params.m_cost_kib,
                "t_cost": info.header.kdf_params.t_cost,
                "p_cost": info.header.kdf_params.p_cost,
                "chunk_size": info.header.chunk_size,
                "salt_hex": info.header.salt.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            })
            .to_string(),
        ),
        Err(e) => to_c(err_json(&e)),
    }
}

/// 安全预览：解析已解密的明文文件，返回受限的结构化内容（只读、无外部程序）。
#[no_mangle]
pub unsafe extern "C" fn sf_preview(path: *const c_char, kind: *const c_char) -> *mut c_char {
    let path = PathBuf::from(str_arg(path));
    let kind = str_arg(kind);
    match safefile_core::preview_file(&path, kind) {
        Ok(doc) => to_c(json!({ "ok": true, "preview": doc }).to_string()),
        Err(e) => to_c(err_json(&e)),
    }
}

/// 单文件加密。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sf_encrypt(
    input: *const c_char,
    output: *const c_char,
    password: *const c_char,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    chunk_size: u32,
    overwrite: bool,
    delete_source: bool,
) -> *mut c_char {
    let kdf = KdfParams { m_cost_kib, t_cost, p_cost };
    let opts = EncryptOptions {
        kdf,
        chunk_size: chunk_size as usize,
        overwrite,
        store_filename: None,
        delete_source,
    };
    let res = encrypt_file(
        &PathBuf::from(str_arg(input)),
        &PathBuf::from(str_arg(output)),
        str_arg(password).as_bytes(),
        &opts,
        None,
        None,
    );
    match res {
        Ok(o) => to_c(
            json!({
                "ok": true,
                "output": o.output.to_string_lossy(),
                "plaintext_size": o.plaintext_size,
                "container_size": o.container_size,
                "source_deleted": o.source_deleted,
                "delete_error": o.delete_error,
            })
            .to_string(),
        ),
        Err(e) => to_c(err_json(&e)),
    }
}

fn meta_json(meta: &Metadata) -> serde_json::Value {
    json!({
        "filename": meta.filename,
        "original_size": meta.original_size,
        "mtime_secs": meta.mtime_secs,
        "mime": meta.mime,
        "kind": format!("{:?}", meta.kind),
    })
}

/// 单文件解密。`output` 可以是目录。
#[no_mangle]
pub unsafe extern "C" fn sf_decrypt(
    input: *const c_char,
    output: *const c_char,
    password: *const c_char,
    overwrite: bool,
    delete_source: bool,
) -> *mut c_char {
    let opts = DecryptOptions { overwrite, output_name: None, delete_source };
    match decrypt_file(
        &PathBuf::from(str_arg(input)),
        &PathBuf::from(str_arg(output)),
        str_arg(password).as_bytes(),
        &opts,
        None,
        None,
    ) {
        Ok(o) => to_c(
            json!({
                "ok": true,
                "output": o.output.to_string_lossy(),
                "plaintext_size": o.plaintext_size,
                "metadata": meta_json(&o.metadata),
                "source_deleted": o.source_deleted,
                "delete_error": o.delete_error,
            })
            .to_string(),
        ),
        Err(e) => to_c(err_json(&e)),
    }
}

/// 只校验，不落盘。
#[no_mangle]
pub unsafe extern "C" fn sf_verify(input: *const c_char, password: *const c_char) -> *mut c_char {
    match verify_path(&PathBuf::from(str_arg(input)), str_arg(password).as_bytes(), None) {
        Ok(meta) => to_c(json!({ "ok": true, "metadata": meta_json(&meta) }).to_string()),
        Err(e) => to_c(err_json(&e)),
    }
}

/// 扫描路径（JSON 数组输入），返回文件清单与跳过原因。
#[no_mangle]
pub unsafe extern "C" fn sf_scan(paths_json: *const c_char, accept_safefile_only: bool) -> *mut c_char {
    let raw = str_arg(paths_json);
    let paths: Vec<String> = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return to_c(json!({ "ok": false, "code": "bad_path", "message": "路径列表解析失败" }).to_string()),
    };
    let opts = if accept_safefile_only {
        ScanOptions::accept_extensions(&["safefile"])
    } else {
        ScanOptions::default()
    };
    let list: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    let report = scan_paths(&list, &opts);
    let files: Vec<_> = report
        .files
        .iter()
        .map(|p| {
            let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            json!({
                "path": p.to_string_lossy(),
                "name": p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
                "size": size,
            })
        })
        .collect();
    let skipped: Vec<_> = report
        .skipped
        .iter()
        .map(|s| json!({ "path": s.path.to_string_lossy(), "reason": s.reason.message() }))
        .collect();
    to_c(json!({ "ok": true, "files": files, "skipped": skipped, "total_bytes": report.total_bytes }).to_string())
}

// ---------------------------------------------------------------- 批量任务

pub struct BatchHandle {
    engine: BatchEngine,
    freed: AtomicBool,
}

/// 创建批量任务控制器，返回不透明句柄（由 Dart 持有并在结束时释放）。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sf_batch_new(
    kind: u8,
    perf: u8,
    concurrency: u32,
    overwrite: bool,
    delete_source: bool,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    chunk_size: u32,
    password: *const c_char,
) -> *mut c_void {
    let kind = if kind == 1 { ItemKind::Decrypt } else { ItemKind::Encrypt };
    let mode = match perf {
        0 => PerfMode::Eco,
        2 => PerfMode::High,
        3 => PerfMode::Custom,
        _ => PerfMode::Balanced,
    };
    let config = BatchConfig {
        kdf: KdfParams { m_cost_kib, t_cost, p_cost },
        chunk_size: chunk_size as usize,
        overwrite,
        delete_source,
        mode,
        custom_concurrency: concurrency as usize,
    };
    let engine = BatchEngine::new(kind, config, SecretBytes::new(str_arg(password).as_bytes().to_vec()));
    Box::into_raw(Box::new(BatchHandle { engine, freed: AtomicBool::new(false) })) as *mut c_void
}

unsafe fn handle<'a>(h: *mut c_void) -> Option<&'a BatchHandle> {
    if h.is_null() {
        None
    } else {
        Some(&*(h as *const BatchHandle))
    }
}

#[no_mangle]
pub unsafe extern "C" fn sf_batch_add(h: *mut c_void, source: *const c_char, dest: *const c_char, size: u64) -> u64 {
    match handle(h) {
        Some(hd) => hd.engine.add(PathBuf::from(str_arg(source)), PathBuf::from(str_arg(dest)), size),
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn sf_batch_start(h: *mut c_void) -> i32 {
    match handle(h) {
        Some(hd) => match hd.engine.start() {
            Ok(()) => 0,
            Err(_) => -1,
        },
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn sf_batch_snapshot(h: *mut c_void) -> *mut c_char {
    let Some(hd) = handle(h) else { return to_c(String::from("[]")) };
    let items: Vec<_> = hd
        .engine
        .snapshot()
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "source": s.source,
                "dest": s.dest,
                "size": s.size,
                "processed": s.processed,
                "status": s.status,
                "deleted": s.deleted,
                "error_code": s.error_code,
                "error_message": s.error_message,
            })
        })
        .collect();
    to_c(serde_json::Value::Array(items).to_string())
}

#[no_mangle]
pub unsafe extern "C" fn sf_batch_summary(h: *mut c_void) -> *mut c_char {
    let Some(hd) = handle(h) else {
        return to_c(json!({ "ok": false, "code": "internal", "message": "无效句柄" }).to_string())
    };
    let s = hd.engine.summary();
    to_c(
        json!({
            "ok": true,
            "total_items": s.total_items,
            "finished_items": s.finished_items,
            "success_items": s.success_items,
            "failed_items": s.failed_items,
            "cancelled_items": s.cancelled_items,
            "total_bytes": s.total_bytes,
            "processed_bytes": s.processed_bytes,
            "elapsed_ms": s.elapsed_ms,
            "speed_bps": s.speed_bps,
            "is_done": s.is_done,
            "is_paused": s.is_paused,
            "is_cancelled": s.is_cancelled,
            "concurrency": s.concurrency,
        })
        .to_string(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn sf_batch_pause(h: *mut c_void) {
    if let Some(hd) = handle(h) {
        hd.engine.pause();
    }
}

#[no_mangle]
pub unsafe extern "C" fn sf_batch_resume(h: *mut c_void) {
    if let Some(hd) = handle(h) {
        hd.engine.resume();
    }
}

#[no_mangle]
pub unsafe extern "C" fn sf_batch_cancel(h: *mut c_void) {
    if let Some(hd) = handle(h) {
        hd.engine.cancel();
    }
}

/// 阻塞等待全部任务结束（Dart 侧不要放在 UI isolate 调用）。
#[no_mangle]
pub unsafe extern "C" fn sf_batch_wait(h: *mut c_void) -> i32 {
    match handle(h) {
        Some(hd) => {
            hd.engine.wait();
            0
        }
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn sf_batch_free(h: *mut c_void) {
    if h.is_null() {
        return;
    }
    let boxed = Box::from_raw(h as *mut BatchHandle);
    boxed.freed.store(true, Ordering::SeqCst);
    drop(boxed);
}

// ---------------------------------------------------------------- 自检

/// 设备端自检：核心版本、KDF 耗时、加解密往返、容器布局断言。
#[no_mangle]
pub extern "C" fn sf_selftest() -> *mut c_char {
    let started = std::time::Instant::now();
    let dir = std::env::temp_dir().join(format!("safefile-selftest-{}", std::process::id()));
    if std::fs::create_dir_all(&dir).is_err() {
        return to_c(json!({ "ok": false, "code": "io", "message": "无法创建临时目录" }).to_string());
    }
    let plain = dir.join("selftest.bin");
    let ct = dir.join("selftest.bin.safefile");
    let out = dir.join("selftest.out.bin");

    let mut checks: Vec<serde_json::Value> = Vec::new();
    let mut push = |name: &str, pass: bool, detail: String| {
        checks.push(json!({ "name": name, "pass": pass, "detail": detail }));
    };

    // 1. 写入 1 MiB 测试数据
    let mut data = vec![0u8; 1024 * 1024];
    let ok = getrandom::fill(&mut data).is_ok() && std::fs::write(&plain, &data).is_ok();
    push("csprng", ok, if ok { "随机数可用".into() } else { "随机数失败".into() });

    let kdf = KdfParams::mobile();
    let t_kdf = std::time::Instant::now();
    let roundtrip = (|| -> Result<()> {
        encrypt_file(
            &plain,
            &ct,
            b"selftest",
            &EncryptOptions { kdf, chunk_size: 65536, overwrite: true, store_filename: None, delete_source: false },
            None,
            None,
        )?;
        decrypt_file(
            &ct,
            &out,
            b"selftest",
            &DecryptOptions { overwrite: true, output_name: None, delete_source: false },
            None,
            None,
        )?;
        Ok(())
    })();
    let kdf_ms = t_kdf.elapsed().as_millis() as u64;

    match roundtrip {
        Ok(()) => {
            let plain_bytes = std::fs::read(&out).unwrap_or_default();
            let same = plain_bytes == data;
            push("roundtrip", same, if same { "1 MiB 往返一致".into() } else { "内容不一致".into() });
            let container = std::fs::read(&ct).unwrap_or_default();
            let magic_ok = container.len() > 8 && &container[0..8] == b"SAFEFILE";
            push("format_magic", magic_ok, format!("容器 {} 字节", container.len()));
            // 明文不应出现在容器中
            let leak = container.windows(16).any(|w| w == &data[0..16]);
            push("no_plaintext_leak", !leak, if leak { "发现明文片段".into() } else { "未发现明文".into() });
        }
        Err(e) => {
            push("roundtrip", false, format!("{} [{}]", e, e.code()));
            push("format_magic", false, "未生成容器".into());
            push("no_plaintext_leak", false, "未生成容器".into());
        }
    }

    // 3. 错误密码必须失败
    let wrong = decrypt_file(
        &ct,
        &dir.join("wrong.bin"),
        b"wrong-password",
        &DecryptOptions { overwrite: true, output_name: None, delete_source: false },
        None,
        None,
    );
    let is_auth = matches!(wrong, Err(safefile_core::Error::AuthFailed));
    push("wrong_password_rejected", is_auth, if is_auth { "认证失败已拒绝".into() } else { "未正确拒绝".into() });

    let _ = std::fs::remove_dir_all(&dir);
    let all_pass = checks.iter().all(|c| c["pass"].as_bool().unwrap_or(false));
    to_c(
        json!({
            "ok": true,
            "all_pass": all_pass,
            "checks": checks,
            "kdf_ms": kdf_ms,
            "elapsed_ms": started.elapsed().as_millis() as u64,
            "core_version": safefile_core::version(),
            "format_version": safefile_core::FORMAT_VERSION,
        })
        .to_string(),
    )
}

/// 纯内存预览：解密与解析都在内存里完成，不写任何临时文件。
///
/// 返回的外观与 `sf_preview` 接近，但多了一个可选的 `image`（重编码后的缩略图，
/// base64）与 `media`（`video`/`audio` 时由界面改用 `sf_media_open`）。
#[no_mangle]
pub unsafe extern "C" fn sf_preview_mem(
    container: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    let path = PathBuf::from(str_arg(container));
    let pw = str_arg(password);
    match safefile_core::preview_container(&path, pw.as_bytes()) {
        Ok(out) => {
            let image = out.image.as_ref().map(|img| {
                json!({
                    "mime": img.mime,
                    "width": img.width,
                    "height": img.height,
                    "data": BASE64.encode(&img.bytes),
                })
            });
            let doc = out
                .doc
                .as_ref()
                .and_then(|d| serde_json::to_value(d).ok());
            to_c(
                json!({
                    "ok": true,
                    "preview": {
                        "name": out.name,
                        "format": out.format(),
                        "plain_len": out.plain_len,
                        "notes": out.notes,
                        "media": out.media,
                        "image": image,
                        "doc": doc,
                    }
                })
                .to_string(),
            )
        }
        Err(e) => to_c(err_json(&e)),
    }
}

/// 为视频/音频起一个只读的回环令牌端点，返回播放器可用的 URL。
#[no_mangle]
pub unsafe extern "C" fn sf_media_open(
    container: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    let path = PathBuf::from(str_arg(container));
    let pw = str_arg(password);
    match safefile_core::media::open(&path, pw.as_bytes()) {
        Ok(ticket) => to_c(
            json!({
                "ok": true,
                "id": ticket.id,
                "url": ticket.url,
                "kind": ticket.kind,
                "size": ticket.size,
            })
            .to_string(),
        ),
        Err(e) => to_c(err_json(&e)),
    }
}

/// 关闭回环令牌端点（界面退出预览或切换文件时调用）。
#[no_mangle]
pub unsafe extern "C" fn sf_media_close(id: *const c_char) -> *mut c_char {
    let id = str_arg(id);
    safefile_core::media::close(id);
    to_c(json!({ "ok": true }).to_string())
}