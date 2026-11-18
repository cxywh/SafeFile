//! SafeFile 命令行验证工具。
//!
//! 该工具的定位是核心引擎的验收载体：所有加密相关测试先在命令行跑通，
//! 再接入 Flutter。交互式产品界面在 app/ 下。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{Parser, Subcommand};
use safefile_core::batch::{BatchConfig, BatchEngine, ItemKind, PerfMode};
use safefile_core::format::KdfParams;
use safefile_core::scan::{scan_paths, ScanOptions};
use safefile_core::transfer::{send_files, Progress, ShareServer};
use safefile_core::{decrypt_file, encrypt_file, inspect, verify_path, CancelToken};
use safefile_core::{DecryptOptions, EncryptOptions, Result, SecretBytes};

#[derive(Parser)]
#[command(name = "safefile", version, about = "SafeFile 加密核心命令行验证工具")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 加密文件或目录
    Enc {
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// 输出文件或输出目录
        #[arg(short, long)]
        out: PathBuf,
        /// KDF 预设：desktop | mobile | maximum
        #[arg(long, default_value = "desktop")]
        kdf: String,
        /// 分块大小（字节，2 的幂，4 KiB..1 MiB）
        #[arg(long, default_value_t = 65536)]
        chunk: usize,
        /// 覆盖已存在输出
        #[arg(long)]
        overwrite: bool,
        /// 成功后删除原文件（失败/取消不删）
        #[arg(long)]
        delete_source: bool,
        /// 从环境变量读取密码
        #[arg(long)]
        password_env: Option<String>,
        /// 从标准输入读取密码（一行）
        #[arg(long)]
        password_stdin: bool,
        /// 递归处理目录
        #[arg(long, default_value_t = true)]
        recursive: bool,
    },
    /// 解密文件或目录
    Dec {
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// 输出文件或输出目录
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long)]
        overwrite: bool,
        /// 成功后删除原容器（失败/取消不删）
        #[arg(long)]
        delete_source: bool,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, default_value_t = true)]
        recursive: bool,
    },
    /// 查看容器公开信息（不需要密码）
    Info { input: PathBuf },
    /// 校验密码与完整性，不落盘
    Verify {
        input: PathBuf,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// 扫描目录，列出将被处理的文件与跳过原因
    Scan {
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },
    /// 批量加密/解密（多线程 + 汇总速度）
    Batch {
        /// enc | dec
        mode: String,
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value = "desktop")]
        kdf: String,
        /// eco | balanced | high | custom
        #[arg(long, default_value = "balanced")]
        perf: String,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        #[arg(long)]
        overwrite: bool,
        /// 成功后删除原文件（失败/取消不删）
        #[arg(long)]
        delete_source: bool,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// 局域网接收端：广播本机身份，可接收多次会话
    Serve {
        /// 保存目录
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        #[arg(long, default_value_t = 47778)]
        port: u16,
        /// 覆盖已存在文件（默认跳过）
        #[arg(long)]
        overwrite: bool,
        /// 每个文件落盘后 fsync 再改名（更安全，但受磁盘落盘速度限制）
        #[arg(long)]
        durable: bool,
        /// 接收多少个会话后退出
        #[arg(long, default_value_t = 1)]
        times: u32,
    },
    /// 向局域网接收端发送文件
    Send {
        /// 接收端设备 id、ip:port 或地址
        #[arg(long)]
        to: String,
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },
    /// 发现局域网内正在等待接收的 SafeFile 端
    Peers {
        #[arg(long, default_value_t = 2)]
        seconds: u64,
    },
    /// 解析已解密的明文文件，打印安全预览结构（调试用）
    Preview {
        path: PathBuf,
        /// 覆盖类型判断：word / excel / powerpoint / pdf / text / image ...
        #[arg(long)]
        kind: Option<String>,
        /// 是否打印正文
        #[arg(long)]
        show: bool,
    },
    /// 纯内存预览：直接从容器解密到内存再解析，校验「磁盘上没有明文」（调试用）
    PreviewMem {
        /// 加密容器（.safefile）
        container: PathBuf,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        password_stdin: bool,
        /// 是否打印正文
        #[arg(long)]
        show: bool,
        /// 是否为音视频起回环令牌端点（打印 URL 后立即关闭）
        #[arg(long)]
        media: bool,
    },
    /// 性能基准（生成临时数据，加密再解密，输出吞吐）
    Bench {
        #[arg(long, default_value_t = 64)]
        size_mb: u64,
        #[arg(long, default_value = "desktop")]
        kdf: String,
        #[arg(long, default_value_t = 65536)]
        chunk: usize,
    },
}

fn read_password(env_var: &Option<String>, stdin_flag: bool) -> String {
    if let Some(name) = env_var {
        return std::env::var(name).unwrap_or_default();
    }
    if stdin_flag {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).ok();
        return buf.lines().next().unwrap_or("").to_string();
    }
    let mut buf = String::new();
    eprint!("密码: ");
    std::io::stderr().flush().ok();
    std::io::stdin().read_line(&mut buf).ok();
    buf.trim_end_matches(['\r', '\n']).to_string()
}

fn kdf_from_name(name: &str) -> KdfParams {
    match name {
        "mobile" => KdfParams::mobile(),
        "maximum" => KdfParams::maximum(),
        _ => KdfParams::desktop(),
    }
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("错误: {} [{}]", e, e.code());
            2
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Serve { dir, port, overwrite, durable, times } => {
            use std::sync::{Arc, Mutex};
            let server = ShareServer::bind(dir.clone(), port, overwrite, durable)?;
            let info = server.info();
            let addr = info
                .addrs
                .first()
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".into());
            println!("READY {} {} {} {}", info.id, info.name, info.port, addr);
            println!(
                "设备：{}（指纹 {}）  端口：{}  保存到：{}",
                info.name,
                info.fingerprint,
                info.port,
                dir.display()
            );
            eprintln!("等待发送端连接（Ctrl+C 结束）…");
            let cancel = CancelToken::new();
            for i in 0..times.max(1) {
                let progress = Arc::new(Mutex::new(Progress::default()));
                let p2 = Arc::clone(&progress);
                match server.accept_one(&p2, &cancel) {
                    Ok(()) => {
                        let g = progress.lock().map(|x| x.clone()).unwrap_or_default();
                        let secs = (g.elapsed_ms as f64 / 1000.0).max(0.001);
                        println!(
                            "DONE {} files={}/{} bytes={} speed={:.1}MiB/s skipped={} peer={} sas={}",
                            i + 1,
                            g.files_done,
                            g.files_total,
                            g.done_bytes,
                            (g.done_bytes as f64 / (1024.0 * 1024.0)) / secs,
                            g.skipped,
                            g.peer,
                            g.sas
                        );
                    }
                    Err(e) => {
                        eprintln!("会话 {} 失败：{} [{}]", i + 1, e, e.code());
                    }
                }
            }
            Ok(())
        }
        Cmd::Send { to, inputs } => {
            use std::sync::{Arc, Mutex};
            let files: Vec<(PathBuf, String)> = inputs
                .iter()
                .map(|p| {
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unnamed".to_string());
                    (p.clone(), name)
                })
                .collect();
            for (p, _) in &files {
                if !p.exists() {
                    return Err(safefile_core::Error::BadPath(format!("不存在：{}", p.display())));
                }
            }
            let progress = Arc::new(Mutex::new(Progress::default()));
            let p2 = Arc::clone(&progress);
            let watch = std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let g = match p2.lock() {
                        Ok(g) => g.clone(),
                        Err(_) => return,
                    };
                    if g.finished {
                        break;
                    }
                    let pct = if g.total_bytes == 0 {
                        0.0
                    } else {
                        g.done_bytes as f64 * 100.0 / g.total_bytes as f64
                    };
                    eprintln!(
                        "  {:.0}%  {}/{}  文件 {}  {:.1} MiB/s",
                        pct,
                        g.files_done,
                        g.files_total,
                        g.current,
                        g.speed_bps() / (1024.0 * 1024.0)
                    );
                }
            });
            let started = std::time::Instant::now();
            send_files(&to, &files, &progress, &CancelToken::new())?;
            let _ = watch.join();
            let g = progress.lock().map(|x| x.clone()).unwrap_or_default();
            let secs = started.elapsed().as_secs_f64().max(0.001);
            println!(
                "SENT files={} bytes={} seconds={:.2} speed={:.1}MiB/s skipped={} peer={} sas={}",
                g.files_done,
                g.done_bytes,
                secs,
                (g.done_bytes as f64 / (1024.0 * 1024.0)) / secs,
                g.skipped,
                g.peer,
                g.sas
            );
            Ok(())
        }
        Cmd::Peers { seconds } => {
            let node = safefile_core::lan::global()?;
            node.probe();
            std::thread::sleep(std::time::Duration::from_secs(seconds));
            let peers = node.peers();
            if peers.is_empty() {
                println!("未发现设备");
            }
            for p in peers {
                println!("PEER {} {} {} {}", p.id, p.addr, p.name, p.fingerprint);
            }
            Ok(())
        }
        Cmd::Preview { path, kind, show } => {
            let kind = kind.unwrap_or_default();
            let doc = safefile_core::preview_file(&path, &kind)?;
            println!(
                "format={} chars={} sheets={} slides={} pdf_pages={} truncated={}",
                doc.format,
                (doc.text.as_deref().map(|t| t.chars().count()).unwrap_or(0)
                        + doc.pdf_pages.iter().map(|p| p.chars().count()).sum::<usize>()),
                doc.sheets.len(),
                doc.slides.len(),
                doc.pdf_pages.len(),
                doc.truncated
            );
            for n in &doc.notes {
                println!("note: {n}");
            }
            for s in &doc.sheets {
                println!("sheet: {} rows={} truncated={}", s.name, s.rows.len(), s.truncated);
            }
            for s in &doc.slides {
                println!("slide {}: {}", s.index, s.title);
            }
            for (i, p) in doc.pdf_pages.iter().enumerate() {
                println!("page {}: {} chars", i + 1, p.chars().count());
            }
            if show {
                if let Some(t) = &doc.text {
                    println!("--- text ---\n{t}");
                }
                for (i, p) in doc.pdf_pages.iter().enumerate() {
                    println!("--- page {} ---\n{p}", i + 1);
                }
                for s in &doc.sheets {
                    println!("--- sheet {} ---", s.name);
                    for row in &s.rows {
                        println!("{}", row.join(" | "));
                    }
                }
            }
            Ok(())
        }
        Cmd::PreviewMem { container, password_env, password_stdin, show, media } => {
            let password = read_password(&password_env, password_stdin);
            let out = safefile_core::preview_mem::preview_container(&container, password.as_bytes())?;
            println!(
                "format={} plain_bytes={} name={} notes={}",
                out.format(),
                out.plain_len,
                out.name,
                out.notes.len()
            );
            for n in &out.notes {
                println!("note: {n}");
            }
            if let Some(img) = &out.image {
                println!("image: {} {}x{} bytes={}", img.mime, img.width, img.height, img.bytes.len());
            }
            if let Some(kind) = &out.media {
                println!("media: {kind}");
                if media {
                    match safefile_core::media::open(&container, password.as_bytes()) {
                        Ok(ticket) => {
                            println!("ticket: {} {} bytes={}", ticket.url, ticket.kind, ticket.size);
                            safefile_core::media::close(&ticket.id);
                            println!("ticket: closed");
                        }
                        Err(e) => println!("ticket error: {e}"),
                    }
                }
            }
            if let Some(doc) = &out.doc {
                println!(
                    "doc format={} chars={} sheets={} slides={} pdf_pages={} truncated={}",
                    doc.format,
                    (doc.text.as_deref().map(|t| t.chars().count()).unwrap_or(0)
                        + doc.pdf_pages.iter().map(|p| p.chars().count()).sum::<usize>()),
                    doc.sheets.len(),
                    doc.slides.len(),
                    doc.pdf_pages.len(),
                    doc.truncated
                );
                if show {
                    if let Some(t) = &doc.text {
                        println!("--- text ---\n{t}");
                    }
                    for s in &doc.sheets {
                        println!("--- sheet {} ---", s.name);
                        for row in &s.rows {
                            println!("{}", row.join(" | "));
                        }
                    }
                    for (i, p) in doc.pdf_pages.iter().enumerate() {
                        println!("--- page {} ---\n{p}", i + 1);
                    }
                }
            }
            Ok(())
        }
        Cmd::Enc { inputs, out, kdf, chunk, overwrite, delete_source, password_env, password_stdin, recursive } => {
            let password = read_password(&password_env, password_stdin);
            if password.is_empty() {
                return Err(safefile_core::Error::EmptyPassword);
            }
            crypt_many(
                &inputs,
                &out,
                &password,
                true,
                KdfParams::from(kdf_from_name(&kdf)),
                chunk,
                overwrite,
                delete_source,
                recursive,
            )
        }
        Cmd::Dec { inputs, out, overwrite, delete_source, password_env, password_stdin, recursive } => {
            let password = read_password(&password_env, password_stdin);
            if password.is_empty() {
                return Err(safefile_core::Error::EmptyPassword);
            }
            crypt_many(&inputs, &out, &password, false, KdfParams::desktop(), 65536, overwrite, delete_source, recursive)
        }
        Cmd::Info { input } => {
            let info = inspect(&input)?;
            println!("文件             : {}", input.display());
            println!("容器大小         : {} 字节", info.container_size);
            println!("格式版本         : {}", info.header.version);
            println!("加密算法         : {}", info.cipher_name());
            println!("密钥派生         : {}（{}）", info.kdf_name(), info.kdf_description());
            println!("分块大小         : {} 字节", info.header.chunk_size);
            println!("Salt (hex)       : {}", hex(&info.header.salt));
            println!("块额外开销       : 17 字节/块，元数据块外加 4096 字节区");
            println!(
                "明文大小估算     : {} 字节",
                info.container_size.saturating_sub(88 + (4096 + 17) as u64)
            );
            Ok(())
        }
        Cmd::Verify { input, password_env, password_stdin } => {
            let password = read_password(&password_env, password_stdin);
            let meta = verify_path(&input, password.as_bytes(), None)?;
            println!("校验通过：{}（{} 字节，类型 {:?}）", meta.filename, meta.original_size, meta.kind);
            Ok(())
        }
        Cmd::Scan { inputs } => {
            let report = scan_paths(&inputs, &ScanOptions::default());
            println!("待处理文件 {} 个，合计 {} 字节", report.files.len(), report.total_bytes);
            for f in &report.files {
                println!("  + {}", f.display());
            }
            if !report.skipped.is_empty() {
                println!("跳过 {} 项：", report.skipped.len());
                for s in &report.skipped {
                    println!("  - {} （{}）", s.path.display(), s.reason.message());
                }
            }
            Ok(())
        }
        Cmd::Batch { mode, inputs, out, kdf, perf, concurrency, overwrite, delete_source, password_env, password_stdin } => {
            let password = read_password(&password_env, password_stdin);
            if password.is_empty() {
                return Err(safefile_core::Error::EmptyPassword);
            }
            let kind = match mode.as_str() {
                "dec" => ItemKind::Decrypt,
                "enc" => ItemKind::Encrypt,
                other => return Err(safefile_core::Error::BadPath(format!("未知模式：{other}"))),
            };
            let perf_mode = match perf.as_str() {
                "eco" => PerfMode::Eco,
                "high" => PerfMode::High,
                "custom" => PerfMode::Custom,
                _ => PerfMode::Balanced,
            };
            let exts: Vec<&str> = if kind == ItemKind::Decrypt { vec!["safefile"] } else { vec![] };
            let scan_opts = if exts.is_empty() {
                ScanOptions::default()
            } else {
                ScanOptions::accept_extensions(&exts)
            };
            let report = scan_paths(&inputs, &scan_opts);
            let engine = BatchEngine::new(
                kind,
                BatchConfig {
                    kdf: kdf_from_name(&kdf),
                    chunk_size: 65536,
                    overwrite,
                    delete_source,
                    mode: perf_mode,
                    custom_concurrency: concurrency,
                },
                SecretBytes::new(password.into_bytes()),
            );
            for f in &report.files {
                let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("file");
                let dest = if kind == ItemKind::Encrypt {
                    out.join(format!("{}.safefile", name))
                } else {
                    out.join(name.trim_end_matches(".safefile"))
                };
                let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
                engine.add(f.clone(), dest, size);
            }
            println!("并发 {}", engine.concurrency());
            let started = Instant::now();
            engine.start()?;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(200));
                let s = engine.summary();
                eprint!(
                    "\r完成 {}/{}  失败 {}  已处理 {:.1} MiB  {:.1} MiB/s   ",
                    s.finished_items,
                    s.total_items,
                    s.failed_items,
                    s.processed_bytes as f64 / 1_048_576.0,
                    s.speed_bps as f64 / 1_048_576.0
                );
                if s.is_done {
                    break;
                }
            }
            engine.wait();
            let s = engine.summary();
            eprintln!();
            println!(
                "总计 {} 项，成功 {}，失败 {}，用时 {:.2}s，速度 {:.1} MiB/s，并发 {}",
                s.total_items,
                s.success_items,
                s.failed_items,
                started.elapsed().as_secs_f64(),
                s.speed_bps as f64 / 1_048_576.0,
                s.concurrency
            );
            for item in engine.snapshot() {
                if item.status == "failed" {
                    println!("  失败: {} -> {:?}", item.source, item.error_message);
                }
            }
            Ok(())
        }
        Cmd::Bench { size_mb, kdf, chunk } => bench(size_mb, kdf_from_name(&kdf), chunk),
    }
}

#[allow(clippy::too_many_arguments)]
fn crypt_many(
    inputs: &[PathBuf],
    out: &Path,
    password: &str,
    encrypt: bool,
    kdf: KdfParams,
    chunk: usize,
    overwrite: bool,
    delete_source: bool,
    recursive: bool,
) -> Result<()> {
    let scan_opts = if encrypt {
        ScanOptions { recursive, ..Default::default() }
    } else {
        let mut o = ScanOptions::accept_extensions(&["safefile"]);
        o.recursive = recursive;
        o
    };
    let report = scan_paths(inputs, &scan_opts);
    if report.files.is_empty() {
        return Err(safefile_core::Error::BadPath("没有可处理的文件".into()));
    }
    if report.files.len() > 1 && !(out.exists() && out.is_dir()) {
        std::fs::create_dir_all(out)?;
    }

    let cancel = CancelToken::new();
    let mut failures = 0usize;
    let mut total_bytes = 0u64;
    let started = Instant::now();
    for src in &report.files {
        let name = src.file_name().and_then(|n| n.to_str()).unwrap_or("file");
        let dest: PathBuf = if encrypt {
            if out.is_dir() || report.files.len() > 1 {
                out.join(format!("{}.safefile", name))
            } else {
                out.to_path_buf()
            }
        } else if out.is_dir() || report.files.len() > 1 {
            // 目录输出：交给引擎按元数据还原原始文件名（含安全收敛）
            out.to_path_buf()
        } else {
            out.to_path_buf()
        };
        let last_report = std::sync::Mutex::new(Instant::now());
        let progress = |done: u64, total: u64| {
            if let Ok(mut t) = last_report.lock() {
                if t.elapsed().as_millis() >= 200 || done == total {
                    eprint!("\r{}: {}/{} 字节   ", name, done, total);
                    let _ = std::io::stderr().flush();
                    *t = Instant::now();
                }
            }
        };
        let res = if encrypt {
            encrypt_file(
                src,
                &dest,
                password.as_bytes(),
                &EncryptOptions { kdf, chunk_size: chunk, overwrite, store_filename: None, delete_source },
                Some(&progress),
                Some(&cancel),
            )
            .map(|o| {
                total_bytes += o.plaintext_size;
                println!(
                    "加密完成: {} -> {}（{} 字节 -> {} 字节）",
                    src.display(),
                    o.output.display(),
                    o.plaintext_size,
                    o.container_size
                );
            })
        } else {
            decrypt_file(
                src,
                &dest,
                password.as_bytes(),
                &DecryptOptions { overwrite, output_name: None, delete_source },
                Some(&progress),
                Some(&cancel),
            )
            .map(|o| {
                total_bytes += o.plaintext_size;
                println!(
                    "解密完成: {} -> {}（{} 字节，原始名 {}）",
                    src.display(),
                    o.output.display(),
                    o.plaintext_size,
                    o.metadata.filename
                );
            })
        };
        if let Err(e) = res {
            failures += 1;
            eprintln!("\n失败: {} - {} [{}]", src.display(), e, e.code());
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "处理 {} 个文件，失败 {}，累计 {} 字节，用时 {:.2}s，{:.1} MiB/s",
        report.files.len(),
        failures,
        total_bytes,
        elapsed,
        (total_bytes as f64 / 1_048_576.0) / elapsed.max(0.001)
    );
    if failures > 0 {
        return Err(safefile_core::Error::Internal("部分文件处理失败"));
    }
    Ok(())
}

fn bench(size_mb: u64, kdf: KdfParams, chunk: usize) -> Result<()> {
    let dir = std::env::temp_dir().join("safefile-bench");
    std::fs::create_dir_all(&dir)?;
    let plain = dir.join("bench.bin");
    let enc = dir.join("bench.bin.safefile");
    let dec = dir.join("bench.out.bin");
    let _ = std::fs::remove_file(&enc);
    let _ = std::fs::remove_file(&dec);

    let mut f = std::fs::File::create(&plain)?;
    let mut remaining = size_mb * 1024 * 1024;
    let mut buf = vec![0u8; 1024 * 1024];
    getrandom::fill(&mut buf).map_err(|_| safefile_core::Error::Internal("随机数失败"))?;
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        f.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    drop(f);

    let mut t = Instant::now();
    let key = safefile_core::derive_key(b"bench-password", &[7u8; 32], &kdf)?;
    let kdf_ms = t.elapsed().as_secs_f64() * 1000.0;
    let _ = key;
    t = Instant::now();
    let eo = encrypt_file(
        &plain,
        &enc,
        b"bench-password",
        &EncryptOptions { kdf, chunk_size: chunk, overwrite: true, store_filename: None, delete_source: false },
        None,
        None,
    )?;
    let enc_s = t.elapsed().as_secs_f64();
    t = Instant::now();
    // 解密含一次 KDF
    let do_ = decrypt_file(&enc, &dec, b"bench-password", &DecryptOptions { overwrite: true, output_name: None, delete_source: false }, None, None)?;
    let dec_s = t.elapsed().as_secs_f64();

    println!("数据量       : {} MiB（分块 {} KiB，KDF {}）", size_mb, chunk / 1024, kdf.describe());
    println!("KDF 单次耗时 : {:.0} ms", kdf_ms);
    println!(
        "加密         : {:.2}s  {:.1} MiB/s（含 KDF）  容器 {} 字节",
        enc_s,
        (eo.plaintext_size as f64 / 1_048_576.0) / enc_s.max(0.001),
        eo.container_size
    );
    println!(
        "解密         : {:.2}s  {:.1} MiB/s（含 KDF）  明文 {} 字节",
        dec_s,
        (do_.plaintext_size as f64 / 1_048_576.0) / dec_s.max(0.001),
        do_.plaintext_size
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[allow(dead_code)]
fn read_all(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut v = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut v)?;
    Ok(v)
}
