//! 局域网传输的端到端测试：全部走真实 TCP 回路（127.0.0.1），不 mock。
//!
//! v2 起没有配对码：接收端广播签名身份，发送端按地址/设备 id 直连，
//! 握手阶段用 Ed25519 双向认证 + X25519 派生会话密钥。

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

use safefile_core::transfer::{send_files, Progress, ShareServer};
use safefile_core::{CancelToken, Error};

fn test_root() -> PathBuf {
    std::env::var_os("SAFEFILE_TEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

/// 初始化本机节点（config 目录放在测试目录里，避免污染真实配置）。
fn init_node() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let dir = test_root().join("lan-node");
        safefile_core::lan::init(&dir, Some(0)).expect("初始化局域网节点失败");
    });
}

fn tmpdir(tag: &str) -> PathBuf {
    let mut p = test_root();
    let nonce: u32 = rand_u32();
    p.push(format!("sftransfer-{tag}-{nonce}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).unwrap();
    u32::from_le_bytes(b)
}

fn write_file(dir: &Path, name: &str, bytes: usize) -> PathBuf {
    let p = dir.join(name);
    let data: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    fs::write(&p, data).unwrap();
    p
}

/// 起一个接收端，返回 (地址, 保存目录, 进度)。
fn start_server(save: PathBuf, overwrite: bool) -> (String, PathBuf, Arc<Mutex<Progress>>) {
    init_node();
    // 每个测试用一个独立端口，避免固定端口冲突。
    let mut bound = None;
    for _ in 0..20 {
        let port = 20_000 + (rand_u32() % 40_000) as u16;
        if let Ok(server) = ShareServer::bind(save.clone(), port, overwrite, true) {
            bound = Some(server);
            break;
        }
    }
    let server = bound.expect("无法绑定测试端口");
    let addr = format!("127.0.0.1:{}", server.port());
    let progress = Arc::new(Mutex::new(Progress::default()));
    let p2 = Arc::clone(&progress);
    thread::spawn(move || {
        if let Err(e) = server.accept_one(&p2, &CancelToken::new()) {
            eprintln!("server error: {} [{}]", e, e.code());
        }
    });
    // 给监听线程一点时间进入 accept。
    thread::sleep(Duration::from_millis(120));
    (addr, save, progress)
}

#[test]
fn transfers_multiple_files_and_verifies_content() {
    let src = tmpdir("src");
    let dst = tmpdir("dst");
    let a = write_file(&src, "a.bin", 300 * 1024 + 7);
    let b = write_file(&src, "b.txt", 12);
    let (addr, save, progress) = start_server(dst.clone(), true);

    let files = vec![
        (a.clone(), "a.bin".to_string()),
        (b.clone(), "b.txt".to_string()),
    ];
    let send_progress = Arc::new(Mutex::new(Progress::default()));
    send_files(&addr, &files, &send_progress, &CancelToken::new()).unwrap();

    assert_eq!(fs::read(save.join("a.bin")).unwrap(), fs::read(&a).unwrap());
    assert_eq!(fs::read(save.join("b.txt")).unwrap(), fs::read(&b).unwrap());
    let g = progress.lock().unwrap();
    assert_eq!(g.files_total, 2);
    assert_eq!(g.files_done, 2);
    assert_eq!(g.done_bytes, g.total_bytes);
    assert!(g.error.is_none());
    assert!(g.encrypted);
    assert_eq!(g.sas.len(), 6);
    let s = send_progress.lock().unwrap();
    assert!(s.finished);
    assert!(s.error.is_none());
}

#[test]
fn garbage_handshake_is_dropped_without_touching_files() {
    let dst = tmpdir("dst2");
    let (addr, save, _progress) = start_server(dst.clone(), true);

    let mut sock = TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.write_all(b"SFTR9-not-a-hello").unwrap();
    let mut buf = [0u8; 16];
    // 服务端应当直接断开（返回 0 或报错），而不是进入文件传输。
    let n = sock.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "服务端在错误握手后仍发送了数据");
    let leftovers: Vec<_> = fs::read_dir(&save).unwrap().flatten().collect();
    assert!(leftovers.is_empty(), "错误握手不应写出任何文件");
}

#[test]
fn existing_file_is_skipped_unless_overwrite() {
    let src = tmpdir("src3");
    let dst = tmpdir("dst3");
    let a = write_file(&src, "dup.txt", 64);
    fs::write(dst.join("dup.txt"), b"old-content").unwrap();

    let (addr, save, progress) = start_server(dst.clone(), false);
    let files = vec![(a, "dup.txt".to_string())];
    send_files(
        &addr,
        &files,
        &Arc::new(Mutex::new(Progress::default())),
        &CancelToken::new(),
    )
    .unwrap();

    assert_eq!(fs::read(save.join("dup.txt")).unwrap(), b"old-content");
    assert_eq!(progress.lock().unwrap().skipped, 1);
}

#[test]
fn path_traversal_names_stay_inside_save_dir() {
    let src = tmpdir("src4");
    let dst = tmpdir("dst4");
    let a = write_file(&src, "x.txt", 32);
    let (addr, save, _progress) = start_server(dst.clone(), true);

    let files = vec![(a, "../../escaped.txt".to_string())];
    send_files(
        &addr,
        &files,
        &Arc::new(Mutex::new(Progress::default())),
        &CancelToken::new(),
    )
    .unwrap();

    assert!(save.join("escaped.txt").exists());
    assert!(!save.parent().unwrap().join("escaped.txt").exists());
}

#[test]
fn unknown_peer_id_reports_peer_not_found() {
    init_node();
    let src = tmpdir("src6");
    let a = write_file(&src, "x.bin", 16);
    let err = send_files(
        "0123456789abcdef",
        &[(a, "x.bin".to_string())],
        &Arc::new(Mutex::new(Progress::default())),
        &CancelToken::new(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::PeerNotFound(_)), "实际错误：{err:?}");
}

#[test]
fn throughput_on_loopback_is_reasonable() {
    let src = tmpdir("src5");
    let dst = tmpdir("dst5");
    let big = write_file(&src, "big.bin", 32 * 1024 * 1024);
    let (addr, save, _progress) = start_server(dst.clone(), true);

    let files = vec![(big.clone(), "big.bin".to_string())];
    let started = Instant::now();
    send_files(
        &addr,
        &files,
        &Arc::new(Mutex::new(Progress::default())),
        &CancelToken::new(),
    )
    .unwrap();
    let secs = started.elapsed().as_secs_f64();
    let got = fs::metadata(save.join("big.bin")).unwrap().len();
    assert_eq!(got, 32 * 1024 * 1024);
    let mib_s = (got as f64 / (1024.0 * 1024.0)) / secs;
    // 回路带宽下限，防止出现退化到「逐块往返」这类实现。
    assert!(mib_s > 30.0, "回路吞吐过低：{mib_s:.1} MiB/s");
    println!("回路吞吐：{mib_s:.1} MiB/s（含握手与逐帧 AEAD）");
}
