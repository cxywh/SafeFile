//! 加密核心集成测试：格式、篡改、截断、原子性、并发批量。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use safefile_core::batch::{BatchConfig, BatchEngine, ItemKind, PerfMode};
use safefile_core::format::{
    KdfParams, CHUNK_TAG_OVERHEAD, MAGIC, META_BLOCK_LEN, PREFIX_LEN,
};
use safefile_core::meta::{sanitize_filename, Metadata};
use safefile_core::{
    decrypt_file, encrypt_file, inspect, verify_path, CancelToken, DecryptOptions, EncryptOptions,
    Error, SecretBytes,
};

/// 测试用 KDF 参数：故意取最小合法值，保证测试快。
fn fast_kdf() -> KdfParams {
    KdfParams { m_cost_kib: 8 * 1024, t_cost: 1, p_cost: 1 }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::var_os("SAFEFILE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = root.join(format!("safefile-test-{}-{}-{}", tag, std::process::id(), n));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn entries(&self) -> Vec<String> {
        fs::read_dir(&self.0)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_pattern(path: &Path, size: usize) -> Vec<u8> {
    let data: Vec<u8> = (0..size).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    fs::write(path, &data).unwrap();
    data
}

fn roundtrip(tag: &str, size: usize, chunk: usize) {
    let dir = TempDir::new(tag);
    let plain = dir.file("input.bin");
    let ct = dir.file("input.bin.safefile");
    let out = dir.file("out.bin");
    let data = write_pattern(&plain, size);

    let eo = encrypt_file(
        &plain,
        &ct,
        b"correct horse battery staple",
        &EncryptOptions { kdf: fast_kdf(), chunk_size: chunk, overwrite: false, store_filename: None, delete_source: false },
        None,
        None,
    )
    .unwrap();
    assert_eq!(eo.plaintext_size, size as u64);
    // 容器 = 前缀 + 元数据块 + 数据块 + 结束块
    let payload = if size == 0 {
        CHUNK_TAG_OVERHEAD
    } else {
        let full = size / chunk;
        let rem = size % chunk;
        full * (chunk + CHUNK_TAG_OVERHEAD) + if rem > 0 { rem + CHUNK_TAG_OVERHEAD } else { 0 }
    };
    assert_eq!(
        eo.container_size as usize,
        PREFIX_LEN + META_BLOCK_LEN + CHUNK_TAG_OVERHEAD + payload,
        "容器大小不符合格式定义"
    );

    let do_ = decrypt_file(&ct, &out, b"correct horse battery staple", &DecryptOptions::default(), None, None).unwrap();
    assert_eq!(do_.plaintext_size, size as u64);
    assert_eq!(fs::read(&out).unwrap(), data, "往返内容不一致（size={size}, chunk={chunk}）");
    assert_eq!(do_.metadata.filename, "input.bin");
    assert_eq!(do_.metadata.original_size, size as u64);
    // 原始文件仍在
    assert!(plain.exists());
}

#[test]
fn empty_file_roundtrip() {
    roundtrip("empty", 0, 65536);
}

#[test]
fn tiny_file_roundtrip() {
    roundtrip("1k", 1024, 65536);
}

#[test]
fn exactly_one_chunk_boundary() {
    roundtrip("exact", 4096, 4096);
}

#[test]
fn chunk_plus_one_boundary() {
    roundtrip("plus1", 4097, 4096);
}

#[test]
fn multi_chunk_with_4k_blocks() {
    roundtrip("4k", 100_000, 4096);
}

#[test]
fn large_blocks_1mib() {
    roundtrip("1m", 3 * 1024 * 1024 + 12345, 1024 * 1024);
}

#[test]
fn unicode_filename_and_metadata() {
    let dir = TempDir::new("unicode");
    let plain = dir.file("中文报告 ①—テスト.pdf");
    fs::write(&plain, b"hello unicode").unwrap();
    let ct = dir.file("report.safefile");
    let pw = "pw-中文-123".as_bytes();
    encrypt_file(&plain, &ct, pw, &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap();

    let target_dir = dir.file("restore");
    fs::create_dir_all(&target_dir).unwrap();
    let out = decrypt_file(&ct, &target_dir, pw, &DecryptOptions::default(), None, None).unwrap();
    assert_eq!(out.metadata.filename, "中文报告 ①—テスト.pdf");
    assert_eq!(out.output.file_name().unwrap().to_string_lossy(), "中文报告 ①—テスト.pdf");
    assert_eq!(fs::read(&out.output).unwrap(), b"hello unicode");
}

#[test]
fn wrong_password_fails_and_leaves_no_output() {
    let dir = TempDir::new("wrongpw");
    let plain = dir.file("a.txt");
    fs::write(&plain, b"secret data").unwrap();
    let ct = dir.file("a.txt.safefile");
    encrypt_file(&plain, &ct, b"right", &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap();
    let out = dir.file("a.txt.out");
    let err = decrypt_file(&ct, &out, b"wrong", &DecryptOptions::default(), None, None).unwrap_err();
    assert!(matches!(err, Error::AuthFailed), "实际错误：{err:?}");
    assert!(!out.exists(), "失败后不应留下输出文件");
    assert!(!dir.entries().iter().any(|n| n.contains("sfpart")), "临时文件必须清理");
}

#[test]
fn tampered_ciphertext_detected() {
    let dir = TempDir::new("tamper-ct");
    let plain = dir.file("a.bin");
    write_pattern(&plain, 50_000);
    let ct = dir.file("a.bin.safefile");
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), chunk_size: 4096, ..Default::default() }, None, None).unwrap();

    let mut bytes = fs::read(&ct).unwrap();
    let idx = PREFIX_LEN + META_BLOCK_LEN + CHUNK_TAG_OVERHEAD + 100; // 落在第一个数据块内
    bytes[idx] ^= 0x01;
    let bad = dir.file("bad.safefile");
    fs::write(&bad, &bytes).unwrap();

    let err = decrypt_file(&bad, &dir.file("bad.out"), b"pw", &DecryptOptions::default(), None, None).unwrap_err();
    assert!(matches!(err, Error::AuthFailed), "实际错误：{err:?}");
}

#[test]
fn tampered_header_salt_detected() {
    let dir = TempDir::new("tamper-salt");
    let plain = dir.file("a.bin");
    write_pattern(&plain, 10_000);
    let ct = dir.file("a.bin.safefile");
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap();

    let mut bytes = fs::read(&ct).unwrap();
    bytes[30] ^= 0x80; // salt 区域
    let bad = dir.file("bad.safefile");
    fs::write(&bad, &bytes).unwrap();
    let err = decrypt_file(&bad, &dir.file("o"), b"pw", &DecryptOptions::default(), None, None).unwrap_err();
    assert!(matches!(err, Error::AuthFailed), "实际错误：{err:?}");
}

#[test]
fn tampered_kdf_params_rejected() {
    let dir = TempDir::new("tamper-kdf");
    let plain = dir.file("a.bin");
    write_pattern(&plain, 1000);
    let ct = dir.file("a.bin.safefile");
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap();

    let mut bytes = fs::read(&ct).unwrap();
    // 把 m_cost 改成 4 GiB（超出上限，必须在派生之前被拒绝）
    bytes[12..16].copy_from_slice(&(4u32 * 1024 * 1024).to_le_bytes());
    let bad = dir.file("bad.safefile");
    fs::write(&bad, &bytes).unwrap();
    let err = decrypt_file(&bad, &dir.file("o"), b"pw", &DecryptOptions::default(), None, None).unwrap_err();
    assert!(matches!(err, Error::HeaderParamOutOfRange(_)), "实际错误：{err:?}");

    // 合法范围内但被篡改的参数：认证失败，而不是静默解出错内容
    let mut bytes2 = fs::read(&ct).unwrap();
    bytes2[16] = bytes2[16].wrapping_add(1); // t_cost
    fs::write(&bad, &bytes2).unwrap();
    let err2 = decrypt_file(&bad, &dir.file("o2"), b"pw", &DecryptOptions::default(), None, None).unwrap_err();
    assert!(matches!(err2, Error::AuthFailed | Error::HeaderParamOutOfRange(_)), "实际错误：{err2:?}");
}

#[test]
fn truncation_detected() {
    let dir = TempDir::new("trunc");
    let plain = dir.file("a.bin");
    write_pattern(&plain, 20_000);
    let ct = dir.file("a.bin.safefile");
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), chunk_size: 4096, ..Default::default() }, None, None).unwrap();

    let bytes = fs::read(&ct).unwrap();
    // 截断掉最后 30 字节（落在结束块内）
    let cut = dir.file("cut.safefile");
    fs::write(&cut, &bytes[..bytes.len() - 30]).unwrap();
    let err = decrypt_file(&cut, &dir.file("o"), b"pw", &DecryptOptions::default(), None, None).unwrap_err();
    assert!(matches!(err, Error::AuthFailed | Error::Truncated), "实际错误：{err:?}");

    // 只在块边界截断（去掉整个结束块）
    let boundary = bytes.len() - CHUNK_TAG_OVERHEAD;
    let cut2 = dir.file("cut2.safefile");
    fs::write(&cut2, &bytes[..boundary]).unwrap();
    let err2 = decrypt_file(&cut2, &dir.file("o2"), b"pw", &DecryptOptions::default(), None, None).unwrap_err();
    assert!(matches!(err2, Error::Truncated), "实际错误：{err2:?}");
}

#[test]
fn trailing_data_detected() {
    let dir = TempDir::new("trail");
    let plain = dir.file("a.bin");
    write_pattern(&plain, 5000);
    let ct = dir.file("a.bin.safefile");
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap();
    let mut bytes = fs::read(&ct).unwrap();
    bytes.extend_from_slice(&[0u8; 32]);
    let bad = dir.file("trail.safefile");
    fs::write(&bad, &bytes).unwrap();
    let err = decrypt_file(&bad, &dir.file("o"), b"pw", &DecryptOptions::default(), None, None).unwrap_err();
    assert!(matches!(err, Error::TrailingData), "实际错误：{err:?}");
}

#[test]
fn bad_magic_and_short_file() {
    let dir = TempDir::new("magic");
    let fake = dir.file("fake.safefile");
    fs::write(&fake, b"NOTSAFEFILE-0123456789").unwrap();
    assert!(matches!(inspect(&fake).unwrap_err(), Error::BadMagic | Error::TooShort));
    assert!(matches!(
        decrypt_file(&fake, &dir.file("o"), b"pw", &DecryptOptions::default(), None, None).unwrap_err(),
        Error::BadMagic | Error::TooShort
    ));

    let empty = dir.file("empty.safefile");
    fs::write(&empty, b"").unwrap();
    assert!(matches!(inspect(&empty).unwrap_err(), Error::TooShort));
}

#[test]
fn same_file_encrypts_differently_each_time() {
    let dir = TempDir::new("random");
    let plain = dir.file("a.txt");
    fs::write(&plain, b"same content").unwrap();
    let c1 = dir.file("c1.safefile");
    let c2 = dir.file("c2.safefile");
    for out in [&c1, &c2] {
        encrypt_file(&plain, out, b"pw", &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap();
    }
    let b1 = fs::read(&c1).unwrap();
    let b2 = fs::read(&c2).unwrap();
    assert_eq!(b1.len(), b2.len());
    assert_ne!(b1, b2, "盐或流初始化参数重复，存在严重安全问题");
    // 盐不同、secretstream header 不同
    assert_ne!(b1[28..60], b2[28..60]);
    assert_ne!(b1[64..88], b2[64..88]);
}

#[test]
fn does_not_overwrite_by_default() {
    let dir = TempDir::new("nooverwrite");
    let plain = dir.file("a.txt");
    fs::write(&plain, b"data").unwrap();
    let ct = dir.file("a.txt.safefile");
    fs::write(&ct, b"existing").unwrap();
    let err = encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap_err();
    assert!(matches!(err, Error::OutputExists(_)), "实际错误：{err:?}");
    assert_eq!(fs::read(&ct).unwrap(), b"existing");

    // 显式覆盖才允许
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), overwrite: true, ..Default::default() }, None, None)
        .unwrap();
    assert_ne!(fs::read(&ct).unwrap(), b"existing");
}

#[test]
fn cancel_leaves_no_partial_output() {
    let dir = TempDir::new("cancel");
    let plain = dir.file("big.bin");
    write_pattern(&plain, 4 * 1024 * 1024);
    let ct = dir.file("big.bin.safefile");
    let token = CancelToken::new();
    let t2 = token.clone();
    let progress = move |done: u64, _total: u64| {
        if done > 512 * 1024 {
            t2.cancel();
        }
    };
    let err = encrypt_file(
        &plain,
        &ct,
        b"pw",
        &EncryptOptions { kdf: fast_kdf(), chunk_size: 4096, ..Default::default() },
        Some(&progress),
        Some(&token),
    )
    .unwrap_err();
    assert!(matches!(err, Error::Cancelled), "实际错误：{err:?}");
    assert!(!ct.exists());
    assert!(!dir.entries().iter().any(|n| n.contains("sfpart")));
}

#[test]
fn progress_is_monotonic_and_complete() {
    let dir = TempDir::new("progress");
    let plain = dir.file("p.bin");
    write_pattern(&plain, 300_000);
    let ct = dir.file("p.bin.safefile");
    let seen = std::sync::Mutex::new(Vec::<(u64, u64)>::new());
    let progress = |done: u64, total: u64| {
        seen.lock().unwrap().push((done, total));
    };
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), chunk_size: 4096, ..Default::default() }, Some(&progress), None)
        .unwrap();
    let s = seen.lock().unwrap().clone();
    assert_eq!(s.last().unwrap().0, 300_000);
    assert!(s.windows(2).all(|w| w[0].0 <= w[1].0), "进度出现回退");
    assert!(s.iter().all(|(_, total)| *total == 300_000));
}

#[test]
fn inspect_reports_format_fields() {
    let dir = TempDir::new("inspect");
    let plain = dir.file("a.bin");
    write_pattern(&plain, 1234);
    let ct = dir.file("a.bin.safefile");
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), chunk_size: 8192, ..Default::default() }, None, None).unwrap();
    let info = inspect(&ct).unwrap();
    assert_eq!(info.header.version, 1);
    assert_eq!(info.header.chunk_size, 8192);
    assert_eq!(info.header.kdf_params, fast_kdf());
    assert_eq!(info.container_size as usize, fs::metadata(&ct).unwrap().len() as usize);
    let bytes = fs::read(&ct).unwrap();
    assert_eq!(&bytes[0..8], &MAGIC);
    assert_eq!(bytes[10], 1); // cipher
    assert_eq!(bytes[11], 1); // kdf
}

#[test]
fn verify_detects_wrong_password_without_writing() {
    let dir = TempDir::new("verify");
    let plain = dir.file("a.txt");
    fs::write(&plain, b"abc").unwrap();
    let ct = dir.file("a.txt.safefile");
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap();
    assert!(verify_path(&ct, b"pw", None).is_ok());
    assert!(matches!(verify_path(&ct, b"nope", None).unwrap_err(), Error::AuthFailed));
    assert_eq!(dir.entries().len(), 2, "verify 不应产生额外文件");
}

#[test]
fn malicious_filename_is_sanitized_on_decrypt() {
    let dir = TempDir::new("traversal");
    let plain = dir.file("evil.txt");
    fs::write(&plain, b"payload").unwrap();
    let ct = dir.file("evil.safefile");
    // 伪造元数据文件名（模拟攻击者构造的容器）
    let mut meta = Metadata::new("../../../../Windows/System32/evil.dll", 7);
    meta.mtime_secs = None;
    let _ = meta.encode().unwrap();

    encrypt_file(
        &plain,
        &ct,
        b"pw",
        &EncryptOptions {
            kdf: fast_kdf(),
            store_filename: Some("../../../../Windows/System32/evil.dll".into()),
            ..Default::default()
        },
        None,
        None,
    )
    .unwrap();
    let target = dir.file("restore");
    fs::create_dir_all(&target).unwrap();
    let out = decrypt_file(&ct, &target, b"pw", &DecryptOptions::default(), None, None).unwrap();
    assert_eq!(out.output.parent().unwrap(), target.as_path(), "输出逃逸出目标目录");
    assert_eq!(out.output.file_name().unwrap().to_string_lossy(), "evil.dll");
}

#[test]
fn sanitize_filename_rules() {
    assert_eq!(sanitize_filename("a/b/c.txt"), "c.txt");
    assert_eq!(sanitize_filename("..\\..\\x"), "x");
    assert_eq!(sanitize_filename("CON"), "_CON");
    assert_eq!(sanitize_filename("   "), "decrypted");
}

#[test]
fn batch_engine_processes_many_files() {
    let dir = TempDir::new("batch");
    let src = dir.file("src");
    let enc = dir.file("enc");
    let dec = dir.file("dec");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&enc).unwrap();
    fs::create_dir_all(&dec).unwrap();

    let mut expected = Vec::new();
    for i in 0..24 {
        let p = src.join(format!("file-{i:02}.bin"));
        let data = write_pattern(&p, 1000 + i * 137);
        expected.push((p, data));
    }

    let engine = BatchEngine::new(
        ItemKind::Encrypt,
        BatchConfig {
            kdf: fast_kdf(),
            chunk_size: 4096,
            overwrite: false,
            delete_source: false,
            mode: PerfMode::Custom,
            custom_concurrency: 4,
        },
        SecretBytes::new(b"batch-pw".to_vec()),
    );
    for (p, data) in &expected {
        let dest = enc.join(format!("{}.safefile", p.file_name().unwrap().to_string_lossy()));
        engine.add(p.clone(), dest, data.len() as u64);
    }
    engine.start().unwrap();
    engine.wait();
    let s = engine.summary();
    assert_eq!(s.success_items, 24, "批量加密失败：{:?}", engine.snapshot());
    assert!(s.is_done);

    // 批量解密并按元数据文件名还原
    let engine2 = BatchEngine::new(
        ItemKind::Decrypt,
        BatchConfig { kdf: fast_kdf(), chunk_size: 4096, overwrite: false, delete_source: false, mode: PerfMode::High, custom_concurrency: 0 },
        SecretBytes::new(b"batch-pw".to_vec()),
    );
    for entry in fs::read_dir(&enc).unwrap().flatten() {
        let p = entry.path();
        let name = p.file_name().unwrap().to_string_lossy().replace(".safefile", "");
        engine2.add(p, dec.join(name), entry.metadata().unwrap().len());
    }
    engine2.start().unwrap();
    engine2.wait();
    assert_eq!(engine2.summary().success_items, 24);

    for (p, data) in expected {
        let restored = dec.join(p.file_name().unwrap());
        assert_eq!(fs::read(&restored).unwrap(), data, "批量往返内容不一致：{}", restored.display());
    }
}

#[test]
fn batch_wrong_password_marks_failed_only() {
    let dir = TempDir::new("batchfail");
    let enc = dir.file("enc");
    let dec = dir.file("dec");
    fs::create_dir_all(&enc).unwrap();
    fs::create_dir_all(&dec).unwrap();
    let plain = dir.file("x.txt");
    fs::write(&plain, b"content").unwrap();
    let ct = enc.join("x.txt.safefile");
    encrypt_file(&plain, &ct, b"good", &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap();

    let engine = BatchEngine::new(
        ItemKind::Decrypt,
        BatchConfig { kdf: fast_kdf(), mode: PerfMode::Eco, ..Default::default() },
        SecretBytes::new(b"bad".to_vec()),
    );
    engine.add(ct.clone(), dec.join("x.txt"), 10);
    engine.start().unwrap();
    engine.wait();
    let s = engine.summary();
    assert_eq!(s.failed_items, 1);
    assert_eq!(s.success_items, 0);
    let snap = engine.snapshot();
    assert_eq!(snap[0].error_code.as_deref(), Some("auth_failed"));
}

#[test]
fn delete_source_removes_input_after_success() {
    let dir = TempDir::new("delsrc-ok");
    let plain = dir.file("keep.txt");
    fs::write(&plain, b"plaintext-for-delete").unwrap();
    let ct = dir.file("keep.txt.safefile");

    let opts = EncryptOptions { kdf: fast_kdf(), delete_source: true, ..Default::default() };
    let out = encrypt_file(&plain, &ct, b"pw", &opts, None, None).unwrap();
    assert!(out.source_deleted, "成功加密后应删除原文件");
    assert!(out.delete_error.is_none());
    assert!(!plain.exists(), "原文件应已删除");
    assert!(ct.exists(), "容器必须保留");

    // 解密同样生效：容器删除、明文落地
    let dopts = DecryptOptions { delete_source: true, ..Default::default() };
    let dec = decrypt_file(&ct, dir.path(), b"pw", &dopts, None, None).unwrap();
    assert!(dec.source_deleted);
    assert!(!ct.exists(), "成功解密后应删除原容器");
    assert!(dir.file("keep.txt").exists());
}

#[test]
fn delete_source_keeps_input_when_output_exists() {
    let dir = TempDir::new("delsrc-exists");
    let plain = dir.file("dup.txt");
    fs::write(&plain, b"data").unwrap();
    let ct = dir.file("dup.txt.safefile");
    encrypt_file(&plain, &ct, b"pw", &EncryptOptions { kdf: fast_kdf(), ..Default::default() }, None, None).unwrap();

    // 不覆盖 + 目标已存在 → 失败，且原文件不得被删除
    let opts = EncryptOptions { kdf: fast_kdf(), delete_source: true, ..Default::default() };
    let err = encrypt_file(&plain, &ct, b"pw", &opts, None, None).unwrap_err();
    assert_eq!(err.code(), "output_exists");
    assert!(plain.exists(), "失败路径绝不能删除原文件");
}

#[test]
fn delete_source_keeps_input_when_cancelled() {
    let dir = TempDir::new("delsrc-cancel");
    let plain = dir.file("big.bin");
    fs::write(&plain, vec![7u8; 512 * 1024]).unwrap();
    let ct = dir.file("big.bin.safefile");

    let token = CancelToken::new();
    token.cancel();
    let opts = EncryptOptions { kdf: fast_kdf(), delete_source: true, ..Default::default() };
    let res = encrypt_file(&plain, &ct, b"pw", &opts, None, Some(&token));
    assert!(res.is_err(), "取消应返回错误");
    assert!(plain.exists(), "取消路径绝不能删除原文件");
    assert!(!ct.exists(), "取消不得留下半成品");
}

#[test]
fn batch_reports_deleted_items() {
    let dir = TempDir::new("delsrc-batch");
    let a = dir.file("a.txt");
    fs::write(&a, b"one").unwrap();
    let b = dir.file("b.txt");
    fs::write(&b, b"two").unwrap();
    let out = dir.file("out");
    fs::create_dir_all(&out).unwrap();

    let engine = BatchEngine::new(
        ItemKind::Encrypt,
        BatchConfig { kdf: fast_kdf(), mode: PerfMode::Eco, delete_source: true, ..Default::default() },
        SecretBytes::new(b"pw".to_vec()),
    );
    engine.add(a.clone(), out.join("a.txt.safefile"), 3);
    engine.add(b.clone(), out.join("b.txt.safefile"), 3);
    engine.start().unwrap();
    engine.wait();

    let s = engine.summary();
    assert_eq!(s.success_items, 2);
    let snap = engine.snapshot();
    assert!(snap.iter().all(|i| i.deleted), "批量成功后应删除每个原文件");
    assert!(!a.exists() && !b.exists());
}
