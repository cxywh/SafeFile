//! 文件引擎：流式加密 / 解密、临时文件 + 原子提交、进度回调、取消。
//!
//! 安全不变量：
//! 1. 输出先写临时文件，全部成功并通过校验后才原子重命名到目标路径。
//! 2. 任何失败 / 取消路径都会删除临时文件，不会留下“看起来成功”的半成品。
//! 3. 解密必须命中结束标记，且解出长度与元数据一致，才算成功。
//! 4. 默认不覆盖已存在文件，不删除原始文件。
//! 5. 密码与密钥不出现在错误、日志或返回值中。

use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::crypto::{ChunkReader, ChunkWriter};
use crate::error::{Error, Result};
use crate::format::{
    chunk_size_from_exp, KdfParams, PublicHeader, PublicInfo, CHUNK_TAG_OVERHEAD,
    CIPHER_XCHACHA20POLY1305_SECRETSTREAM, DEFAULT_CHUNK_SIZE, KDF_ARGON2ID13, META_BLOCK_LEN,
    PREFIX_LEN, PUBLIC_HEADER_LEN, SALT_LEN, SS_HEADER_LEN,
};
use crate::kdf::derive_key;
use crate::meta::{sanitize_filename, Metadata};

/// 取消令牌，可跨线程共享。
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// 进度回调：(已处理明文字节, 总明文字节)。
pub type ProgressFn<'a> = dyn Fn(u64, u64) + Send + Sync + 'a;

#[derive(Debug, Clone)]
pub struct EncryptOptions {
    pub kdf: KdfParams,
    pub chunk_size: usize,
    pub overwrite: bool,
    /// 覆盖写入元数据的文件名；默认取输入文件名。
    pub store_filename: Option<String>,
    /// 输出提交成功后再删除输入文件；失败、取消一律不动原文件。
    pub delete_source: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            kdf: KdfParams::desktop(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            overwrite: false,
            store_filename: None,
            delete_source: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DecryptOptions {
    pub overwrite: bool,
    /// 指定输出文件名（仍会做安全收敛）。
    pub output_name: Option<String>,
    /// 输出提交成功后再删除输入容器；失败、取消一律不动原文件。
    pub delete_source: bool,
}

#[derive(Debug, Clone)]
pub struct EncryptOutcome {
    pub output: PathBuf,
    pub plaintext_size: u64,
    pub container_size: u64,
    pub kdf: KdfParams,
    /// 是否已按 `delete_source` 删除输入文件。
    pub source_deleted: bool,
    /// 想删但删不掉时的原因（不影响加密结果）。
    pub delete_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DecryptOutcome {
    pub output: PathBuf,
    pub plaintext_size: u64,
    pub metadata: Metadata,
    /// 是否已按 `delete_source` 删除输入容器。
    pub source_deleted: bool,
    /// 想删但删不掉时的原因（不影响解密结果）。
    pub delete_error: Option<String>,
}

/// 只在输出已提交之后调用：删不掉不算失败，但要把原因带回去。
/// 输入与输出是同一路径时直接跳过，避免把刚写好的结果删掉。
fn finish_delete_source(input: &Path, output: &Path, enabled: bool) -> (bool, Option<String>) {
    if !enabled {
        return (false, None);
    }
    let same = match (input.canonicalize(), output.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => input == output,
    };
    if same {
        return (false, Some("输入与输出为同一路径，已跳过删除".to_string()));
    }
    match std::fs::remove_file(input) {
        Ok(()) => (true, None),
        Err(e) => (false, Some(format!("原文件删除失败：{e}"))),
    }
}

/// 临时输出文件守卫：未提交则删除。
struct TempOutput {
    path: PathBuf,
    committed: bool,
}

impl TempOutput {
    fn create(dir: &Path) -> Result<(Self, File)> {
        let mut rand = [0u8; 8];
        getrandom::fill(&mut rand).map_err(|_| Error::Internal("随机数生成失败"))?;
        let suffix: String = rand.iter().map(|b| format!("{:02x}", b)).collect();
        let path = dir.join(format!(".safefile-{}.sfpart", suffix));
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok((Self { path, committed: false }, file))
    }

    fn commit(mut self, dest: &Path) -> Result<()> {
        match fs::rename(&self.path, dest) {
            Ok(()) => {
                self.committed = true;
                Ok(())
            }
            Err(e) => Err(Error::Io(e)),
        }
    }
}

impl Drop for TempOutput {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// 填充读取：返回实际读到的字节数，0 表示 EOF。
fn read_chunk(file: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(filled)
}

fn parent_dir(path: &Path) -> PathBuf {
    path.parent().filter(|p| !p.as_os_str().is_empty()).map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."))
}

/// 解密侧的块切分计划：由元数据中的明文大小与块大小唯一确定。
///
/// 这样解密方无需猜测消息边界，多余字节、缺失块、块合并都能被精确识别。
struct FramePlan {
    total: u64,
    chunk: u64,
    count: u64,
}

impl FramePlan {
    fn new(total: u64, chunk: usize) -> Self {
        let chunk = chunk as u64;
        let count = if total == 0 {
            1
        } else if total % chunk == 0 {
            total / chunk
        } else {
            total / chunk + 1
        };
        Self { total, chunk, count }
    }

    /// 第 `i` 个块的 (明文长度, 是否结束块)。
    fn message(&self, i: u64) -> (usize, bool) {
        if self.total == 0 {
            return (0, true);
        }
        let last = self.count - 1;
        let rem = self.total % self.chunk;
        if i < last {
            (self.chunk as usize, false)
        } else if rem == 0 {
            (self.chunk as usize, true)
        } else {
            (rem as usize, true)
        }
    }
}

/// 读取容器公开信息，不需要密码。
pub fn inspect(input: &Path) -> Result<PublicInfo> {
    let mut file = File::open(input).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::BadPath(format!("找不到文件：{}", input.display())),
        _ => Error::Io(e),
    })?;
    let container_size = file.metadata()?.len();
    if container_size < (PREFIX_LEN + CHUNK_TAG_OVERHEAD) as u64 {
        return Err(Error::TooShort);
    }
    let mut prefix = [0u8; PREFIX_LEN];
    read_exact_or_too_short(&mut file, &mut prefix)?;
    let header = PublicHeader::parse(&prefix[..PUBLIC_HEADER_LEN])?;
    Ok(PublicInfo { header, container_size })
}

fn read_exact_or_too_short(file: &mut File, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => return Err(Error::TooShort),
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(())
}

fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| Error::Internal("随机数生成失败"))?;
    Ok(salt)
}

fn file_mtime(path: &Path) -> Option<(i64, u32)> {
    let meta = fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    let dur = mtime.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some((dur.as_secs() as i64, dur.subsec_nanos()))
}

fn check_output_available(dest: &Path, overwrite: bool) -> Result<()> {
    if !overwrite && dest.exists() {
        return Err(Error::OutputExists(dest.display().to_string()));
    }
    Ok(())
}

/// 加密单个文件。
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    password: &[u8],
    opts: &EncryptOptions,
    progress: Option<&ProgressFn<'_>>,
    cancel: Option<&CancelToken>,
) -> Result<EncryptOutcome> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    opts.kdf.validate()?;
    if !(crate::format::MIN_CHUNK_SIZE..=crate::format::MAX_CHUNK_SIZE).contains(&opts.chunk_size)
        || !opts.chunk_size.is_power_of_two()
    {
        return Err(Error::HeaderParamOutOfRange("chunk_size"));
    }

    let mut file = File::open(input)?;
    let plaintext_size = file.metadata()?.len();
    check_output_available(output, opts.overwrite)?;

    let mut salt = random_salt()?;
    let header = PublicHeader::new(opts.kdf, opts.chunk_size, salt)?;
    let key = derive_key(password, &salt, &opts.kdf)?;
    salt.zeroize_in_place();

    let dir = parent_dir(output);
    let (temp, file_out) = TempOutput::create(&dir)?;
    let mut writer = BufWriter::with_capacity(256 * 1024, file_out);

    // 公共文件头 + secretstream header
    let (mut chunk_writer, header_tail) = {
        let cw = ChunkWriter::new(&key)?;
        let tail = *cw.header();
        (cw, tail)
    };
    let mut prefix = [0u8; PREFIX_LEN];
    prefix[..PUBLIC_HEADER_LEN].copy_from_slice(&header.to_bytes());
    prefix[PUBLIC_HEADER_LEN..].copy_from_slice(&header_tail);
    writer.write_all(&prefix)?;

    // 元数据块：加密并填充到定长
    let mut meta = match &opts.store_filename {
        Some(name) => Metadata::new(name.clone(), plaintext_size),
        None => Metadata::new(
            input.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string(),
            plaintext_size,
        ),
    };
    if let Some((secs, nanos)) = file_mtime(input) {
        meta.mtime_secs = Some(secs);
        meta.mtime_nanos = Some(nanos);
    }
    let meta_bytes = meta.encode()?;
    let mut meta_block = vec![0u8; META_BLOCK_LEN];
    meta_block[..meta_bytes.len()].copy_from_slice(&meta_bytes);
    let mut meta_ct = vec![0u8; META_BLOCK_LEN + CHUNK_TAG_OVERHEAD];
    chunk_writer.push(&meta_block, &mut meta_ct, &prefix, false)?;
    writer.write_all(&meta_ct)?;
    drop(meta_ct);
    drop(meta_block);

    // 数据块：双缓冲前瞻，保证最后一块带 TAG_FINAL
    let chunk = opts.chunk_size;
    let mut buf_a = vec![0u8; chunk];
    let mut buf_b = vec![0u8; chunk];
    let mut ct = vec![0u8; chunk + CHUNK_TAG_OVERHEAD];
    let mut done: u64 = 0;
    let mut na = read_chunk(&mut file, &mut buf_a)?;

    if na == 0 {
        let n = chunk_writer.push(&[], &mut ct, &prefix, true)?;
        writer.write_all(&ct[..n])?;
    } else {
        loop {
            if let Some(token) = cancel {
                if token.is_cancelled() {
                    return Err(Error::Cancelled);
                }
            }
            let nb = if na == chunk { read_chunk(&mut file, &mut buf_b)? } else { 0 };
            let is_final = nb == 0;
            let n = chunk_writer.push(&buf_a[..na], &mut ct, &prefix, is_final)?;
            writer.write_all(&ct[..n])?;
            done += na as u64;
            if let Some(cb) = progress {
                cb(done.min(plaintext_size), plaintext_size);
            }
            if is_final {
                break;
            }
            std::mem::swap(&mut buf_a, &mut buf_b);
            na = nb;
        }
    }

    writer.flush()?;
    let f = writer.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    f.sync_all()?;
    drop(f);

    let container_size = fs::metadata(&temp.path)?.len();
    temp.commit(output)?;

    if let Some(cb) = progress {
        cb(plaintext_size, plaintext_size);
    }

    let (source_deleted, delete_error) = finish_delete_source(input, output, opts.delete_source);

    Ok(EncryptOutcome {
        output: output.to_path_buf(),
        plaintext_size,
        container_size,
        kdf: opts.kdf,
        source_deleted,
        delete_error,
    })
}

/// 解密单个文件。
///
/// `output` 可以是目标文件路径，也可以是已存在的目录（此时使用元数据中
/// 的文件名，经安全收敛后落盘）。
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    password: &[u8],
    opts: &DecryptOptions,
    progress: Option<&ProgressFn<'_>>,
    cancel: Option<&CancelToken>,
) -> Result<DecryptOutcome> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let mut file = File::open(input).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::BadPath(format!("找不到文件：{}", input.display())),
        _ => Error::Io(e),
    })?;
    let container_size = file.metadata()?.len();
    if container_size < (PREFIX_LEN + CHUNK_TAG_OVERHEAD) as u64 {
        return Err(Error::TooShort);
    }

    let mut prefix = [0u8; PREFIX_LEN];
    read_exact_or_too_short(&mut file, &mut prefix)?;
    let header = PublicHeader::parse(&prefix[..PUBLIC_HEADER_LEN])?;
    let mut ss_header = [0u8; SS_HEADER_LEN];
    ss_header.copy_from_slice(&prefix[PUBLIC_HEADER_LEN..]);

    let key = derive_key(password, &header.salt, &header.kdf_params)?;

    // 元数据块
    let mut meta_ct = vec![0u8; META_BLOCK_LEN + CHUNK_TAG_OVERHEAD];
    read_exact_or_too_short(&mut file, &mut meta_ct)?;
    let mut reader = ChunkReader::new(&key, &ss_header);
    let mut meta_plain = vec![0u8; META_BLOCK_LEN];
    let (meta_len, meta_final) = reader.pull(&meta_ct, &mut meta_plain, &prefix)?;
    if meta_final {
        return Err(Error::BadMetadata("元数据块不应带结束标记"));
    }
    let metadata = Metadata::decode(&meta_plain[..meta_len])?;
    drop(meta_plain);
    drop(meta_ct);

    // 输出路径裁决
    let dest = resolve_output_path(output, &metadata, opts)?;
    check_output_available(&dest, opts.overwrite)?;
    let dir = parent_dir(&dest);
    let (temp, file_out) = TempOutput::create(&dir)?;
    let mut writer = BufWriter::with_capacity(256 * 1024, file_out);

    let chunk = header.chunk_size;
    let mut ct = vec![0u8; chunk + CHUNK_TAG_OVERHEAD];
    let mut pt = vec![0u8; chunk];
    let total = metadata.original_size;
    let plan = FramePlan::new(total, chunk);
    let mut done: u64 = 0;

    for index in 0..plan.count {
        if let Some(token) = cancel {
            if token.is_cancelled() {
                return Err(Error::Cancelled);
            }
        }
        let (plain_len, expect_final) = plan.message(index);
        let want = plain_len + CHUNK_TAG_OVERHEAD;
        let got = read_chunk(&mut file, &mut ct[..want])?;
        if got < want {
            // 缺失结束块或块内截断
            return Err(Error::Truncated);
        }
        let (n, is_final) = reader.pull(&ct[..want], &mut pt, &prefix)?;
        if is_final != expect_final {
            return Err(Error::TrailingData);
        }
        writer.write_all(&pt[..n])?;
        done += n as u64;
        if let Some(cb) = progress {
            cb(done.min(total), total);
        }
    }

    // 结束块之后不得有多余字节
    let mut probe = [0u8; 1];
    if file.read(&mut probe)? != 0 {
        return Err(Error::TrailingData);
    }
    if done != total {
        return Err(Error::SizeMismatch);
    }

    writer.flush()?;
    let f = writer.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    f.sync_all()?;
    drop(f);
    temp.commit(&dest)?;

    if let Some(cb) = progress {
        cb(total, total);
    }
    // 还原修改时间（尽力而为，失败不影响解密结果）
    if let (Some(secs), nanos) = (metadata.mtime_secs, metadata.mtime_nanos.unwrap_or(0)) {
        if secs >= 0 {
            let ft = std::time::UNIX_EPOCH + std::time::Duration::new(secs as u64, nanos);
            if let Ok(f) = File::options().write(true).open(&dest) {
                let _ = f.set_modified(ft);
            }
        }
    }

    let (source_deleted, delete_error) = finish_delete_source(input, &dest, opts.delete_source);

    Ok(DecryptOutcome {
        output: dest,
        plaintext_size: done,
        metadata,
        source_deleted,
        delete_error,
    })
}

/// 仅校验完整性与密码，不落盘。
pub fn verify_path(input: &Path, password: &[u8], cancel: Option<&CancelToken>) -> Result<Metadata> {
    let outcome = decrypt_to_sink(input, password, &mut std::io::sink(), cancel, None)?;
    Ok(outcome)
}

/// 解密到任意 Write（预览引擎、内存流使用）。返回元数据。
pub fn decrypt_to_sink<W: Write>(
    input: &Path,
    password: &[u8],
    sink: &mut W,
    cancel: Option<&CancelToken>,
    progress: Option<&ProgressFn<'_>>,
) -> Result<Metadata> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let mut file = File::open(input)?;
    let mut prefix = [0u8; PREFIX_LEN];
    read_exact_or_too_short(&mut file, &mut prefix)?;
    let header = PublicHeader::parse(&prefix[..PUBLIC_HEADER_LEN])?;
    let mut ss_header = [0u8; SS_HEADER_LEN];
    ss_header.copy_from_slice(&prefix[PUBLIC_HEADER_LEN..]);
    let key = derive_key(password, &header.salt, &header.kdf_params)?;

    let mut meta_ct = vec![0u8; META_BLOCK_LEN + CHUNK_TAG_OVERHEAD];
    read_exact_or_too_short(&mut file, &mut meta_ct)?;
    let mut reader = ChunkReader::new(&key, &ss_header);
    let mut meta_plain = vec![0u8; META_BLOCK_LEN];
    let (meta_len, _) = reader.pull(&meta_ct, &mut meta_plain, &prefix)?;
    let metadata = Metadata::decode(&meta_plain[..meta_len])?;

    let chunk = header.chunk_size;
    let mut ct = vec![0u8; chunk + CHUNK_TAG_OVERHEAD];
    let mut pt = vec![0u8; chunk];
    let plan = FramePlan::new(metadata.original_size, chunk);
    let mut done: u64 = 0;
    for index in 0..plan.count {
        if let Some(token) = cancel {
            if token.is_cancelled() {
                return Err(Error::Cancelled);
            }
        }
        let (plain_len, expect_final) = plan.message(index);
        let want = plain_len + CHUNK_TAG_OVERHEAD;
        let got = read_chunk(&mut file, &mut ct[..want])?;
        if got < want {
            return Err(Error::Truncated);
        }
        let (n, is_final) = reader.pull(&ct[..want], &mut pt, &prefix)?;
        if is_final != expect_final {
            return Err(Error::TrailingData);
        }
        sink.write_all(&pt[..n])?;
        done += n as u64;
        if let Some(cb) = progress {
            cb(done.min(metadata.original_size), metadata.original_size);
        }
    }
    let mut probe = [0u8; 1];
    if file.read(&mut probe)? != 0 {
        return Err(Error::TrailingData);
    }
    if done != metadata.original_size {
        return Err(Error::SizeMismatch);
    }
    Ok(metadata)
}

/// 只解密元数据块，不遍历数据块。
///
/// 预览大文件（尤其是视频）时，必须先知道「是什么类型、有多大」再决定
/// 是否整段解密：否则会先吃满一次明文内存，才发现超限或根本不需要。
pub fn read_metadata(input: &Path, password: &[u8]) -> Result<Metadata> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let mut file = File::open(input)?;
    let mut prefix = [0u8; PREFIX_LEN];
    read_exact_or_too_short(&mut file, &mut prefix)?;
    let header = PublicHeader::parse(&prefix[..PUBLIC_HEADER_LEN])?;
    let mut ss_header = [0u8; SS_HEADER_LEN];
    ss_header.copy_from_slice(&prefix[PUBLIC_HEADER_LEN..]);
    let key = derive_key(password, &header.salt, &header.kdf_params)?;
    let mut meta_ct = vec![0u8; META_BLOCK_LEN + CHUNK_TAG_OVERHEAD];
    read_exact_or_too_short(&mut file, &mut meta_ct)?;
    let mut reader = ChunkReader::new(&key, &ss_header);
    let mut meta_plain = vec![0u8; META_BLOCK_LEN];
    let (meta_len, _) = reader.pull(&meta_ct, &mut meta_plain, &prefix)?;
    Metadata::decode(&meta_plain[..meta_len])
}

/// 解密到内存（预览小文件使用，带硬上限）。
///
/// 先读元数据判上限，再按真实大小一次性预留：避免「解完才发现超限」，
/// 也避免 `Vec` 反复扩容时出现接近两倍的内存峰值（Android 上会被 OOM 杀掉）。
pub fn decrypt_to_vec(input: &Path, password: &[u8], max_bytes: u64) -> Result<(Metadata, Vec<u8>)> {
    let meta = read_metadata(input, password)?;
    if meta.original_size > max_bytes {
        return Err(Error::Preview(format!(
            "明文 {} MiB 超过内存上限 {} MiB，请先解密到磁盘",
            meta.original_size / (1024 * 1024),
            max_bytes / (1024 * 1024)
        )));
    }
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(meta.original_size as usize)
        .map_err(|_| Error::Preview("内存不足，无法在内存中预览该文件".into()))?;
    let meta = decrypt_to_sink(input, password, &mut buf, None, None)?;
    Ok((meta, buf))
}

fn resolve_output_path(output: &Path, meta: &Metadata, opts: &DecryptOptions) -> Result<PathBuf> {
    let wanted = opts
        .output_name
        .clone()
        .unwrap_or_else(|| sanitize_filename(&meta.filename));
    let wanted = sanitize_filename(&wanted);
    if output.is_dir() {
        return Ok(output.join(wanted));
    }
    // 输出以分隔符结尾视为目录
    let s = output.to_string_lossy();
    if s.ends_with('/') || s.ends_with('\\') {
        return Ok(output.join(wanted));
    }
    Ok(output.to_path_buf())
}

/// 便于测试与外部工具：容器格式的固定前缀长度。
pub fn prefix_len() -> usize {
    PREFIX_LEN
}

/// 便于测试：块大小指数解码。
pub fn chunk_from_exp(exp: u8) -> Result<usize> {
    chunk_size_from_exp(exp)
}

/// 供外部断言算法标识常量。
pub const CIPHER_ID: u8 = CIPHER_XCHACHA20POLY1305_SECRETSTREAM;
pub const KDF_ID: u8 = KDF_ARGON2ID13;

trait ZeroizeInPlace {
    fn zeroize_in_place(&mut self);
}
impl ZeroizeInPlace for [u8] {
    fn zeroize_in_place(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

/// 供上层（批量调度）复用：把主密钥保留为 Zeroizing。
pub fn derive(password: &[u8], salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    derive_key(password, salt, params)
}
