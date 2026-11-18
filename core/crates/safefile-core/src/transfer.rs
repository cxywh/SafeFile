//! 局域网直传 v2：无配对码，固定端口 + 双向身份认证。
//!
//! 发现阶段由 [`crate::lan`] 负责：每台设备在固定 UDP 端口广播带 Ed25519
//! 签名的公告，因此设备名与「可接收」状态无需先握手即可看到，也不会被
//! 局域网内第三方伪造。
//!
//! 传输阶段：
//! 1. 客户端连接固定 TCP 端口，发送 hello（临时 X25519 公钥 + 静态 Ed25519
//!    公钥 + 随机数 + 对上述内容的签名）。
//! 2. 服务端验签，检查 TOFU 信任库；身份变更则直接拒绝（status=2）。
//! 3. 服务端回 hello（带上自己的临时/静态公钥与签名，签名覆盖双方字段，
//!    防止中间人拼接）。
//! 4. 双方用 libsodium `crypto_kx`（X25519 + BLAKE2b）算共享密钥，再与握手
//!    转录一起派生两个方向独立的会话密钥；各发 24 字节 secretstream 头。
//! 5. 之后所有帧都是 `[kind:1][len:u32 LE][密文]`，AAD 绑定方向；任何一位
//!    被改都会导致认证失败并中断。
//!
//! 性能：1 MiB 帧、写缓冲复用、单 TCP 连接、只对控制帧 flush、默认不 fsync。

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dryoc::kx;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::crypto::{ChunkReader, ChunkWriter};
use crate::error::{Error, Result};
use crate::format::{CHUNK_TAG_OVERHEAD, SS_HEADER_LEN};
use crate::identity::{device_id, hex_decode, hex_encode, Identity, NAME_MAX};
use crate::lan::{self, LanNode, PeerInfo};
use crate::CancelToken;

/// 默认接收端口（固定，避免每次都要交换端口）。
pub const DEFAULT_PORT: u16 = lan::DEFAULT_PORT;
/// 默认发现端口（UDP 广播）。
pub const DISCOVERY_PORT: u16 = lan::DISCOVERY_PORT;

/// 单帧最大明文长度。1 MiB 在千兆局域网与 Wi-Fi 上都是较优的吞吐点。
pub const CHUNK: usize = 1024 * 1024;

const MAGIC: &[u8; 5] = b"SFTR2";
const KIND_CONTROL: u8 = 0;
const KIND_DATA: u8 = 1;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const ACCEPT_POLL: Duration = Duration::from_millis(25);

const MAX_FILES: usize = 20_000;
const MAX_NAME_BYTES: usize = 200;
const MAX_CONTROL_BYTES: usize = 256 * 1024;

/// 一个文件的元信息（控制帧里用）。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
}

/// 控制帧。`t` 是类型，其余字段按类型取用。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Control {
    t: String,
    #[serde(default)]
    index: usize,
    #[serde(default)]
    name: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    files: Vec<FileMeta>,
    #[serde(default)]
    skip: Vec<usize>,
    #[serde(default)]
    hash: String,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    message: String,
}

impl Control {
    fn new(t: &str) -> Self {
        Self { t: t.to_string(), ..Default::default() }
    }
}

/// 传输进度。FFI 会把它序列化成 JSON 给 Dart 侧。
#[derive(Clone, Debug, Default, Serialize)]
pub struct Progress {
    pub files_total: usize,
    pub files_done: usize,
    pub total_bytes: u64,
    pub done_bytes: u64,
    pub current: String,
    pub skipped: usize,
    pub error: Option<String>,
    pub finished: bool,
    pub elapsed_ms: u64,
    /// 对端设备名（握手后才知道）。
    pub peer: String,
    /// 对端设备 id。
    pub peer_id: String,
    /// 6 位 SAS；双方一致说明没有中间人。
    pub sas: String,
    /// 是否全程加密（v2 固定为 true）。
    pub encrypted: bool,
}

impl Progress {
    pub fn speed_bps(&self) -> f64 {
        if self.elapsed_ms == 0 {
            return 0.0;
        }
        self.done_bytes as f64 / (self.elapsed_ms as f64 / 1000.0)
    }
}

/// 本机接收端信息，UI 用来展示「我在哪个地址、叫什么名字」。
#[derive(Clone, Debug, Serialize)]
pub struct ShareInfo {
    pub name: String,
    pub id: String,
    pub fingerprint: String,
    pub port: u16,
    pub addrs: Vec<String>,
}

// ---------------------------------------------------------------------------
// 字节辅助
// ---------------------------------------------------------------------------

fn random32() -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).map_err(|_| Error::Internal("系统随机数不可用"))?;
    Ok(out)
}

fn arr32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

fn hex_of(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

/// 校验并收敛对端提供的文件名，绝不允许多级路径或 Windows 设备名。
fn safe_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw).trim();
    let mut clean: String = base
        .chars()
        .map(|c| match c {
            '\u{0}'..='\u{1f}' | '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c => c,
        })
        .filter(|c| *c != '\u{7f}')
        .collect();
    if clean.is_empty() || clean == "." || clean == ".." {
        clean = "unnamed".to_string();
    }
    if clean.len() > MAX_NAME_BYTES {
        // 按字节截断可能切到 UTF-8 中间，退回到字符边界。
        while clean.len() > MAX_NAME_BYTES && !clean.is_char_boundary(MAX_NAME_BYTES) {
            clean.pop();
        }
        clean.truncate(MAX_NAME_BYTES);
        clean.push_str("");
    }
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED
        .iter()
        .any(|r| clean.eq_ignore_ascii_case(r) || clean.to_uppercase().starts_with(&format!("{r}.")))
    {
        clean.insert(0, '_');
    }
    clean
}

fn set_peer(progress: &Arc<Mutex<Progress>>, info: &SessionInfo) {
    if let Ok(mut g) = progress.lock() {
        g.peer = info.peer_name.clone();
        g.peer_id = info.peer_id.clone();
        g.sas = info.sas.clone();
        g.encrypted = true;
    }
}

fn bump(progress: &Arc<Mutex<Progress>>, f: impl FnOnce(&mut Progress)) {
    if let Ok(mut g) = progress.lock() {
        f(&mut g);
    }
}

// ---------------------------------------------------------------------------
// 帧读写
// ---------------------------------------------------------------------------

struct FrameWriter {
    out: TcpStream,
    crypt: ChunkWriter,
    scratch: Vec<u8>,
    aad: &'static [u8],
}

impl FrameWriter {
    fn new(out: TcpStream, key: &[u8; 32], aad: &'static [u8]) -> Result<(Self, [u8; SS_HEADER_LEN])> {
        let crypt = ChunkWriter::new(key)?;
        let header = *crypt.header();
        let mut me = Self {
            out,
            crypt,
            scratch: Vec::with_capacity(CHUNK + 5 + CHUNK_TAG_OVERHEAD),
            aad,
        };
        me.out.write_all(&header)?;
        Ok((me, header))
    }

    fn send(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        if payload.len() > CHUNK {
            return Err(Error::Internal("帧负载超过上限"));
        }
        let aad = self.aad;
        let need = payload.len() + CHUNK_TAG_OVERHEAD;
        self.scratch.clear();
        self.scratch.resize(5 + need, 0);
        {
            let (head, body) = self.scratch.split_at_mut(5);
            head[0] = kind;
            head[1..5].copy_from_slice(&(need as u32).to_le_bytes());
            self.crypt.push(payload, body, aad, false)?;
        }
        self.out.write_all(&self.scratch)?;
        Ok(())
    }

    fn send_json(&mut self, c: &Control) -> Result<()> {
        let bytes = serde_json::to_vec(c).map_err(|_| Error::Internal("控制帧序列化失败"))?;
        self.send(KIND_CONTROL, &bytes)?;
        // 控制帧很小，立刻刷出去，让对端不必等数据帧。
        self.out.flush()?;
        Ok(())
    }
}

struct FrameReader {
    inp: BufReader<TcpStream>,
    crypt: ChunkReader,
    cipher: Vec<u8>,
    plain: Vec<u8>,
    aad: &'static [u8],
}

impl FrameReader {
    fn new(stream: TcpStream, key: &[u8; 32], aad: &'static [u8]) -> Result<(Self, [u8; SS_HEADER_LEN])> {
        let mut inp = BufReader::with_capacity(CHUNK + 64, stream);
        let mut header = [0u8; SS_HEADER_LEN];
        inp.read_exact(&mut header)?;
        let crypt = ChunkReader::new(key, &header);
        Ok((
            Self {
                inp,
                crypt,
                cipher: Vec::with_capacity(CHUNK + CHUNK_TAG_OVERHEAD),
                plain: vec![0u8; CHUNK],
                aad,
            },
            header,
        ))
    }

    /// 读取一帧，返回 `(kind, payload)`；payload 借用内部缓冲，下一次读取即失效。
    fn read(&mut self) -> Result<(u8, &[u8])> {
        let mut head = [0u8; 5];
        self.inp.read_exact(&mut head)?;
        let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if len < CHUNK_TAG_OVERHEAD || len > CHUNK + CHUNK_TAG_OVERHEAD {
            return Err(Error::Protocol("帧长度非法"));
        }
        self.cipher.clear();
        self.cipher.resize(len, 0);
        self.inp.read_exact(&mut self.cipher)?;
        let aad = self.aad;
        let (n, _final) = self.crypt.pull(&self.cipher, &mut self.plain, aad)?;
        Ok((head[0], &self.plain[..n]))
    }

    fn read_control(&mut self) -> Result<Control> {
        let (kind, payload) = self.read()?;
        if kind != KIND_CONTROL {
            return Err(Error::Protocol("期望控制帧，收到数据帧"));
        }
        if payload.len() > MAX_CONTROL_BYTES {
            return Err(Error::Protocol("控制帧过大"));
        }
        serde_json::from_slice(payload).map_err(|_| Error::Protocol("控制帧 JSON 非法"))
    }
}

/// 一条已认证、已加密的连接。
struct Session {
    reader: FrameReader,
    writer: FrameWriter,
    info: SessionInfo,
}

#[derive(Clone, Debug, Default)]
struct SessionInfo {
    peer_id: String,
    peer_name: String,
    #[allow(dead_code)]
    peer_public_key: [u8; 32],
    sas: String,
}

// ---------------------------------------------------------------------------
// 握手
// ---------------------------------------------------------------------------

fn append_name(buf: &mut Vec<u8>, name: &str) {
    let bytes = name.as_bytes();
    let n = bytes.len().min(NAME_MAX);
    buf.push(n as u8);
    buf.extend_from_slice(&bytes[..n]);
}

fn handshake_signature_client(name: &str, eph: &[u8; 32], stat: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(b"sf-hello-v2");
    append_name(&mut m, name);
    m.extend_from_slice(eph);
    m.extend_from_slice(stat);
    m.extend_from_slice(nonce);
    m
}

fn handshake_signature_server(
    c_name: &str,
    c_eph: &[u8; 32],
    c_stat: &[u8; 32],
    c_nonce: &[u8; 32],
    s_name: &str,
    s_eph: &[u8; 32],
    s_stat: &[u8; 32],
    s_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(160);
    m.extend_from_slice(b"sf-hello2-v2");
    append_name(&mut m, c_name);
    m.extend_from_slice(c_eph);
    m.extend_from_slice(c_stat);
    m.extend_from_slice(c_nonce);
    append_name(&mut m, s_name);
    m.extend_from_slice(s_eph);
    m.extend_from_slice(s_stat);
    m.extend_from_slice(s_nonce);
    m
}

fn transcript(
    c_name: &str,
    c_eph: &[u8; 32],
    c_stat: &[u8; 32],
    c_nonce: &[u8; 32],
    s_name: &str,
    s_eph: &[u8; 32],
    s_stat: &[u8; 32],
    s_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(224);
    m.extend_from_slice(b"safefile-transcript-v2");
    append_name(&mut m, c_name);
    m.extend_from_slice(c_eph);
    m.extend_from_slice(c_stat);
    m.extend_from_slice(c_nonce);
    append_name(&mut m, s_name);
    m.extend_from_slice(s_eph);
    m.extend_from_slice(s_stat);
    m.extend_from_slice(s_nonce);
    m
}

struct Keys {
    send: [u8; 32],
    recv: [u8; 32],
    sas: String,
}

fn derive_keys(
    is_client: bool,
    session: kx::StackSession,
    transcript: &[u8],
    c_stat: &[u8; 32],
    s_stat: &[u8; 32],
) -> Keys {
    let (rx, tx) = session.into_parts();
    let th = blake3::derive_key("safefile lan transcript v2", transcript);
    let mix = |ctx: &'static str, kx_key: &[u8]| -> [u8; 32] {
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(&th);
        material.extend_from_slice(kx_key);
        blake3::derive_key(ctx, &material)
    };
    // crypto_kx 的 tx/rx 在两端是对称的：客户端 tx == 服务端 rx。
    let (send, recv) = if is_client {
        (mix("safefile lan c2s v2", &tx), mix("safefile lan s2c v2", &rx))
    } else {
        (mix("safefile lan s2c v2", &tx), mix("safefile lan c2s v2", &rx))
    };
    let mut sas_material = Vec::with_capacity(96);
    sas_material.extend_from_slice(&th);
    sas_material.extend_from_slice(c_stat);
    sas_material.extend_from_slice(s_stat);
    let tag = blake3::derive_key("safefile lan sas v2", &sas_material);
    let value = u32::from_le_bytes([tag[0], tag[1], tag[2], tag[3]]) % 1_000_000;
    Keys { send, recv, sas: format!("{value:06}") }
}

fn aad_for(is_client: bool, sending: bool) -> &'static [u8] {
    match (is_client, sending) {
        (true, true) => b"c2s",
        (true, false) => b"s2c",
        (false, true) => b"s2c",
        (false, false) => b"c2s",
    }
}

/// 建立会话（双方都已算出密钥、收到对端 secretstream 头之后）。
fn open_session(stream: TcpStream, keys: Keys, is_client: bool, info: SessionInfo) -> Result<Session> {
    stream.set_nodelay(true)?;
    let send_side = stream;
    let recv_side = send_side.try_clone()?;
    send_side.set_write_timeout(Some(IDLE_TIMEOUT))?;
    recv_side.set_read_timeout(Some(IDLE_TIMEOUT))?;
    recv_side.set_write_timeout(Some(IDLE_TIMEOUT))?;

    // 先建写侧（写出自己的 24 字节头），再读对端头。
    let (writer, _h) = FrameWriter::new(send_side, &keys.send, aad_for(is_client, true))?;
    let (reader, _peer_h) = FrameReader::new(recv_side, &keys.recv, aad_for(is_client, false))?;
    Ok(Session { reader, writer, info })
}

fn read_client_hello(stream: &mut TcpStream) -> Result<(String, [u8; 32], [u8; 32], [u8; 32], [u8; 64])> {
    let mut magic = [0u8; 5];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(Error::Protocol("不是 SafeFile v2 设备（魔数不匹配）"));
    }
    let mut len = [0u8; 1];
    stream.read_exact(&mut len)?;
    let n = len[0] as usize;
    if n == 0 || n > NAME_MAX {
        return Err(Error::Protocol("设备名长度非法"));
    }
    let mut name = vec![0u8; n];
    stream.read_exact(&mut name)?;
    let name = String::from_utf8(name).map_err(|_| Error::Protocol("设备名不是合法 UTF-8"))?;
    let mut eph = [0u8; 32];
    let mut stat = [0u8; 32];
    let mut nonce = [0u8; 32];
    let mut sig = [0u8; 64];
    stream.read_exact(&mut eph)?;
    stream.read_exact(&mut stat)?;
    stream.read_exact(&mut nonce)?;
    stream.read_exact(&mut sig)?;
    let msg = handshake_signature_client(&name, &eph, &stat, &nonce);
    if !Identity::verify(&stat, &msg, &sig) {
        return Err(Error::AuthFailed);
    }
    Ok((name, eph, stat, nonce, sig))
}

fn client_handshake(mut stream: TcpStream, node: &Arc<LanNode>, expect: Option<[u8; 32]>) -> Result<Session> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_nodelay(true)?;

    let ident = node.identity().clone();
    let eph = kx::StackKeyPair::generate();
    let c_nonce = random32()?;
    let c_eph = arr32(&eph.public_key);
    let c_stat = ident.public_key;
    let c_name = ident.name.clone();

    let mut hello = Vec::with_capacity(200);
    hello.extend_from_slice(MAGIC);
    append_name(&mut hello, &c_name);
    hello.extend_from_slice(&c_eph);
    hello.extend_from_slice(&c_stat);
    hello.extend_from_slice(&c_nonce);
    hello.extend_from_slice(&ident.sign(&handshake_signature_client(
        &c_name, &c_eph, &c_stat, &c_nonce,
    )));
    stream.write_all(&hello)?;
    stream.flush()?;

    let mut status = [0u8; 1];
    stream.read_exact(&mut status)?;
    match status[0] {
        0 => {}
        2 => return Err(Error::IdentityChanged),
        _ => return Err(Error::PeerRejected("对端拒绝连接".into())),
    }

    let mut len = [0u8; 1];
    stream.read_exact(&mut len)?;
    let n = len[0] as usize;
    if n == 0 || n > NAME_MAX {
        return Err(Error::Protocol("对端设备名长度非法"));
    }
    let mut s_name = vec![0u8; n];
    stream.read_exact(&mut s_name)?;
    let s_name = String::from_utf8(s_name).map_err(|_| Error::Protocol("对端设备名不是合法 UTF-8"))?;

    let mut s_eph = [0u8; 32];
    let mut s_stat = [0u8; 32];
    let mut s_nonce = [0u8; 32];
    let mut sig = [0u8; 64];
    stream.read_exact(&mut s_eph)?;
    stream.read_exact(&mut s_stat)?;
    stream.read_exact(&mut s_nonce)?;
    stream.read_exact(&mut sig)?;

    let msg = handshake_signature_server(
        &c_name, &c_eph, &c_stat, &c_nonce, &s_name, &s_eph, &s_stat, &s_nonce,
    );
    if !Identity::verify(&s_stat, &msg, &sig) {
        return Err(Error::AuthFailed);
    }

    // 身份钉扎：广播里看到的公钥、或第一次信任时记下的公钥都必须一致。
    if let Some(pk) = expect {
        if pk != s_stat {
            return Err(Error::IdentityChanged);
        }
    }
    let sid = device_id(&s_stat);
    if let Some(known) = node.known_public_key(&sid) {
        if known != s_stat {
            return Err(Error::IdentityChanged);
        }
    }

    let shared = kx::StackSession::new_client(&eph, &kx::PublicKey::from(&s_eph))
        .map_err(|_| Error::AuthFailed)?;
    let tr = transcript(&c_name, &c_eph, &c_stat, &c_nonce, &s_name, &s_eph, &s_stat, &s_nonce);
    let keys = derive_keys(true, shared, &tr, &c_stat, &s_stat);
    let sas = keys.sas.clone();

    node.learn_peer_identity(&sid, &s_stat, &s_name);
    let info = SessionInfo {
        peer_id: sid,
        peer_name: s_name,
        peer_public_key: s_stat,
        sas,
    };
    open_session(stream, keys, true, info)
}


/// 服务端握手。身份变更时先回 status=2 再断开，客户端能给出准确提示。
fn server_handshake(mut stream: TcpStream, node: &Arc<LanNode>) -> Result<Session> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let (c_name, c_eph, c_stat, c_nonce, _c_sig) = read_client_hello(&mut stream)?;
    let cid = device_id(&c_stat);
    if node.trust_verdict(&cid, &c_stat) == crate::identity::Verdict::Changed {
        stream.write_all(&[2])?;
        let _ = stream.flush();
        return Err(Error::IdentityChanged);
    }

    let ident = node.identity().clone();
    let eph = kx::StackKeyPair::generate();
    let s_nonce = random32()?;
    let s_eph = arr32(&eph.public_key);
    let s_stat = ident.public_key;
    let s_name = ident.name.clone();

    let mut resp = Vec::with_capacity(200);
    resp.push(0u8);
    append_name(&mut resp, &s_name);
    resp.extend_from_slice(&s_eph);
    resp.extend_from_slice(&s_stat);
    resp.extend_from_slice(&s_nonce);
    resp.extend_from_slice(&ident.sign(&handshake_signature_server(
        &c_name, &c_eph, &c_stat, &c_nonce, &s_name, &s_eph, &s_stat, &s_nonce,
    )));
    stream.write_all(&resp)?;
    stream.flush()?;

    let shared = kx::StackSession::new_server(&eph, &kx::PublicKey::from(&c_eph))
        .map_err(|_| Error::AuthFailed)?;
    let tr = transcript(&c_name, &c_eph, &c_stat, &c_nonce, &s_name, &s_eph, &s_stat, &s_nonce);
    let keys = derive_keys(false, shared, &tr, &c_stat, &s_stat);
    let sas = keys.sas.clone();

    node.learn_peer_identity(&cid, &c_stat, &c_name);
    let info = SessionInfo {
        peer_id: cid,
        peer_name: c_name,
        peer_public_key: c_stat,
        sas,
    };
    open_session(stream, keys, false, info)
}

// ---------------------------------------------------------------------------
// 接收
// ---------------------------------------------------------------------------

struct Sink {
    file: BufWriter<File>,
    tmp: PathBuf,
    target: PathBuf,
    expected: u64,
    got: u64,
    hasher: blake3::Hasher,
    durable: bool,
}

impl Sink {
    fn create(dir: &Path, name: &str, expected: u64, durable: bool) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let target = dir.join(name);
        let salt = hex_of(&random32()?[..6]);
        let tmp = dir.join(format!(".safefile-{salt}.part"));
        let file = File::create(&tmp)?;
        Ok(Self {
            file: BufWriter::with_capacity(CHUNK, file),
            tmp,
            target,
            expected,
            got: 0,
            hasher: blake3::Hasher::new(),
            durable,
        })
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.file.write_all(data)?;
        self.hasher.update(data);
        self.got += data.len() as u64;
        if self.got > self.expected {
            return Err(Error::Protocol("收到的数据超过声明大小"));
        }
        Ok(())
    }

    fn finish(mut self, expected_hash: &str) -> Result<PathBuf> {
        self.file.flush()?;
        if self.durable {
            self.file.get_ref().sync_all()?;
        }
        drop(self.file);
        let got_hash = hex_of(self.hasher.finalize().as_bytes());
        if self.got != self.expected {
            let _ = fs::remove_file(&self.tmp);
            return Err(Error::SizeMismatch);
        }
        if !expected_hash.is_empty() && !got_hash.eq_ignore_ascii_case(expected_hash) {
            let _ = fs::remove_file(&self.tmp);
            return Err(Error::AuthFailed);
        }
        fs::rename(&self.tmp, &self.target)?;
        Ok(self.target)
    }

    fn abort(self) {
        drop(self.file);
        let _ = fs::remove_file(&self.tmp);
    }
}

fn receive_files(
    session: Session,
    save_dir: &Path,
    overwrite: bool,
    durable: bool,
    progress: &Arc<Mutex<Progress>>,
    cancel: &CancelToken,
) -> Result<()> {
    let Session { mut reader, mut writer, info } = session;
    set_peer(progress, &info);
    let started = Instant::now();

    let offer = reader.read_control()?;
    if offer.t != "offer" {
        return Err(Error::Protocol("期望 offer"));
    }
    if offer.files.len() > MAX_FILES {
        return Err(Error::Protocol("文件数量超过上限"));
    }

    let mut plans: Vec<(usize, String, u64, PathBuf, bool)> = Vec::new();
    let mut index = 0usize;
    for meta in &offer.files {
        let name = safe_name(&meta.name);
        let target = save_dir.join(&name);
        let skip = if target.exists() && !overwrite {
            true
        } else if target.is_dir() {
            true
        } else {
            false
        };
        plans.push((index, name, meta.size, target, skip));
        index += 1;
    }

    let mut total = 0u64;
    let mut skipped = 0usize;
    for (_, _, size, _, skip) in &plans {
        if *skip {
            skipped += 1;
        } else {
            total += *size;
        }
    }
    bump(progress, |p| {
        p.files_total = plans.len();
        p.total_bytes = total;
        p.skipped = skipped;
        p.current = String::new();
    });

    let skip_list: Vec<usize> = plans
        .iter()
        .filter(|(_, _, _, _, skip)| *skip)
        .map(|(i, _, _, _, _)| *i)
        .collect();
    let mut accept = Control::new("accept");
    accept.skip = skip_list;

    writer.send_json(&accept)?;

    for (i, name, size, _target, skip) in &plans {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if *skip {
            continue;
        }
        let start = reader.read_control()?;
        if start.t != "file_start" || start.index != *i {
            return Err(Error::Protocol("file_start 与 offer 不一致"));
        }
        if start.size != *size {
            return Err(Error::Protocol("文件大小与 offer 不一致"));
        }
        let mut sink = Sink::create(save_dir, name, *size, durable)?;
        bump(progress, |p| p.current = name.clone());

        let end_hash = loop {
            if cancel.is_cancelled() {
                sink.abort();
                return Err(Error::Cancelled);
            }
            let (kind, payload) = match reader.read() {
                Ok(v) => v,
                Err(e) => {
                    sink.abort();
                    return Err(e);
                }
            };
            match kind {
                KIND_DATA => {
                    let n = payload.len() as u64;
                    if let Err(e) = sink.write(payload) {
                        sink.abort();
                        return Err(e);
                    }
                    bump(progress, |p| {
                        p.done_bytes += n;
                        p.elapsed_ms = started.elapsed().as_millis() as u64;
                    });
                }
                KIND_CONTROL => {
                    let c: Control = serde_json::from_slice(payload)
                        .map_err(|_| Error::Protocol("控制帧 JSON 非法"))?;
                    if c.t != "file_end" {
                        sink.abort();
                        return Err(Error::Protocol("期望 file_end"));
                    }
                    break c.hash;
                }
                _ => {
                    sink.abort();
                    return Err(Error::Protocol("未知帧类型"));
                }
            }
        };

        match sink.finish(&end_hash) {
            Ok(path) => {
                let mut done = Control::new("file_done");
                done.index = *i;
                done.ok = true;
                writer.send_json(&done)?;
                bump(progress, |p| {
                    p.files_done += 1;
                    p.current = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                });
            }
            Err(e) => {
                let mut done = Control::new("file_done");
                done.index = *i;
                done.ok = false;
                done.message = e.to_string();
                let _ = writer.send_json(&done);
                return Err(e);
            }
        }
    }

    // 对端收尾（失败也无所谓，文件已经落盘）。
    let _ = reader.read_control();
    let _ = writer.send_json(&Control::new("bye"));
    bump(progress, |p| {
        p.finished = true;
        p.current = String::new();
        p.elapsed_ms = started.elapsed().as_millis() as u64;
    });
    Ok(())
}


// ---------------------------------------------------------------------------
// 发送
// ---------------------------------------------------------------------------

fn resolve_target(node: &Arc<LanNode>, peer: &str) -> Result<(String, Option<[u8; 32]>, String)> {
    let trimmed = peer.trim();
    if trimmed.is_empty() {
        return Err(Error::BadPath("目标为空".into()));
    }
    if trimmed.contains(':') && trimmed.parse::<SocketAddr>().is_ok() {
        return Ok((trimmed.to_string(), None, String::new()));
    }
    if let Some(p) = node.peer(trimmed) {
        let pk = decode_peer_key(&p)?;
        return Ok((p.addr.clone(), Some(pk), p.name));
    }
    // 设备 id 但本地邻居表还没收录：先主动探测，给广播/应答留出往返时间。
    // （命令行的每个进程都是新节点，不能指望它启动时就已经认识对方。）
    if looks_like_device_id(trimmed) {
        node.probe();
        let deadline = Instant::now() + Duration::from_millis(2500);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(p) = node.peer(trimmed) {
                let pk = decode_peer_key(&p)?;
                return Ok((p.addr.clone(), Some(pk), p.name));
            }
        }
    }
    // 也可能是「ip:port」但带主机名，或者直接是 IP（补默认端口）。
    if let Ok(sa) = trimmed.to_socket_addrs().map(|mut it| it.next()) {
        if let Some(sa) = sa {
            return Ok((sa.to_string(), None, String::new()));
        }
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Ok((format!("{ip}:{DEFAULT_PORT}"), None, String::new()));
    }
    Err(Error::PeerNotFound(peer.to_string()))
}

fn looks_like_device_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn decode_peer_key(p: &PeerInfo) -> Result<[u8; 32]> {
    let bytes = hex_decode(&p.public_key).ok_or(Error::Protocol("设备公钥格式非法"))?;
    if bytes.len() != 32 {
        return Err(Error::Protocol("设备公钥长度非法"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 发送文件到一台设备。`peer` 可以是设备 id（来自广播列表）或 `ip:port`。
pub fn send_files(
    peer: &str,
    files: &[(PathBuf, String)],
    progress: &Arc<Mutex<Progress>>,
    cancel: &CancelToken,
) -> Result<()> {
    if files.is_empty() {
        return Err(Error::BadPath("没有要发送的文件".into()));
    }
    let started = Instant::now();
    let node = lan::global()?;
    let (addr, expect, name) = resolve_target(&node, peer)?;

    let mut metas = Vec::with_capacity(files.len());
    let mut total = 0u64;
    for (path, display) in files {
        let meta = fs::metadata(path)?;
        if !meta.is_file() {
            return Err(Error::BadPath(format!("不是普通文件：{}", path.display())));
        }
        total += meta.len();
        metas.push(FileMeta {
            name: if display.is_empty() {
                path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".to_string())
            } else {
                display.clone()
            },
            size: meta.len(),
        });
    }
    bump(progress, |p| {
        p.files_total = files.len();
        p.total_bytes = total;
        p.peer = name.clone();
        p.current = String::new();
    });

    let sa: SocketAddr = addr
        .to_socket_addrs()
        .map_err(|_| Error::PeerNotFound(addr.clone()))?
        .next()
        .ok_or_else(|| Error::PeerNotFound(addr.clone()))?;
    let stream = TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT)
        .map_err(|e| Error::Transfer(format!("无法连接 {}：{e}", sa)))?;
    let session = client_handshake(stream, &node, expect)?;
    let Session { mut reader, mut writer, info } = session;
    set_peer(progress, &info);
    bump(progress, |p| {
        if p.peer.is_empty() {
            p.peer = info.peer_name.clone();
        }
        p.sas = info.sas.clone();
    });

    let mut offer = Control::new("offer");
    offer.files = metas.clone();
    writer.send_json(&offer)?;

    let accept = reader.read_control()?;
    if accept.t != "accept" {
        return Err(Error::PeerRejected(accept.message));
    }
    let skip: std::collections::HashSet<usize> = accept.skip.into_iter().collect();
    bump(progress, |p| p.skipped = skip.len());

    for (i, ((path, _display), meta)) in files.iter().zip(metas.iter()).enumerate() {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if skip.contains(&i) {
            continue;
        }
        let mut start = Control::new("file_start");
        start.index = i;
        start.name = meta.name.clone();
        start.size = meta.size;
        writer.send_json(&start)?;

        let file = File::open(path)?;
        let mut inp = BufReader::with_capacity(CHUNK, file);
        let mut buf = vec![0u8; CHUNK];
        let mut hasher = blake3::Hasher::new();
        let mut sent = 0u64;
        bump(progress, |p| p.current = meta.name.clone());
        loop {
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            let n = inp.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            writer.send(KIND_DATA, &buf[..n])?;
            sent += n as u64;
            bump(progress, |p| {
                p.done_bytes += n as u64;
                p.elapsed_ms = started.elapsed().as_millis() as u64;
            });
        }
        if sent != meta.size {
            return Err(Error::Transfer(format!("文件在发送过程中被修改：{}", meta.name)));
        }
        let mut end = Control::new("file_end");
        end.index = i;
        end.hash = hex_of(hasher.finalize().as_bytes());
        writer.send_json(&end)?;

        let done = reader.read_control()?;
        if done.t != "file_done" || done.index != i {
            return Err(Error::Protocol("期望 file_done"));
        }
        if !done.ok {
            return Err(Error::Transfer(if done.message.is_empty() {
                "对端写入失败".to_string()
            } else {
                done.message
            }));
        }
        bump(progress, |p| {
            p.files_done += 1;
            p.current = String::new();
        });
    }

    let _ = writer.send_json(&Control::new("bye"));
    let _ = reader.read_control();
    bump(progress, |p| {
        p.finished = true;
        p.elapsed_ms = started.elapsed().as_millis() as u64;
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// 接收端
// ---------------------------------------------------------------------------

struct BusyGuard<'a>(&'a AtomicBool);
impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// 固定端口的接收端。持有 TCP 监听器，并把「正在等待接收」的状态广播出去。
pub struct ShareServer {
    listener: TcpListener,
    save_dir: PathBuf,
    overwrite: bool,
    durable: bool,
    node: Arc<LanNode>,
    port: u16,
    stop: Arc<AtomicBool>,
    busy: Arc<AtomicBool>,
}

impl ShareServer {
    /// 绑定接收端口。`port == 0` 时用固定端口 [`DEFAULT_PORT`]。
    pub fn bind(save_dir: PathBuf, port: u16, overwrite: bool, durable: bool) -> Result<Self> {
        let node = lan::global()?;
        let wanted = if port == 0 { DEFAULT_PORT } else { port };
        let listener = TcpListener::bind(("0.0.0.0", wanted)).map_err(|e| {
            Error::Transfer(format!(
                "端口 {wanted} 被占用（可能已有接收端在运行）：{e}"
            ))
        })?;
        let actual = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        node.set_tcp_port(actual);
        node.set_accepting(true);
        Ok(Self {
            listener,
            save_dir,
            overwrite,
            durable,
            node,
            port: actual,
            stop: Arc::new(AtomicBool::new(false)),
            busy: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn info(&self) -> ShareInfo {
        ShareInfo {
            name: self.node.name().to_string(),
            id: self.node.id().to_string(),
            fingerprint: self.node.identity().fingerprint.clone(),
            port: self.port,
            addrs: lan::local_addrs(),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn node(&self) -> Arc<LanNode> {
        self.node.clone()
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.node.set_accepting(false);
    }

    fn serve(
        &self,
        stream: TcpStream,
        progress: &Arc<Mutex<Progress>>,
        cancel: &CancelToken,
    ) -> Result<()> {
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err(Error::PeerBusy);
        }
        let _guard = BusyGuard(&self.busy);
        stream.set_nonblocking(false)?;
        let session = server_handshake(stream, &self.node)?;
        receive_files(session, &self.save_dir, self.overwrite, self.durable, progress, cancel)
    }

    /// 等到一次连接（最多 `timeout`），服务完返回 `Ok(true)`；超时返回 `Ok(false)`。
    pub fn accept_once_timeout(
        &self,
        progress: &Arc<Mutex<Progress>>,
        cancel: &CancelToken,
        timeout: Duration,
    ) -> Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.stop.load(Ordering::SeqCst) || cancel.is_cancelled() {
                return Ok(false);
            }
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    self.serve(stream, progress, cancel)?;
                    return Ok(true);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Ok(false);
                    }
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }

    /// 阻塞到有一次完整接收（或出错/取消）。
    pub fn accept_one(&self, progress: &Arc<Mutex<Progress>>, cancel: &CancelToken) -> Result<()> {
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Err(Error::Cancelled);
            }
            if self.accept_once_timeout(progress, cancel, Duration::from_secs(1))? {
                return Ok(());
            }
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
        }
    }
}

impl Drop for ShareServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 主动探测一次，并在 `timeout` 后返回当前看到的设备列表。
pub fn discover(timeout: Duration) -> Result<Vec<PeerInfo>> {
    let node = lan::global()?;
    node.probe();
    std::thread::sleep(timeout);
    Ok(node.peers())
}

/// 把设备列表序列化成 FFI 用的 JSON。
pub fn peers_json(peers: &[PeerInfo]) -> Value {
    json!(peers)
}
