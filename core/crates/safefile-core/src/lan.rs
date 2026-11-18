//! 局域网节点：固定端口 UDP 广播 + 签名公告 + 自动发现。
//!
//! 关键设计
//! --------
//! * **没有配对码**。设备身份就是一对持久 Ed25519 密钥；广播包带签名，
//!   收到后先验签、再用 `device_id == BLAKE3(pk)` 绑定「名字/地址/公钥」 inseparable，
//!   因此搜索列表里出现的任何设备都真的持有对应私钥。
//! * 固定端口：发现用 UDP 47777，传输用 TCP 47778（被占用时允许回退到临时端口，
//!   端口号写在广播包里，对端无需手输）。
//! * 自动配对：两端都监听同一个 UDP 端口，启动时各发一次探测、之后每 2s 广播一次
//!   公告；谁先上线都能互相看到，不需要任何人工步骤。
//! * 安全边界：广播只用于发现（名字/地址/是否可接收），传输内容永远走
//!   TCP + X25519 ECDH + Ed25519 双向认证 + XChaCha20-Poly1305（见 transfer.rs）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// 显式开 `SO_REUSEADDR` 绑发现端口：同一台机器上可能同时跑 App 与 CLI，
/// 或者用户开了两个窗口；不允许复用时后启动的进程会静默失去发现能力。
fn bind_discovery(port: u16) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    let addr: std::net::SocketAddr = ([0, 0, 0, 0], port).into();
    sock.bind(&addr.into())?;
    sock.set_read_timeout(Some(Duration::from_millis(400)))?;
    Ok(sock.into())
}

use crate::error::Result;
use crate::identity::{device_id, fingerprint, hex_decode, hex_encode, Identity, TrustStore, Verdict, NAME_MAX};

/// 固定发现端口。
pub const DISCOVERY_PORT: u16 = 47777;
/// 固定传输端口。
pub const DEFAULT_PORT: u16 = 47778;

const MAGIC: &[u8; 4] = b"SFB2";
const PROBE: &[u8] = b"SFB2?";
const VERSION: u8 = 2;
/// 4 magic + 1 version + 1 flags + 2 tcp_port + 8 seq + 1 name_len
const BEACON_HEAD: usize = 17;
const BEACON_TAIL: usize = 32 + 64; // Ed25519 公钥 + 签名
const BEACON_INTERVAL: Duration = Duration::from_secs(2);
const PEER_TTL: Duration = Duration::from_secs(9);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 自动发现到的一台设备。
#[derive(Debug, Clone, Serialize)]
pub struct PeerInfo {
    /// 由公钥派生的 16 位十六进制设备 id。
    pub id: String,
    /// 设备自报的名字（已随公告签名，不可被局域网内第三方篡改）。
    pub name: String,
    /// `ip:port`，传输用的 TCP 地址。
    pub addr: String,
    /// 公钥十六进制，发送时用于固定对端身份。
    pub public_key: String,
    /// 指纹，供人工核对。
    pub fingerprint: String,
    /// 是否正在等待接收（否则只能作为发送方）。
    pub accepting: bool,
    /// 最近一次收到公告的本地时间（毫秒时间戳）。
    pub last_seen_ms: u64,
}

/// 本机节点状态（给 UI 展示，不含任何秘密）。
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    pub public_key: String,
    pub port: u16,
    pub discovery_port: u16,
    pub addrs: Vec<String>,
    pub accepting: bool,
    /// 发现服务是否成功绑定端口。绑定失败时传输仍可用（可手动填地址）。
    pub discovery_ok: bool,
    pub discovery_error: Option<String>,
    pub trusted_peer_count: usize,
    pub peer_count: usize,
}

/// 一台局域网节点。进程内单例（[`global`]），后台线程负责收发广播。
pub struct LanNode {
    identity: Arc<Identity>,
    socket: Option<UdpSocket>,
    discovery_port: u16,
    discovery_error: Option<String>,
    tcp_port: AtomicU16,
    accepting: AtomicBool,
    peers: Mutex<HashMap<String, PeerInfo>>,
    seen: Mutex<HashMap<String, Instant>>,
    trust: Mutex<TrustStore>,
    seq: AtomicU64,
    stop: AtomicBool,
    dir: PathBuf,
}

impl LanNode {
    /// 建立节点：加载/生成身份、打开固定 UDP 端口、启动广播线程。
    ///
    /// UDP 端口被占用时不会失败：`discovery_ok=false`，传输依旧可用。
    pub fn start(dir: &Path, discovery_port: u16) -> Result<Arc<Self>> {
        let identity = Identity::load_or_create(dir)?;
        let trust = TrustStore::open(dir)?;
        let mut discovery_error = None;
        let socket = match bind_discovery(discovery_port) {
            Ok(s) => Some(s),
            Err(e) => {
                discovery_error = Some(format!("发现端口 {discovery_port} 不可用：{e}"));
                None
            }
        };
        // 允许测试用 0 让系统分配端口；对外公布的永远是实际端口。
        let bound_port = socket
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(discovery_port);
        let node = Arc::new(Self {
            identity,
            socket,
            discovery_port: bound_port,
            discovery_error,
            tcp_port: AtomicU16::new(DEFAULT_PORT),
            accepting: AtomicBool::new(false),
            peers: Mutex::new(HashMap::new()),
            seen: Mutex::new(HashMap::new()),
            trust: Mutex::new(trust),
            seq: AtomicU64::new(1),
            stop: AtomicBool::new(false),
            dir: dir.to_path_buf(),
        });
        if node.socket.is_some() {
            let weak = Arc::downgrade(&node);
            std::thread::Builder::new()
                .name("safefile-lan-recv".into())
                .spawn(move || {
                    while let Some(n) = weak.upgrade() {
                        if n.stop.load(Ordering::Relaxed) {
                            break;
                        }
                        n.recv_once();
                    }
                })
                .ok();
            let weak = Arc::downgrade(&node);
            std::thread::Builder::new()
                .name("safefile-lan-beacon".into())
                .spawn(move || {
                    // 上线立刻探测一次，不等第一个 2s 周期。
                    std::thread::sleep(Duration::from_millis(120));
                    while let Some(n) = weak.upgrade() {
                        if n.stop.load(Ordering::Relaxed) {
                            break;
                        }
                        n.send_probe();
                        n.send_beacon_all();
                        n.prune();
                        std::thread::sleep(BEACON_INTERVAL);
                    }
                })
                .ok();
        }
        Ok(node)
    }

    pub fn identity(&self) -> &Arc<Identity> {
        &self.identity
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn id(&self) -> &str {
        &self.identity.id
    }

    pub fn name(&self) -> &str {
        &self.identity.name
    }

    pub fn set_tcp_port(&self, port: u16) {
        if port > 0 {
            self.tcp_port.store(port, Ordering::Relaxed);
        }
    }

    pub fn tcp_port(&self) -> u16 {
        self.tcp_port.load(Ordering::Relaxed)
    }

    pub fn set_accepting(&self, on: bool) {
        self.accepting.store(on, Ordering::Relaxed);
        if on {
            // 立刻把「可接收」状态播出去，别让对端等下一个周期。
            self.send_beacon_all();
        }
    }

    pub fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Relaxed)
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        let mut list: Vec<PeerInfo> = self
            .peers
            .lock()
            .map(|g| g.values().cloned().collect())
            .unwrap_or_default();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    pub fn peer(&self, id: &str) -> Option<PeerInfo> {
        self.peers.lock().ok()?.get(id).cloned()
    }

    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            id: self.identity.id.clone(),
            name: self.identity.name.clone(),
            fingerprint: self.identity.fingerprint.clone(),
            public_key: self.identity.public_key_hex(),
            port: self.tcp_port(),
            discovery_port: self.discovery_port,
            addrs: local_addrs(),
            accepting: self.is_accepting(),
            discovery_ok: self.socket.is_some() && self.discovery_error.is_none(),
            discovery_error: self.discovery_error.clone(),
            trusted_peer_count: self.trust.lock().map(|t| t.count()).unwrap_or(0),
            peer_count: self.peers.lock().map(|p| p.len()).unwrap_or(0),
        }
    }

    pub fn trust_verdict(&self, id: &str, public_key: &[u8; 32]) -> Verdict {
        self.trust
            .lock()
            .map(|t| t.verdict(id, public_key))
            .unwrap_or(Verdict::New)
    }

    pub fn learn_peer_identity(&self, id: &str, public_key: &[u8; 32], name: &str) {
        if let Ok(mut t) = self.trust.lock() {
            t.learn(id, public_key, name);
        }
    }

    pub fn known_public_key(&self, id: &str) -> Option<[u8; 32]> {
        let t = self.trust.lock().ok()?;
        let known = t.known(id)?;
        let bytes = hex_decode(&known.public_key)?;
        if bytes.len() != 32 {
            return None;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        Some(pk)
    }

    /// 立刻广播一次探测（UI 下拉刷新、刚打开页面时用）。
    pub fn probe(&self) {
        self.send_probe();
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.accepting.store(false, Ordering::Relaxed);
    }

    // ---- 广播包 ----

    fn beacon_bytes(&self) -> Vec<u8> {
        let name = self.identity.name.as_bytes();
        let name = &name[..name.len().min(NAME_MAX)];
        let pk_at = BEACON_HEAD + name.len();
        let sig_at = pk_at + 32;
        let mut buf = vec![0u8; sig_at + 64];
        buf[..4].copy_from_slice(MAGIC);
        buf[4] = VERSION;
        buf[5] = u8::from(self.is_accepting());
        buf[6..8].copy_from_slice(&self.tcp_port().to_le_bytes());
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        buf[8..16].copy_from_slice(&seq.to_le_bytes());
        buf[16] = name.len() as u8;
        buf[BEACON_HEAD..pk_at].copy_from_slice(name);
        buf[pk_at..sig_at].copy_from_slice(&self.identity.public_key);
        let sig = self.identity.sign(&buf[..sig_at]);
        buf[sig_at..].copy_from_slice(&sig);
        buf
    }

    fn send_beacon_all(&self) {
        let Some(sock) = &self.socket else { return };
        let beacon = self.beacon_bytes();
        for addr in broadcast_targets(self.discovery_port) {
            let _ = sock.send_to(&beacon, addr);
        }
        // 兜底：部分系统/防火墙只放行受限广播。
        let _ = sock.send_to(&beacon, SocketAddrV4::new(Ipv4Addr::BROADCAST, self.discovery_port));
    }

    fn send_probe(&self) {
        let Some(sock) = &self.socket else { return };
        for addr in broadcast_targets(self.discovery_port) {
            let _ = sock.send_to(PROBE, addr);
        }
        let _ = sock.send_to(PROBE, SocketAddrV4::new(Ipv4Addr::BROADCAST, self.discovery_port));
    }

    fn recv_once(&self) {
        let Some(sock) = &self.socket else { return };
        let mut buf = [0u8; 256];
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => return,
        };
        let IpAddr::V4(src_ip) = src.ip() else { return };
        if src_ip.is_loopback() {
            return;
        }
        if n == PROBE.len() && &buf[..n] == PROBE {
            let beacon = self.beacon_bytes();
            let _ = sock.send_to(&beacon, src);
            return;
        }
        if n < BEACON_HEAD + BEACON_TAIL {
            return;
        }
        let Some(peer) = self.parse_beacon(&buf[..n], src_ip) else {
            return;
        };
        if peer.id == self.identity.id {
            return;
        }
        let now = Instant::now();
        if let Ok(mut peers) = self.peers.lock() {
            peers.insert(peer.id.clone(), peer.clone());
        }
        if let Ok(mut seen) = self.seen.lock() {
            seen.insert(peer.id, now);
        }
    }

    fn parse_beacon(&self, buf: &[u8], src_ip: Ipv4Addr) -> Option<PeerInfo> {
        if buf.len() < BEACON_HEAD + BEACON_TAIL || &buf[..4] != MAGIC || buf[4] != VERSION {
            return None;
        }
        let flags = buf[5];
        let tcp_port = u16::from_le_bytes([buf[6], buf[7]]);
        if tcp_port == 0 {
            return None;
        }
        let name_len = buf[16] as usize;
        if name_len == 0 || name_len > NAME_MAX {
            return None;
        }
        if buf.len() != BEACON_HEAD + name_len + BEACON_TAIL {
            return None;
        }
        let name = std::str::from_utf8(&buf[BEACON_HEAD..BEACON_HEAD + name_len]).ok()?;
        if name.trim().is_empty() {
            return None;
        }
        let pk_at = BEACON_HEAD + name_len;
        let sig_at = pk_at + 32;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[pk_at..sig_at]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&buf[sig_at..]);
        if !Identity::verify(&pk, &buf[..sig_at], &sig) {
            return None;
        }
        Some(PeerInfo {
            id: device_id(&pk),
            name: name.to_string(),
            addr: format!("{src_ip}:{tcp_port}"),
            public_key: hex_encode(&pk),
            fingerprint: fingerprint(&pk),
            accepting: flags & 1 != 0,
            last_seen_ms: now_ms(),
        })
    }

    fn prune(&self) {
        let now = Instant::now();
        let mut stale = Vec::new();
        if let Ok(seen) = self.seen.lock() {
            for (id, at) in seen.iter() {
                if now.duration_since(*at) > PEER_TTL {
                    stale.push(id.clone());
                }
            }
        }
        if stale.is_empty() {
            return;
        }
        if let Ok(mut peers) = self.peers.lock() {
            for id in &stale {
                peers.remove(id);
            }
        }
        if let Ok(mut seen) = self.seen.lock() {
            for id in &stale {
                seen.remove(id);
            }
        }
    }
}

/// 枚举本机所有非回环 IPv4 的定向广播地址；失败时退回受限广播。
pub fn broadcast_targets(port: u16) -> Vec<SocketAddrV4> {
    let mut out = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for it in ifaces {
            if it.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = it.addr {
                if v4.ip.is_unspecified() {
                    continue;
                }
                let bcast = v4
                    .broadcast
                    .unwrap_or_else(|| {
                        let mask = u32::from(v4.netmask);
                        Ipv4Addr::from(u32::from(v4.ip) | !mask)
                    });
                let addr = SocketAddrV4::new(bcast, port);
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
    }
    if out.is_empty() {
        out.push(SocketAddrV4::new(Ipv4Addr::BROADCAST, port));
    }
    out
}

/// 本机 IPv4 地址列表（去掉回环/链路本地）。
pub fn local_addrs() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for it in ifaces {
            if it.is_loopback() {
                continue;
            }
            if let IpAddr::V4(ip) = it.ip() {
                if !ip.is_unspecified() && !ip.is_loopback() {
                    let s = ip.to_string();
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
        }
    }
    if out.is_empty() {
        // 最坏情况：用一条「连出去」的路由探测默认出口地址。
        if let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0)) {
            if sock.connect(("8.8.8.8", 53)).is_ok() {
                if let Ok(local) = sock.local_addr() {
                    if let IpAddr::V4(ip) = local.ip() {
                        out.push(ip.to_string());
                    }
                }
            }
        }
    }
    out
}

/// 配置目录：优先环境变量（测试/多实例），否则按平台惯例。
pub fn default_config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SAFEFILE_CONFIG_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("SafeFile");
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("safefile");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".config/safefile");
        }
    }
    std::env::temp_dir().join("safefile")
}

fn env_discovery_port() -> Option<u16> {
    std::env::var("SAFEFILE_DISCOVERY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
}

static NODE: OnceLock<Arc<LanNode>> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::new(());

/// 初始化全局节点（可重复调用，第二次起忽略参数）。App 启动时用持久目录调用；
/// CLI / FFI 不调用时会自动使用 [`default_config_dir`]。
pub fn init(dir: &Path, discovery_port: Option<u16>) -> Result<Arc<LanNode>> {
    let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(node) = NODE.get() {
        return Ok(Arc::clone(node));
    }
    let port = discovery_port
        .or_else(env_discovery_port)
        .unwrap_or(DISCOVERY_PORT);
    let node = LanNode::start(dir, port)?;
    if NODE.set(Arc::clone(&node)).is_err() {
        return Ok(Arc::clone(NODE.get().unwrap()));
    }
    Ok(node)
}

/// 取全局节点，未初始化时按默认配置目录创建。
pub fn global() -> Result<Arc<LanNode>> {
    if let Some(node) = NODE.get() {
        return Ok(Arc::clone(node));
    }
    init(&default_config_dir(), None)
}

/// 便于测试：若尚未初始化则以指定目录初始化，否则复用。
#[cfg(test)]
pub fn init_for_test(dir: &Path) -> Arc<LanNode> {
    init(dir, Some(0)).unwrap_or_else(|_| global().unwrap())
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<LanNode>();
    check::<TrustStore>();
    check::<Identity>();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let root = std::env::var_os("SAFEFILE_TEST_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let p = root.join(format!("sflan-{tag}-{}", now_ms()));
        p
    }

    #[test]
    fn beacon_is_signed_and_carries_port() {
        let dir = tmpdir("beacon");
        let node = LanNode::start(&dir, 0).unwrap();
        node.set_tcp_port(47778);
        let beacon = node.beacon_bytes();
        assert_eq!(&beacon[..4], MAGIC);
        let peer = node.parse_beacon(&beacon, Ipv4Addr::new(192, 168, 1, 7)).unwrap();
        assert_eq!(peer.id, node.id());
        assert_eq!(peer.addr, "192.168.1.7:47778");
        assert!(!peer.accepting);

        // 篡改一个字节必须验签失败
        let mut bad = beacon;
        bad[20] ^= 0xff;
        assert!(node.parse_beacon(&bad, Ipv4Addr::new(192, 168, 1, 7)).is_none());
        node.shutdown();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_addrs_are_reported() {
        let addrs = local_addrs();
        for a in &addrs {
            let ip: Ipv4Addr = a.parse().unwrap();
            assert!(!ip.is_loopback());
        }
    }
}
