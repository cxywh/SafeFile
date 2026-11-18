//! 设备身份：持久的 Ed25519 密钥、由公钥一次性派生的随机名称、TOFU 信任库。
//!
//! 设计要点（与 docs/02-crypto-protocol.md 的「局域网 v2」一节对应）：
//!
//! * 每台设备首次启动时生成一对 Ed25519 身份密钥，保存在 `<config>/device.json`（权限 0600）。
//! * 设备名只在**首次生成**时随机产生一次并持久化，此后永不改变——
//!   因此「同一台设备最多只有一个名字」，重启、换网、重装 App 都不会变。
//! * `device_id = BLAKE3("safefile device id v1" || pk)[..8]`，用于在广播与传输中索引设备，
//!   不暴露公钥以外的任何信息；名称只用于显示，不参与认证。
//! * 指纹 `BLAKE3("safefile device fingerprint v1" || pk)[..10]` 以 5 组 4 位十六进制展示，
//!   供用户人工核对（配合握手结束后两端一致的 6 位 SAS）。
//! * `trust.json` 记录首次见到的 `id → 公钥`。若同一 id 再次出现却换了公钥，一律拒绝，
//!   防的是「局域网内冒充成你上次传过文件的设备」。

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dryoc::classic::crypto_sign::{crypto_sign_detached, crypto_sign_verify_detached};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// 设备名最大字节数（广播包与握手都用 1 字节长度）。
pub const NAME_MAX: usize = 64;

/// 名称词表：形容词 × 名词 × 1 字节后缀，保证「随机、可读、近乎不重复」。
const ADJECTIVES: &[&str] = &[
    "琥珀", "青瓷", "松雾", "流云", "星屑", "铜绿", "夜航", "浮光", "霜蓝", "橙砂", "墨玉", "雪松",
    "暖砂", "雨林", "晨雾", "焰红", "海盐", "月白", "山岚", "霓青", "静水", "秋杏", "银霜", "苔原",
];
const NOUNS: &[&str] = &[
    "山雀", "鲸鱼", "狐狸", "白鹭", "野兔", "海豚", "猫头鹰", "麋鹿", "猎豹", "企鹅", "水獭",
    "刺猬", "燕子", "蝴蝶", "松鼠", "仙鹤", "河马", "羊驼", "萤火", "珊瑚", "竹节", "松果", "苔藓",
    "风铃",
];

/// 与 Dart 侧 `hex` 互操作的小工具。
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in bytes.chunks(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::Internal("系统随机数不可用"))?;
    Ok(out)
}

/// 由公钥派生的稳定设备 id（16 位十六进制）。
pub fn device_id(public_key: &[u8; 32]) -> String {
    let h = blake3::derive_key("safefile device id v1", public_key);
    hex_encode(&h[..8])
}

/// 由公钥派生的指纹，格式 `ABCD EF01 2345 6789 AB`。
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let h = blake3::derive_key("safefile device fingerprint v1", public_key);
    let hex = hex_encode(&h[..10]);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or("?").to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// 首次生成名称：随机、可读、持久。之后名称从 `device.json` 读取，绝不重算。
pub fn generate_name(public_key: &[u8; 32]) -> String {
    let h = blake3::derive_key("safefile device name v1", public_key);
    let a = ADJECTIVES[(h[0] as usize) % ADJECTIVES.len()];
    let n = NOUNS[(h[1] as usize) % NOUNS.len()];
    format!("{a}{n}·{:02X}", h[3])
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    v: u8,
    secret_key: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    created_ms: u64,
}

/// 本机设备身份。密钥放在 `Zeroizing` 里，Drop 时清零。
pub struct Identity {
    secret: Zeroizing<[u8; 64]>,
    pub public_key: [u8; 32],
    pub name: String,
    pub id: String,
    pub fingerprint: String,
    pub created_ms: u64,
}

impl Identity {
    /// 从 `dir/device.json` 读取身份；不存在则生成并落盘。
    pub fn load_or_create(dir: &Path) -> Result<Arc<Self>> {
        fs::create_dir_all(dir)?;
        let path = dir.join("device.json");
        if path.exists() {
            if let Ok(identity) = Self::load(&path) {
                return Ok(Arc::new(identity));
            }
            // 文件损坏：留档后重新生成，避免 App 永久起不来。
            let backup = dir.join(format!("device.broken.{}.json", now_ms()));
            let _ = fs::rename(&path, backup);
        }
        let identity = Self::generate()?;
        identity.save(&path)?;
        Ok(Arc::new(identity))
    }

    fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let doc: StoredIdentity =
            serde_json::from_str(&text).map_err(|_| Error::Internal("device.json 已损坏"))?;
        if doc.v != 1 {
            return Err(Error::Internal("device.json 版本不受支持"));
        }
        let sk = hex_decode(&doc.secret_key).ok_or(Error::Internal("device.json 密钥格式错误"))?;
        if sk.len() != 64 {
            return Err(Error::Internal("device.json 密钥长度错误"));
        }
        let mut secret = Zeroizing::new([0u8; 64]);
        secret.copy_from_slice(&sk);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&secret[32..]);
        // 自检：私钥必须能签出可被公钥验证的签名，防止文件被随意改写。
        let probe = b"safefile identity self-check";
        let sig = Self::sign_with(&secret, probe);
        if !Self::verify(&public_key, probe, &sig) {
            return Err(Error::Internal("device.json 密钥自检失败"));
        }
        let name = doc
            .name
            .filter(|n| !n.trim().is_empty() && n.len() <= NAME_MAX)
            .unwrap_or_else(|| generate_name(&public_key));
        Ok(Self {
            secret,
            public_key,
            id: device_id(&public_key),
            fingerprint: fingerprint(&public_key),
            name,
            created_ms: if doc.created_ms == 0 { now_ms() } else { doc.created_ms },
        })
    }

    fn generate() -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; 64]);
        // 前 32 字节是种子，后 32 字节是公钥（Ed25519 sk 的标准布局）。
        let seed: [u8; 32] = random_bytes()?;
        let kp: dryoc::sign::StackSigningKeyPair =
            dryoc::sign::SigningKeyPair::from_seed(&seed);
        secret.copy_from_slice(kp.secret_key.as_ref());
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(kp.public_key.as_ref());
        Ok(Self {
            secret,
            public_key,
            id: device_id(&public_key),
            fingerprint: fingerprint(&public_key),
            name: generate_name(&public_key),
            created_ms: now_ms(),
        })
    }

    fn save(&self, path: &Path) -> Result<()> {
        let doc = StoredIdentity {
            v: 1,
            secret_key: hex_encode(self.secret.as_slice()),
            name: Some(self.name.clone()),
            created_ms: self.created_ms,
        };
        let text = serde_json::to_vec_pretty(&doc)
            .map_err(|_| Error::Internal("device.json 序列化失败"))?;
        write_private(path, &text)?;
        Ok(())
    }

    fn sign_with(secret: &[u8; 64], message: &[u8]) -> [u8; 64] {
        let mut sig = [0u8; 64];
        let _ = crypto_sign_detached(&mut sig, message, secret);
        sig
    }

    /// 用本机身份签名。
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        Self::sign_with(&self.secret, message)
    }

    /// 校验任意设备公钥的签名。
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        crypto_sign_verify_detached(signature, message, public_key).is_ok()
    }

    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.public_key)
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
        f.sync_all()
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::File::create(path)?;
        f.write_all(data)?;
        f.sync_all()
    }
}

/// 对端身份的信任判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 与记录一致。
    Trusted,
    /// 首次见到，握手成功后记录（TOFU）。
    New,
    /// id 已存在但公钥变了——可能是冒充，拒绝。
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPeer {
    pub public_key: String,
    pub name: String,
    pub first_seen_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct TrustDoc {
    v: u8,
    #[serde(default)]
    peers: BTreeMap<String, TrustPeer>,
}

/// 简单的 TOFU 信任库，整体读写，量级是「几台设备」。
pub struct TrustStore {
    path: PathBuf,
    doc: TrustDoc,
}

impl TrustStore {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join("trust.json");
        let doc = match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or(TrustDoc {
                v: 1,
                peers: BTreeMap::new(),
            }),
            Err(_) => TrustDoc {
                v: 1,
                peers: BTreeMap::new(),
            },
        };
        Ok(Self { path, doc })
    }

    pub fn verdict(&self, id: &str, public_key: &[u8; 32]) -> Verdict {
        match self.doc.peers.get(id) {
            Some(known) if known.public_key == hex_encode(public_key) => Verdict::Trusted,
            Some(_) => Verdict::Changed,
            None => Verdict::New,
        }
    }

    /// 记录（或刷新）一台设备，落盘失败只告警不阻断传输。
    pub fn learn(&mut self, id: &str, public_key: &[u8; 32], name: &str) {
        let pk_hex = hex_encode(public_key);
        let entry = self.doc.peers.get_mut(id);
        match entry {
            Some(e) => {
                e.name = name.to_string();
            }
            None => {
                self.doc.peers.insert(
                    id.to_string(),
                    TrustPeer {
                        public_key: pk_hex,
                        name: name.to_string(),
                        first_seen_ms: now_ms(),
                    },
                );
            }
        }
        let _ = self.flush();
    }

    /// 校验通过后推进「最近一次成功传输」时间，桌面端可据此做二次确认。
    pub fn touch(&mut self, id: &str) {
        if let Some(e) = self.doc.peers.get_mut(id) {
            e.first_seen_ms = e.first_seen_ms.max(now_ms());
        }
    }

    pub fn known(&self, id: &str) -> Option<&TrustPeer> {
        self.doc.peers.get(id)
    }

    pub fn count(&self) -> usize {
        self.doc.peers.len()
    }

    fn flush(&self) -> Result<()> {
        let text = serde_json::to_vec_pretty(&self.doc)
            .map_err(|_| Error::Internal("trust.json 序列化失败"))?;
        write_private(&self.path, &text)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试目录：优先 `SAFEFILE_TEST_DIR`（受限环境下临时目录可能不可写）。
    fn test_root() -> PathBuf {
        std::env::var_os("SAFEFILE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
    }

    #[test]
    fn identity_roundtrip_keeps_name_and_keys() {
        let dir = test_root().join(format!("sfid-{}", now_ms()));
        let a = Identity::load_or_create(&dir).unwrap();
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.public_key, b.public_key);
        assert_eq!(a.name, b.name);
        assert_eq!(a.id, b.id);
        assert!(a.name.len() <= NAME_MAX);
        let sig = a.sign(b"hello");
        assert!(Identity::verify(&a.public_key, b"hello", &sig));
        assert!(!Identity::verify(&a.public_key, b"hell0", &sig));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn trust_store_flags_key_change() {
        let dir = test_root().join(format!("sftrust-{}", now_ms()));
        let a = Identity::load_or_create(&dir.join("a")).unwrap();
        let b = Identity::load_or_create(&dir.join("b")).unwrap();
        let path = dir.join("shared");
        let mut store = TrustStore::open(&path).unwrap();
        assert_eq!(store.verdict(&a.id, &a.public_key), Verdict::New);
        store.learn(&a.id, &a.public_key, &a.name);
        assert_eq!(store.verdict(&a.id, &a.public_key), Verdict::Trusted);
        // 同一个 id 换了公钥 → Changed
        assert_eq!(store.verdict(&a.id, &b.public_key), Verdict::Changed);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn names_are_stable_and_unique_enough() {
        let dir = test_root().join(format!("sfname-{}", now_ms()));
        let mut seen = std::collections::HashSet::new();
        for i in 0..16 {
            let id = Identity::load_or_create(&dir.join(format!("d{i}"))).unwrap();
            assert!(seen.insert(id.name.clone()), "名称碰撞：{}", id.name);
        }
        fs::remove_dir_all(&dir).ok();
    }
}
