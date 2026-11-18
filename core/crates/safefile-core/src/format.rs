//! `.safefile` 容器格式 v1：公共文件头、KDF 参数、常量。
//!
//! 布局（全部小端）：
//!
//! ```text
//! [0..8)    Magic "SAFEFILE"
//! [8..10)   格式版本 u16 = 1
//! [10]      加密算法标识 = 1 (XChaCha20-Poly1305 secretstream)
//! [11]      KDF 算法标识 = 1 (Argon2id v1.3)
//! [12..16)  Argon2 m_cost（KiB，u32）
//! [16..20)  Argon2 t_cost（u32）
//! [20..24)  Argon2 p_cost（u32）
//! [24]      KDF 输出长度 = 32
//! [25]      块大小指数 exp，块大小 = 1024 << exp
//! [26..28)  flags u16（v1 保留，参与认证）
//! [28..60)  salt（32 字节，每文件随机）
//! [60..64)  保留（必须为 0，参与认证）
//! [64..88)  secretstream header（24 字节）
//! [88..)    加密块 0：元数据块（明文定长 4096 字节 + 17 字节认证开销）
//!           加密块 1..n-1：数据块（chunk_size 明文 + 17）
//!           加密块 n：结束块（TAG_FINAL）
//! ```
//!
//! 所有块的 AAD = 公共文件头 64 字节 + secretstream header 24 字节。

use crate::error::{Error, Result};

pub const MAGIC: [u8; 8] = *b"SAFEFILE";
pub const FORMAT_VERSION: u16 = 1;

pub const CIPHER_XCHACHA20POLY1305_SECRETSTREAM: u8 = 1;
pub const KDF_ARGON2ID13: u8 = 1;

pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const SS_HEADER_LEN: usize = 24;
pub const PUBLIC_HEADER_LEN: usize = 64;
pub const RESERVED_LEN: usize = 4;

/// 公共文件头 + secretstream header 的总长度，也是每块的 AAD 长度。
pub const PREFIX_LEN: usize = PUBLIC_HEADER_LEN + SS_HEADER_LEN;
/// 每块密文相对明文的额外开销：1 字节 tag + 16 字节 Poly1305 认证。
pub const CHUNK_TAG_OVERHEAD: usize = 17;
/// 元数据块明文定长，避免在明文头中泄漏文件名长度。
pub const META_BLOCK_LEN: usize = 4096;

pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
pub const MIN_CHUNK_SIZE: usize = 4 * 1024;
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// 恶意文件通过超大 KDF 参数耗尽设备资源的上限。
pub const MIN_M_COST_KIB: u32 = 8 * 1024;
pub const MAX_M_COST_KIB: u32 = 1024 * 1024;
pub const MAX_T_COST: u32 = 16;
pub const MAX_P_COST: u32 = 64;

/// Argon2id 参数。m_cost 单位为 KiB。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// 桌面默认：64 MiB / 3 轮 / 4 并行。
    pub const fn desktop() -> Self {
        Self { m_cost_kib: 65_536, t_cost: 3, p_cost: 4 }
    }

    /// 移动默认：32 MiB / 3 轮 / 2 并行。
    pub const fn mobile() -> Self {
        Self { m_cost_kib: 32_768, t_cost: 3, p_cost: 2 }
    }

    /// 高强度：256 MiB / 4 轮 / 8 并行。
    pub const fn maximum() -> Self {
        Self { m_cost_kib: 262_144, t_cost: 4, p_cost: 8 }
    }

    pub fn validate(&self) -> Result<()> {
        if self.m_cost_kib < MIN_M_COST_KIB || self.m_cost_kib > MAX_M_COST_KIB {
            return Err(Error::HeaderParamOutOfRange("m_cost"));
        }
        if self.t_cost < 1 || self.t_cost > MAX_T_COST {
            return Err(Error::HeaderParamOutOfRange("t_cost"));
        }
        if self.p_cost < 1 || self.p_cost > MAX_P_COST {
            return Err(Error::HeaderParamOutOfRange("p_cost"));
        }
        // Argon2 要求 m_cost >= 8 * p_cost（以 1 KiB 块计）。
        if self.m_cost_kib < 8 * self.p_cost {
            return Err(Error::BadKdfParams("m_cost 必须不小于 8 * p_cost".into()));
        }
        Ok(())
    }

    /// 供 UI 显示的人读描述。
    pub fn describe(&self) -> String {
        format!(
            "Argon2id {} MiB / {} 轮 / {} 并行",
            self.m_cost_kib / 1024,
            self.t_cost,
            self.p_cost
        )
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::desktop()
    }
}

/// 块大小 <-> 指数编码。
pub fn chunk_size_to_exp(chunk_size: usize) -> Result<u8> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) || !chunk_size.is_power_of_two() {
        return Err(Error::HeaderParamOutOfRange("chunk_size"));
    }
    Ok((chunk_size.trailing_zeros() - 10) as u8)
}

pub fn chunk_size_from_exp(exp: u8) -> Result<usize> {
    let size = 1024usize
        .checked_shl(exp as u32)
        .ok_or(Error::HeaderParamOutOfRange("chunk_size"))?;
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&size) {
        return Err(Error::HeaderParamOutOfRange("chunk_size"));
    }
    Ok(size)
}

/// 公共文件头（不含 secretstream header）。字段全部参与 AAD 认证。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicHeader {
    pub version: u16,
    pub cipher: u8,
    pub kdf: u8,
    pub kdf_params: KdfParams,
    pub out_len: u8,
    pub chunk_size: usize,
    pub flags: u16,
    pub salt: [u8; SALT_LEN],
}

impl PublicHeader {
    pub fn new(kdf_params: KdfParams, chunk_size: usize, salt: [u8; SALT_LEN]) -> Result<Self> {
        kdf_params.validate()?;
        Ok(Self {
            version: FORMAT_VERSION,
            cipher: CIPHER_XCHACHA20POLY1305_SECRETSTREAM,
            kdf: KDF_ARGON2ID13,
            kdf_params,
            out_len: KEY_LEN as u8,
            chunk_size,
            flags: 0,
            salt,
        })
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_HEADER_LEN] {
        let mut buf = [0u8; PUBLIC_HEADER_LEN];
        buf[0..8].copy_from_slice(&MAGIC);
        buf[8..10].copy_from_slice(&self.version.to_le_bytes());
        buf[10] = self.cipher;
        buf[11] = self.kdf;
        buf[12..16].copy_from_slice(&self.kdf_params.m_cost_kib.to_le_bytes());
        buf[16..20].copy_from_slice(&self.kdf_params.t_cost.to_le_bytes());
        buf[20..24].copy_from_slice(&self.kdf_params.p_cost.to_le_bytes());
        buf[24] = self.out_len;
        buf[25] = chunk_size_to_exp(self.chunk_size).unwrap_or(6);
        buf[26..28].copy_from_slice(&self.flags.to_le_bytes());
        buf[28..60].copy_from_slice(&self.salt);
        // [60..64) 保留为 0
        buf
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < PUBLIC_HEADER_LEN {
            return Err(Error::TooShort);
        }
        if buf[0..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        let version = u16::from_le_bytes([buf[8], buf[9]]);
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let cipher = buf[10];
        if cipher != CIPHER_XCHACHA20POLY1305_SECRETSTREAM {
            return Err(Error::UnsupportedCipher(cipher));
        }
        let kdf = buf[11];
        if kdf != KDF_ARGON2ID13 {
            return Err(Error::UnsupportedKdf(kdf));
        }
        let kdf_params = KdfParams {
            m_cost_kib: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            t_cost: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            p_cost: u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
        };
        // 先做上限检查，再进行任何 KDF 计算，避免恶意参数导致资源耗尽。
        kdf_params.validate()?;
        let out_len = buf[24];
        if out_len as usize != KEY_LEN {
            return Err(Error::HeaderParamOutOfRange("kdf out_len"));
        }
        let chunk_size = chunk_size_from_exp(buf[25])?;
        let flags = u16::from_le_bytes([buf[26], buf[27]]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[28..60]);
        if buf[60..64] != [0u8; RESERVED_LEN] {
            return Err(Error::HeaderParamOutOfRange("reserved"));
        }
        Ok(Self { version, cipher, kdf, kdf_params, out_len, chunk_size, flags, salt })
    }
}

/// 无需密码即可读取的公开信息（用于解密页展示）。
#[derive(Debug, Clone)]
pub struct PublicInfo {
    pub header: PublicHeader,
    pub container_size: u64,
}

impl PublicInfo {
    pub fn kdf_description(&self) -> String {
        self.header.kdf_params.describe()
    }
    pub fn cipher_name(&self) -> &'static str {
        "XChaCha20-Poly1305 (secretstream)"
    }
    pub fn kdf_name(&self) -> &'static str {
        "Argon2id v1.3"
    }
}
