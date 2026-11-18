//! secretstream 流式加密封装。
//!
//! 底层直接调用 libsodium 兼容的 `crypto_secretstream_xchacha20poly1305`，
//! 不自行设计块认证、计数器或 nonce 递进逻辑。

use dryoc::classic::crypto_secretstream_xchacha20poly1305 as ss;

use crate::error::{Error, Result};
use crate::format::{CHUNK_TAG_OVERHEAD, SS_HEADER_LEN};

pub const TAG_MESSAGE: u8 = dryoc::constants::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
pub const TAG_FINAL: u8 = dryoc::constants::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;

/// 加密用的块写入器。
pub struct ChunkWriter {
    state: ss::State,
    header: [u8; SS_HEADER_LEN],
    key: zeroize::Zeroizing<[u8; 32]>,
}

impl ChunkWriter {
    /// `key` 为派生主密钥；secretstream header 由 CSPRNG 生成。
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let mut state = ss::State::new();
        let mut header = [0u8; SS_HEADER_LEN];
        ss::crypto_secretstream_xchacha20poly1305_init_push(&mut state, &mut header, key);
        Ok(Self { state, header, key: zeroize::Zeroizing::new(*key) })
    }

    pub fn header(&self) -> &[u8; SS_HEADER_LEN] {
        &self.header
    }

    /// 压入一个明文块，写入 `out` 的前 `plaintext.len() + 17` 字节。
    pub fn push(&mut self, plaintext: &[u8], out: &mut [u8], aad: &[u8], is_final: bool) -> Result<usize> {
        let need = plaintext.len() + CHUNK_TAG_OVERHEAD;
        if out.len() < need {
            return Err(Error::Internal("密文缓冲长度不足"));
        }
        let tag = if is_final { TAG_FINAL } else { TAG_MESSAGE };
        ss::crypto_secretstream_xchacha20poly1305_push(&mut self.state, &mut out[..need], plaintext, Some(aad), tag)
            .map_err(|_| Error::Internal("加密块失败"))?;
        Ok(need)
    }
}

impl Drop for ChunkWriter {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.state = ss::State::new();
    }
}

/// 解密用的块读取器。
pub struct ChunkReader {
    state: ss::State,
}

impl ChunkReader {
    pub fn new(key: &[u8; 32], header: &[u8; SS_HEADER_LEN]) -> Self {
        let mut state = ss::State::new();
        ss::crypto_secretstream_xchacha20poly1305_init_pull(&mut state, header, key);
        Self { state }
    }

    /// 解出一个块。返回 (明文长度, 是否为结束块)。
    ///
    /// 认证失败统一返回 [`Error::AuthFailed`]，不区分“密码错”还是“被篡改”，
    /// 避免给出可区分的预言机信号。
    pub fn pull(&mut self, ciphertext: &[u8], out: &mut [u8], aad: &[u8]) -> Result<(usize, bool)> {
        if ciphertext.len() < CHUNK_TAG_OVERHEAD {
            return Err(Error::Truncated);
        }
        if out.len() < ciphertext.len() - CHUNK_TAG_OVERHEAD {
            return Err(Error::Internal("明文缓冲过小"));
        }
        let mut tag = 0u8;
        let n = ss::crypto_secretstream_xchacha20poly1305_pull(&mut self.state, out, &mut tag, ciphertext, Some(aad))
            .map_err(|_| Error::AuthFailed)?;
        match tag {
            TAG_MESSAGE => Ok((n, false)),
            TAG_FINAL => Ok((n, true)),
            other => Err(Error::UnsupportedChunkTag(other)),
        }
    }
}
