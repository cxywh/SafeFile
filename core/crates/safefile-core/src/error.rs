//! 错误类型。所有变体均不包含密码、密钥或明文内容。

use std::fmt;

/// 核心错误枚举。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO 错误：{0}")]
    Io(#[from] std::io::Error),

    #[error("不是 SAFEFILE 加密文件（Magic 不匹配）")]
    BadMagic,

    #[error("文件过短，无法构成完整加密文件")]
    TooShort,

    #[error("不支持的格式版本：{0}")]
    UnsupportedVersion(u16),

    #[error("不支持的加密算法标识：{0}")]
    UnsupportedCipher(u8),

    #[error("不支持的密钥派生算法标识：{0}")]
    UnsupportedKdf(u8),

    #[error("文件头参数超出安全上限：{0}")]
    HeaderParamOutOfRange(&'static str),

    #[error("密码错误或文件已被篡改（认证失败）")]
    AuthFailed,

    #[error("加密数据被截断：未发现结束标记")]
    Truncated,

    #[error("结束标记之后存在多余数据")]
    TrailingData,

    #[error("加密数据流中出现不支持的块标记：{0}")]
    UnsupportedChunkTag(u8),

    #[error("元数据解析失败：{0}")]
    BadMetadata(&'static str),

    #[error("解密后数据长度与元数据记录不一致")]
    SizeMismatch,

    #[error("输出已存在：{0}")]
    OutputExists(String),

    #[error("任务已取消")]
    Cancelled,

    #[error("KDF 参数非法：{0}")]
    BadKdfParams(String),

    #[error("密码不能为空")]
    EmptyPassword,

    #[error("路径非法：{0}")]
    BadPath(String),

    #[error("传输失败：{0}")]
    Transfer(String),

    #[error("对端拒绝接收：{0}")]
    PeerRejected(String),

    #[error("设备身份已变更，连接被拒绝（可能是伪造或设备重置）")]
    IdentityChanged,

    #[error("对端正在接收其他传输，请稍后重试")]
    PeerBusy,

    #[error("协议错误：{0}")]
    Protocol(&'static str),

    #[error("没有找到设备或地址不可达：{0}")]
    PeerNotFound(String),

    #[error("预览解析失败：{0}")]
    Preview(String),

    #[error("内部错误：{0}")]
    Internal(&'static str),
}

impl Error {
    /// 是否为认证类失败（可用于 UI 提示“密码错误或文件损坏”）。
    pub fn is_auth(&self) -> bool {
        matches!(self, Error::AuthFailed)
    }
}

/// 结果别名。
pub type Result<T> = std::result::Result<T, Error>;

/// 供 Dart 侧使用的错误码，保持稳定，避免依赖错误文案。
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Io(_) => "io",
            Error::BadMagic => "bad_magic",
            Error::TooShort => "too_short",
            Error::UnsupportedVersion(_) => "unsupported_version",
            Error::UnsupportedCipher(_) => "unsupported_cipher",
            Error::UnsupportedKdf(_) => "unsupported_kdf",
            Error::HeaderParamOutOfRange(_) => "header_param_out_of_range",
            Error::AuthFailed => "auth_failed",
            Error::Truncated => "truncated",
            Error::TrailingData => "trailing_data",
            Error::UnsupportedChunkTag(_) => "unsupported_chunk_tag",
            Error::BadMetadata(_) => "bad_metadata",
            Error::SizeMismatch => "size_mismatch",
            Error::OutputExists(_) => "output_exists",
            Error::Cancelled => "cancelled",
            Error::BadKdfParams(_) => "bad_kdf_params",
            Error::EmptyPassword => "empty_password",
            Error::BadPath(_) => "bad_path",
            Error::Transfer(_) => "transfer",
            Error::PeerRejected(_) => "peer_rejected",
            Error::IdentityChanged => "identity_changed",
            Error::PeerBusy => "peer_busy",
            Error::Protocol(_) => "protocol",
            Error::PeerNotFound(_) => "peer_not_found",
            Error::Preview(_) => "preview",
            Error::Internal(_) => "internal",
        }
    }
}

/// 敏感缓冲：Drop 时清零。
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self(data.into())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}
