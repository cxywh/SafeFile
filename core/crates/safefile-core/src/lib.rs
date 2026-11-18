//! SafeFile 加密核心。
//!
//! 设计目标：跨平台（Windows / Android）字节级一致、流式处理大文件、
//! 默认安全（临时文件 + 原子提交、不覆盖、不删除原件）。
//!
//! 上层（Flutter）只调用本 crate 的公开接口，不允许在 Dart 侧实现任何
//! 密码学逻辑。

pub mod batch;
pub mod crypto;
pub mod engine;
pub mod error;
pub mod format;
pub mod identity;
pub mod kdf;
pub mod lan;
pub mod media;
pub mod meta;
pub mod preview;
pub mod preview_mem;
pub mod scan;
pub mod transfer;

pub use batch::{BatchConfig, BatchEngine, ItemKind, ItemStatus, PerfMode, Snapshot};
pub use engine::{
    decrypt_file, decrypt_to_sink, decrypt_to_vec, encrypt_file, inspect, verify_path, CancelToken,
    DecryptOptions, DecryptOutcome, EncryptOptions, EncryptOutcome, ProgressFn,
};
pub use error::{Error, Result, SecretBytes};
pub use format::{KdfParams, PublicHeader, PublicInfo, DEFAULT_CHUNK_SIZE, FORMAT_VERSION, MAGIC};
pub use identity::{device_id, fingerprint, Identity, Verdict};
pub use kdf::{derive_key, password_strength, Key};
pub use lan::{LanNode, NodeStatus, PeerInfo};
pub use meta::{FileKind, Metadata};
pub use media::{MediaTicket, MAX_MEDIA_BYTES};
pub use preview::{
    preview_bytes, preview_file, PreviewDoc, Sheet as PreviewSheet, Slide as PreviewSlide,
};
pub use preview_mem::{
    preview_container, ImageMeta as PreviewImageMeta, MemPreview, PreviewImage,
    MAX_IMAGE_EDGE as PREVIEW_MAX_IMAGE_EDGE, MAX_MEM_BYTES as PREVIEW_MAX_MEM_BYTES,
};
pub use scan::{scan_paths, ScanOptions, ScanReport, SkipReason, SkippedEntry};
pub use transfer::{discover, send_files, ShareInfo, ShareServer, Progress as TransferProgress};

/// crate 版本，供 UI 与日志显示（不含敏感信息）。
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
