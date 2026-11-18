//! 批量任务引擎：多文件并发、单文件流式、可暂停/恢复/取消、快照式进度。
//!
//! 对外只暴露快照（snapshot）轮询，不跨线程回调，便于 FFI 与 UI 层安全使用。
//! 密码仅保存在内存中的 `SecretBytes`，不写入任何日志或任务记录。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::engine::{decrypt_file, encrypt_file, CancelToken, DecryptOptions, EncryptOptions};
use crate::error::{Error, Result, SecretBytes};
use crate::format::{KdfParams, DEFAULT_CHUNK_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfMode {
    /// 节能：1 并发
    Eco,
    /// 均衡：CPU 核数 / 2
    Balanced,
    /// 高性能：CPU 核数
    High,
    /// 自定义并发数
    Custom,
}

impl PerfMode {
    pub fn resolve_concurrency(&self, custom: usize) -> usize {
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let n = match self {
            PerfMode::Eco => 1,
            PerfMode::Balanced => (cores / 2).max(1),
            PerfMode::High => cores.max(1),
            PerfMode::Custom => custom.max(1),
        };
        n.clamp(1, (cores * 2).max(2))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemStatus {
    Pending,
    Running,
    Success,
    Failed,
    Cancelled,
}

impl ItemStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ItemStatus::Pending => "pending",
            ItemStatus::Running => "running",
            ItemStatus::Success => "success",
            ItemStatus::Failed => "failed",
            ItemStatus::Cancelled => "cancelled",
        }
    }
    pub fn is_terminal(&self) -> bool {
        matches!(self, ItemStatus::Success | ItemStatus::Failed | ItemStatus::Cancelled)
    }
}

#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub kdf: KdfParams,
    pub chunk_size: usize,
    pub overwrite: bool,
    /// 每个条目成功后删除其输入文件；失败与取消不删。
    pub delete_source: bool,
    pub mode: PerfMode,
    pub custom_concurrency: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            kdf: KdfParams::desktop(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            overwrite: false,
            delete_source: false,
            mode: PerfMode::Balanced,
            custom_concurrency: 4,
        }
    }
}

/// 单个任务的对外快照（纯数据，便于 FFI 序列化）。
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: u64,
    pub source: String,
    pub dest: String,
    pub size: u64,
    pub processed: u64,
    pub status: &'static str,
    /// 该条目的输入文件是否已被删除。
    pub deleted: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

/// 整体统计。
#[derive(Debug, Clone, Default)]
pub struct BatchSummary {
    pub total_items: usize,
    pub finished_items: usize,
    pub success_items: usize,
    pub failed_items: usize,
    pub cancelled_items: usize,
    pub total_bytes: u64,
    pub processed_bytes: u64,
    pub elapsed_ms: u64,
    pub speed_bps: u64,
    pub is_done: bool,
    pub is_paused: bool,
    pub is_cancelled: bool,
    pub concurrency: usize,
}

struct Item {
    id: u64,
    source: PathBuf,
    dest: PathBuf,
    size: u64,
    processed: u64,
    status: ItemStatus,
    deleted: bool,
    error_code: Option<String>,
    error_message: Option<String>,
}

/// 批量任务引擎。
pub struct BatchEngine {
    kind: ItemKind,
    config: BatchConfig,
    password: Arc<SecretBytes>,
    items: Arc<Mutex<Vec<Item>>>,
    cancel: CancelToken,
    pause: Arc<(Mutex<bool>, Condvar)>,
    remaining: Arc<AtomicUsize>,
    processed_bytes: Arc<AtomicU64>,
    total_bytes: Arc<AtomicU64>,
    started_at: Mutex<Option<Instant>>,
    elapsed_ms: AtomicU64,
    concurrency: usize,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl BatchEngine {
    pub fn new(kind: ItemKind, config: BatchConfig, password: SecretBytes) -> Self {
        let concurrency = config.mode.resolve_concurrency(config.custom_concurrency);
        Self {
            kind,
            config,
            password: Arc::new(password),
            items: Arc::new(Mutex::new(Vec::new())),
            cancel: CancelToken::new(),
            pause: Arc::new((Mutex::new(false), Condvar::new())),
            remaining: Arc::new(AtomicUsize::new(0)),
            processed_bytes: Arc::new(AtomicU64::new(0)),
            total_bytes: Arc::new(AtomicU64::new(0)),
            started_at: Mutex::new(None),
            elapsed_ms: AtomicU64::new(0),
            concurrency,
            handles: Mutex::new(Vec::new()),
        }
    }

    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    pub fn kind(&self) -> ItemKind {
        self.kind
    }

    /// 追加任务，返回任务 id。
    pub fn add(&self, source: PathBuf, dest: PathBuf, size: u64) -> u64 {
        let mut items = self.items.lock().expect("items poisoned");
        let id = items.len() as u64 + 1;
        items.push(Item {
            id,
            source,
            dest,
            size,
            processed: 0,
            status: ItemStatus::Pending,
            deleted: false,
            error_code: None,
            error_message: None,
        });
        self.remaining.store(items.len(), Ordering::SeqCst);
        self.total_bytes.fetch_add(size, Ordering::SeqCst);
        id
    }

    pub fn len(&self) -> usize {
        self.items.lock().expect("items poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn summary(&self) -> BatchSummary {
        let mut s = BatchSummary {
            concurrency: self.concurrency,
            total_bytes: self.total_bytes.load(Ordering::SeqCst),
            processed_bytes: self.processed_bytes.load(Ordering::SeqCst),
            is_paused: *self.pause.0.lock().expect("pause poisoned"),
            is_cancelled: self.cancel.is_cancelled(),
            ..Default::default()
        };
        {
            let items = self.items.lock().expect("items poisoned");
            s.total_items = items.len();
            for it in items.iter() {
                match it.status {
                    ItemStatus::Success => s.success_items += 1,
                    ItemStatus::Failed => s.failed_items += 1,
                    ItemStatus::Cancelled => s.cancelled_items += 1,
                    _ => {}
                }
                if it.status.is_terminal() {
                    s.finished_items += 1;
                }
            }
        }
        s.elapsed_ms = self.elapsed_ms.load(Ordering::SeqCst);
        if let Some(t) = *self.started_at.lock().expect("started_at poisoned") {
            s.elapsed_ms = t.elapsed().as_millis() as u64;
        }
        if s.elapsed_ms > 0 {
            s.speed_bps = s.processed_bytes * 1000 / s.elapsed_ms;
        }
        s.is_done = s.total_items > 0 && s.finished_items == s.total_items;
        s
    }

    pub fn snapshot(&self) -> Vec<Snapshot> {
        let items = self.items.lock().expect("items poisoned");
        items
            .iter()
            .map(|it| Snapshot {
                id: it.id,
                source: it.source.to_string_lossy().to_string(),
                dest: it.dest.to_string_lossy().to_string(),
                size: it.size,
                processed: it.processed,
                status: it.status.as_str(),
                deleted: it.deleted,
                error_code: it.error_code.clone(),
                error_message: it.error_message.clone(),
            })
            .collect()
    }

    pub fn pause(&self) {
        if let Ok(mut paused) = self.pause.0.lock() {
            *paused = true;
        }
    }

    pub fn resume(&self) {
        if let Ok(mut paused) = self.pause.0.lock() {
            *paused = false;
        }
        self.pause.1.notify_all();
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
        if let Ok(mut paused) = self.pause.0.lock() {
            *paused = false;
        }
        self.pause.1.notify_all();
    }

    pub fn is_running(&self) -> bool {
        self.handles.lock().map(|h| !h.is_empty()).unwrap_or(false)
    }

    /// 启动工作线程（幂等：重复调用不重复开线程）。
    pub fn start(&self) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let mut handles = self.handles.lock().expect("handles poisoned");
        if !handles.is_empty() {
            return Ok(());
        }
        *self.started_at.lock().expect("started_at poisoned") = Some(Instant::now());
        let total = self.len();
        let workers = self.concurrency.min(total.max(1));
        let next = Arc::new(AtomicUsize::new(0));

        for _ in 0..workers {
            let items = Arc::clone(&self.items);
            let password = Arc::clone(&self.password);
            let cancel = self.cancel.clone();
            let pause = Arc::clone(&self.pause);
            let remaining = Arc::clone(&self.remaining);
            let processed_bytes = Arc::clone(&self.processed_bytes);
            let next = Arc::clone(&next);
            let kind = self.kind;
            let config = self.config.clone();

            let handle = std::thread::Builder::new()
                .name("safefile-worker".into())
                .stack_size(512 * 1024)
                .spawn(move || {
                    worker_loop(kind, config, password, items, cancel, pause, remaining, processed_bytes, next, total)
                })
                .map_err(|e| Error::Io(std::io::Error::other(e)))?;
            handles.push(handle);
        }
        Ok(())
    }

    /// 阻塞直到全部任务结束。
    pub fn wait(&self) {
        let handles: Vec<JoinHandle<()>> = {
            let mut guard = self.handles.lock().expect("handles poisoned");
            std::mem::take(&mut *guard)
        };
        for h in handles {
            let _ = h.join();
        }
        if let Some(t) = *self.started_at.lock().expect("started_at poisoned") {
            self.elapsed_ms.store(t.elapsed().as_millis() as u64, Ordering::SeqCst);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn worker_loop(
    kind: ItemKind,
    config: BatchConfig,
    password: Arc<SecretBytes>,
    items: Arc<Mutex<Vec<Item>>>,
    cancel: CancelToken,
    pause: Arc<(Mutex<bool>, Condvar)>,
    remaining: Arc<AtomicUsize>,
    processed_bytes: Arc<AtomicU64>,
    next: Arc<AtomicUsize>,
    total: usize,
) {
    loop {
        // 暂停等待（等待期间仍响应取消）
        {
            let mut guard = match pause.0.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            while *guard && !cancel.is_cancelled() {
                guard = match pause.1.wait_timeout(guard, Duration::from_millis(120)) {
                    Ok((g, _)) => g,
                    Err(_) => return,
                };
            }
        }

        if cancel.is_cancelled() {
            if let Ok(mut guard) = items.lock() {
                for it in guard.iter_mut() {
                    if !it.status.is_terminal() {
                        it.status = ItemStatus::Cancelled;
                    }
                }
            }
            remaining.store(0, Ordering::SeqCst);
            return;
        }

        let idx = next.fetch_add(1, Ordering::SeqCst);
        if idx >= total {
            return;
        }

        let (id, source, dest) = {
            let mut guard = match items.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let it = &mut guard[idx];
            it.status = ItemStatus::Running;
            (it.id, it.source.clone(), it.dest.clone())
        };

        let progress = |done: u64, total: u64| {
            if let Ok(mut guard) = items.lock() {
                if let Some(it) = guard.iter_mut().find(|i| i.id == id) {
                    it.processed = done;
                    // 解密时 Dart 侧只知道容器大小，而引擎上报的进度以明文计
                    // （容器另有 4 KiB 元数据块与每块 17 B 标签）。
                    // 分母不校正就会出现「已完成 却只有 57%」的假进度。
                    if total > 0 {
                        it.size = total;
                    }
                }
            }
        };

        let res: Result<(u64, bool, Option<String>)> = match kind {
            ItemKind::Encrypt => encrypt_file(
                &source,
                &dest,
                password.as_bytes(),
                &EncryptOptions {
                    kdf: config.kdf,
                    chunk_size: config.chunk_size,
                    overwrite: config.overwrite,
                    store_filename: None,
                    delete_source: config.delete_source,
                },
                Some(&progress),
                Some(&cancel),
            )
            .map(|o| (o.plaintext_size, o.source_deleted, o.delete_error)),
            ItemKind::Decrypt => decrypt_file(
                &source,
                &dest,
                password.as_bytes(),
                &DecryptOptions {
                    overwrite: config.overwrite,
                    output_name: None,
                    delete_source: config.delete_source,
                },
                Some(&progress),
                Some(&cancel),
            )
            .map(|o| (o.plaintext_size, o.source_deleted, o.delete_error)),
        };

        let mut counted = 0u64;
        if let Ok(mut guard) = items.lock() {
            if let Some(it) = guard.iter_mut().find(|i| i.id == id) {
                match &res {
                    Ok((size, deleted, delete_error)) => {
                        it.status = ItemStatus::Success;
                        it.deleted = *deleted;
                        it.processed = (*size).max(it.processed);
                        counted = *size;
                        // 删除失败不影响「已成功」判定，但要把原因显式带回界面。
                        if let Some(msg) = delete_error {
                            it.error_code = Some("delete_source_failed".to_string());
                            it.error_message = Some(msg.clone());
                        }
                    }
                    Err(Error::Cancelled) => it.status = ItemStatus::Cancelled,
                    Err(e) => {
                        it.status = ItemStatus::Failed;
                        it.error_code = Some(e.code().to_string());
                        it.error_message = Some(e.to_string());
                    }
                }
            }
        }
        if counted > 0 {
            processed_bytes.fetch_add(counted, Ordering::SeqCst);
        }
        remaining.fetch_sub(1, Ordering::SeqCst);
    }
}
