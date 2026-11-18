//! 目录扫描：递归收集待处理文件，显式跳过符号链接、特殊文件、无权限目录，
//! 并记录跳过原因供 UI 展示。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// 符号链接（避免循环与越界）
    Symlink,
    /// 非普通文件（设备、管道、套接字、目录）
    NotRegularFile,
    /// 无权限访问
    PermissionDenied,
    /// 命中扩展名过滤（例如解密时只处理 .safefile）
    Filtered,
    /// 超过单文件上限
    TooLarge,
    /// 路径解析失败（无效 Unicode 等）
    InvalidPath,
}

impl SkipReason {
    pub fn message(&self) -> &'static str {
        match self {
            SkipReason::Symlink => "符号链接，已跳过",
            SkipReason::NotRegularFile => "不是普通文件，已跳过",
            SkipReason::PermissionDenied => "无访问权限，已跳过",
            SkipReason::Filtered => "不符合处理条件，已跳过",
            SkipReason::TooLarge => "超过单文件大小上限，已跳过",
            SkipReason::InvalidPath => "路径无效，已跳过",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SkippedEntry {
    pub path: PathBuf,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    pub files: Vec<PathBuf>,
    pub skipped: Vec<SkippedEntry>,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// 递归子目录
    pub recursive: bool,
    /// 只接受满足条件（例如只收 .safefile）的文件
    pub accept: Option<Vec<String>>,
    /// 单文件上限，0 表示不限制
    pub max_file_size: u64,
    /// 最大递归深度，防御异常深的目录树
    pub max_depth: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { recursive: true, accept: None, max_file_size: 0, max_depth: 64 }
    }
}

impl ScanOptions {
    pub fn accept_extensions(exts: &[&str]) -> Self {
        Self {
            recursive: true,
            accept: Some(exts.iter().map(|e| e.trim_start_matches('.').to_ascii_lowercase()).collect()),
            max_file_size: 0,
            max_depth: 64,
        }
    }

    fn matches(&self, path: &Path) -> bool {
        match &self.accept {
            None => true,
            Some(list) => {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
                list.iter().any(|e| *e == ext)
            }
        }
    }
}

/// 展开给定的路径列表（文件或目录）为待处理文件清单。
pub fn scan_paths(inputs: &[PathBuf], opts: &ScanOptions) -> ScanReport {
    let mut report = ScanReport::default();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    for input in inputs {
        visit(input, opts, 0, &mut report, &mut visited);
    }
    report
}

fn visit(
    path: &Path,
    opts: &ScanOptions,
    depth: usize,
    report: &mut ScanReport,
    visited: &mut HashSet<PathBuf>,
) {
    if depth > opts.max_depth {
        report.skipped.push(SkippedEntry { path: path.to_path_buf(), reason: SkipReason::InvalidPath });
        return;
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            let reason = if e.kind() == std::io::ErrorKind::PermissionDenied {
                SkipReason::PermissionDenied
            } else {
                SkipReason::InvalidPath
            };
            report.skipped.push(SkippedEntry { path: path.to_path_buf(), reason });
            return;
        }
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        report.skipped.push(SkippedEntry { path: path.to_path_buf(), reason: SkipReason::Symlink });
        return;
    }
    if ft.is_dir() {
        if !opts.recursive {
            return;
        }
        // 用规范化路径做环检测
        if let Ok(canonical) = path.canonicalize() {
            if !visited.insert(canonical) {
                return;
            }
        }
        let entries = match std::fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => {
                report.skipped.push(SkippedEntry { path: path.to_path_buf(), reason: SkipReason::PermissionDenied });
                return;
            }
        };
        let mut children: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten() {
            children.push(entry.path());
        }
        children.sort();
        for child in children {
            visit(&child, opts, depth + 1, report, visited);
        }
        return;
    }
    if !ft.is_file() {
        report.skipped.push(SkippedEntry { path: path.to_path_buf(), reason: SkipReason::NotRegularFile });
        return;
    }
    if !opts.matches(path) {
        report.skipped.push(SkippedEntry { path: path.to_path_buf(), reason: SkipReason::Filtered });
        return;
    }
    if opts.max_file_size > 0 && meta.len() > opts.max_file_size {
        report.skipped.push(SkippedEntry { path: path.to_path_buf(), reason: SkipReason::TooLarge });
        return;
    }
    report.total_bytes += meta.len();
    report.files.push(path.to_path_buf());
}
