import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'widgets.dart';

/// 一个可浏览的存储卷。内部共享存储之外，还可能是 OTG U 盘（挂载在 /storage/XXXX-XXXX）。
class StorageVolume {
  const StorageVolume(this.path, this.label);

  final String path;
  final String label;
}

/// 列出所有可浏览的存储卷。
///
/// Android 把可移动卷挂到 `/storage/<FS-UUID>`（形如 `BEA6-BBCE`），
/// 内部共享存储是 `/storage/emulated/0`。只列真实存在的目录，
/// 没插 U 盘时列表里就只有「内部存储」。
Future<List<StorageVolume>> listStorageVolumes() async {
  // 必须问系统：`/storage` 目录本身权限是 drwx--x--- root:media_rw，
  // 应用进程直接 list 会抛 EACCES，U 盘就永远发现不了。
  try {
    const channel = MethodChannel('safefile/storage');
    final raw = await channel.invokeMethod<List<Object?>>('volumes');
    if (raw != null && raw.isNotEmpty) {
      final volumes = <StorageVolume>[];
      for (final item in raw) {
        final map = (item as Map).cast<Object?, Object?>();
        final path = map['path'] as String?;
        if (path == null) continue;
        volumes.add(StorageVolume(path, (map['label'] as String?) ?? path));
      }
      if (volumes.isNotEmpty) return volumes;
    }
  } catch (_) {
    // 通道不可用（非 Android 或引擎未就绪）时退回目录扫描。
  }

  final volumes = <StorageVolume>[const StorageVolume('/storage/emulated/0', '内部存储')];
  try {
    final entries = await Directory('/storage').list(followLinks: false).toList();
    final uuids = <String>[];
    for (final e in entries) {
      final name = e.path.split('/').last;
      if (RegExp(r'^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$').hasMatch(name)) uuids.add(e.path);
    }
    uuids.sort();
    for (final path in uuids) {
      volumes.add(StorageVolume(path, 'U 盘 · ${path.split('/').last}'));
    }
  } catch (_) {
    // 拿不到卷列表时只保留内部存储。
  }
  return volumes;
}

/// 应用内文件浏览器（Android 专用）。
///
/// 不用 `file_selector` 的原因：它在 Android 上走 SAF，`openFiles()` 会把文件
/// 复制到应用缓存，交给核心的是副本，「删除原文件」就删在副本上；
/// 而且 SAF 拿不到 U 盘的真实路径。这里直接扫真实目录（已申请「所有文件访问权限」）。
bool get _isAndroid => Platform.isAndroid;

Future<List<String>?> showFileBrowser(
  BuildContext context, {
  required String title,
  bool safefileOnly = false,
}) {
  // 应用内的 `/storage` 浏览器只对 Android 有意义；桌面端直接用系统对话框，
  // 否则会停在「内部存储 /storage/emulated/0」并报 PathNotFound。
  if (!_isAndroid) {
    return FilePick.pickFiles(safefileOnly: safefileOnly).then<List<String>?>(
      (files) => files.isEmpty ? null : files,
    );
  }
  return Navigator.of(context).push<List<String>>(
    MaterialPageRoute(
      fullscreenDialog: true,
      builder: (_) => _FileBrowserPage(title: title, safefileOnly: safefileOnly),
    ),
  );
}

/// 选择目录（输出目录、整个文件夹加密），返回真实路径。
Future<String?> showDirectoryPicker(BuildContext context, {required String title}) {
  if (!_isAndroid) {
    return getDirectoryPath(confirmButtonText: '选择此目录');
  }
  return Navigator.of(context).push<String>(
    MaterialPageRoute(
      fullscreenDialog: true,
      builder: (_) => _FileBrowserPage(title: title, safefileOnly: false, pickDirectory: true),
    ),
  );
}

class _FileBrowserPage extends StatefulWidget {
  const _FileBrowserPage({
    required this.title,
    required this.safefileOnly,
    this.pickDirectory = false,
  });

  final String title;
  final bool safefileOnly;
  final bool pickDirectory;

  @override
  State<_FileBrowserPage> createState() => _FileBrowserPageState();
}

class _FileBrowserPageState extends State<_FileBrowserPage> {
  List<StorageVolume> _volumes = const [];
  StorageVolume? _volume;
  late Directory _dir = Directory('/storage/emulated/0');
  List<Directory> _dirs = const [];
  List<File> _files = const [];
  final Set<String> _selected = <String>{};
  String? _error;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    final volumes = await listStorageVolumes();
    if (!mounted) return;
    setState(() => _volumes = volumes);
    _volume = volumes.first;
    await _open(volumes.first.path);
  }

  Future<void> _open(String path) async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final dir = Directory(path);
      final entries = await dir.list(followLinks: false).toList();
      final dirs = <Directory>[];
      final files = <File>[];
      for (final e in entries) {
        final name = e.path.split('/').last;
        if (name.startsWith('.')) continue;
        if (e is Directory) {
          dirs.add(e);
        } else if (e is File) {
          if (widget.pickDirectory) continue;
          if (widget.safefileOnly && !name.toLowerCase().endsWith('.safefile')) continue;
          files.add(e);
        }
      }
      dirs.sort((a, b) => a.path.toLowerCase().compareTo(b.path.toLowerCase()));
      files.sort((a, b) => a.path.toLowerCase().compareTo(b.path.toLowerCase()));
      if (!mounted) return;
      setState(() {
        _dir = dir;
        _dirs = dirs;
        _files = files;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '无法读取该目录：$e';
        _loading = false;
        _dirs = const [];
        _files = const [];
      });
    }
  }

  bool get _atVolumeRoot => _volume != null && _dir.path == _volume!.path;

  void _goUp() {
    if (_atVolumeRoot) return;
    _open(_dir.parent.path);
  }

  String get _crumb {
    if (_volume == null) return _dir.path;
    if (_atVolumeRoot) return _volume!.label;
    return _dir.path.substring(_volume!.path.length + 1);
  }

  void _confirm() {
    if (widget.pickDirectory) {
      Navigator.of(context).pop(_dir.path);
      return;
    }
    if (_selected.isNotEmpty) Navigator.of(context).pop(_selected.toList());
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final canConfirm = widget.pickDirectory || _selected.isNotEmpty;
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title, maxLines: 1, overflow: TextOverflow.ellipsis),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          tooltip: '取消',
          onPressed: () => Navigator.of(context).pop(),
        ),
        actions: [
          if (!_atVolumeRoot)
            IconButton(
              icon: const Icon(Icons.arrow_upward),
              tooltip: '上一级',
              onPressed: _goUp,
            ),
          Padding(
            padding: const EdgeInsets.only(right: 12, left: 4),
            child: FilledButton(
              onPressed: canConfirm ? _confirm : null,
              child: Text(
                widget.pickDirectory
                    ? '选此目录'
                    : '确定${_selected.isEmpty ? '' : '(${_selected.length})'}',
              ),
            ),
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            if (_volumes.length > 1)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.fromLTRB(16, 2, 12, 2),
                child: Row(
                  children: [
                    Icon(Icons.sd_storage_outlined, size: 18, color: theme.colorScheme.primary),
                    const SizedBox(width: 8),
                    Expanded(
                      child: DropdownButtonHideUnderline(
                        child: DropdownButton<StorageVolume>(
                          value: _volume,
                          isExpanded: true,
                          items: [
                            for (final v in _volumes)
                              DropdownMenuItem(value: v, child: Text(v.label)),
                          ],
                          onChanged: (v) {
                            if (v == null) return;
                            setState(() {
                              _volume = v;
                              _selected.clear();
                            });
                            _open(v.path);
                          },
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
              child: Text(
                _crumb,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
            if (_loading) const LinearProgressIndicator(minHeight: 2),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.all(16),
                child: Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
              ),
            Expanded(
              child: ListView(
                children: [
                  for (final d in _dirs)
                    ListTile(
                      leading: Icon(Icons.folder_outlined, color: theme.colorScheme.primary),
                      title: Text(d.path.split('/').last),
                      onTap: () => _open(d.path),
                    ),
                  for (final f in _files)
                    CheckboxListTile(
                      value: _selected.contains(f.path),
                      onChanged: (v) => setState(() {
                        if (v == true) {
                          _selected.add(f.path);
                        } else {
                          _selected.remove(f.path);
                        }
                      }),
                      title: Text(
                        f.path.split('/').last,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  if (!_loading && _dirs.isEmpty && _files.isEmpty && _error == null)
                    Padding(
                      padding: const EdgeInsets.all(24),
                      child: EmptyHint(
                        title: widget.pickDirectory ? '这里没有子目录' : '这个目录是空的',
                        description: widget.pickDirectory
                            ? '可以点右上角「选此目录」，把当前这个目录作为输出位置'
                            : '返回上一级换个目录；也可以直接把文件夹整个加进来',
                      ),
                    ),
                ],
              ),
            ),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.fromLTRB(16, 10, 16, 14),
              child: Text(
                widget.pickDirectory
                    ? '当前目录：${_dir.path}'
                    : '已选 ${_selected.length} 个文件 · 使用真实路径，删除原文件会作用在原件上',
                maxLines: 2,
                style: theme.textTheme.labelSmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
