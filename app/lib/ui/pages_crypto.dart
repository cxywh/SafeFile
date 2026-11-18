import 'dart:io';

import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';

import '../core/android_storage.dart';
import '../core/app_state.dart';
import '../core/paths.dart';
import 'pages_main.dart';
import 'file_browser.dart';
import 'preview_view.dart';
import 'theme.dart';
import 'widgets.dart';

class PickedFile {
  PickedFile(this.path, this.size);
  final String path;
  final int size;
  String get name => fileNameOf(path);
}

/// 文件加密页。
class EncryptPage extends StatefulWidget {
  const EncryptPage({super.key, required this.state, required this.onNavigate});

  final AppState state;
  final ValueChanged<int> onNavigate;

  @override
  State<EncryptPage> createState() => _EncryptPageState();
}

class _EncryptPageState extends State<EncryptPage> {
  final _pw = TextEditingController();
  final _pw2 = TextEditingController();
  final List<PickedFile> _files = [];
  String? _outDir;
  String? _error;
  bool _dragging = false;
  int _chunkSize = 65536;

  @override
  void initState() {
    super.initState();
    widget.state.addListener(_refreshOutDir);
    _refreshOutDir();
  }

  /// 未授权时先不显示任何路径；等用户授权（按钮或系统设置页返回）后自动补上。
  void _refreshOutDir() {
    if (_outDir != null) return;
    // AppState 在批量任务期间每 250ms 通知一次，未授权时没必要反复查平台通道。
    if (Platform.isAndroid && !widget.state.storageGranted) return;
    defaultOutputDir().then((dir) {
      if (mounted && dir.isNotEmpty) setState(() => _outDir = dir);
    });
  }

  @override
  void dispose() {
    widget.state.removeListener(_refreshOutDir);
    _pw.dispose();
    _pw2.dispose();
    super.dispose();
  }

  void _addPaths(List<String> paths) {
    var added = 0;
    for (final path in paths) {
      final stat = FileSystemEntity.typeSync(path);
      if (stat == FileSystemEntityType.directory) {
        final scan = widget.state.scan([path]);
        final files = (scan['files'] as List? ?? const []);
        for (final f in files) {
          final m = Map<String, dynamic>.from(f as Map);
          final p = m['path'] as String;
          if (_files.any((e) => e.path == p) || p.endsWith('.safefile')) continue;
          _files.add(PickedFile(p, (m['size'] as num?)?.toInt() ?? 0));
          added++;
        }
      } else if (stat == FileSystemEntityType.file) {
        if (_files.any((e) => e.path == path) || path.endsWith('.safefile')) continue;
        final size = File(path).lengthSync();
        _files.add(PickedFile(path, size));
        added++;
      }
    }
    setState(() => _error = added == 0 ? '没有新增可加密的文件（.safefile 会被跳过）' : null);
  }

  Future<void> _pickFiles() async {
    if (!widget.state.storageGranted && !await _ensureStorage()) return;
    // Android 必须用真实路径：SAF 的 openFiles() 会给缓存副本，
    // 「成功后删除原文件」会删在副本上，用户的原件仍在。
    if (Platform.isAndroid) {
      if (!mounted) return;
      final picked = await showFileBrowser(context, title: '选择要加密的文件');
      if (picked != null && picked.isNotEmpty) _addPaths(picked);
      return;
    }
    final group = const XTypeGroup(label: '所有文件');
    final files = await openFiles(acceptedTypeGroups: [group]);
    _addPaths(files.map((f) => f.path).toList());
  }

  Future<void> _pickFolder() async {
    if (!widget.state.storageGranted && !await _ensureStorage()) return;
    final dir = Platform.isAndroid
        ? (mounted ? await showDirectoryPicker(context, title: '选择要加密的文件夹') : null)
        : await getDirectoryPath(confirmButtonText: '选择文件夹');
    if (dir != null) _addPaths([dir]);
  }

  Future<void> _pickOutDir() async {
    if (!widget.state.storageGranted && !await _ensureStorage()) return;
    final dir = Platform.isAndroid
        ? (mounted ? await showDirectoryPicker(context, title: '选择输出目录') : null)
        : await getDirectoryPath(confirmButtonText: '选择输出目录');
    if (dir != null) setState(() => _outDir = dir);
  }

  /// Android：拉起「所有文件访问权限」授权，并刷新默认输出目录。
  Future<bool> _ensureStorage() async {
    final ok = await widget.state.ensureStorageAccess();
    if (!mounted) return ok;
    if (!ok) {
      setState(() => _error = '需要允许「所有文件访问权限」，否则无法读取文件夹或写入存储目录');
      return false;
    }
    final dir = await defaultOutputDir();
    if (!mounted) return true;
    setState(() {
      _error = null;
      if (dir.isNotEmpty) _outDir = dir;
    });
    return true;
  }

  String _outLabel() {
    if (_outDir != null) return '输出目录：$_outDir';
    if (Platform.isAndroid) {
      return widget.state.storageGranted
          ? '输出目录不可写：请检查 ${AndroidStorage.publicRoot} 是否可创建'
          : '未授权：授予「所有文件访问权限」后输出到 ${AndroidStorage.publicRoot}';
    }
    return '输出到源文件同目录';
  }

  Future<void> _start() async {
    if (Platform.isAndroid && !widget.state.storageGranted) {
      setState(() => _error = '需要「所有文件访问权限」才能把加密产物写进手机存储；点「去授权」后重试');
      return;
    }
    if (_files.isEmpty) {
      setState(() => _error = '请先选择要加密的文件或文件夹');
      return;
    }
    if (_pw.text.isEmpty) {
      setState(() => _error = '密码不能为空');
      return;
    }
    if (_pw.text != _pw2.text) {
      setState(() => _error = '两次输入的密码不一致');
      return;
    }
    final jobs = <({String source, String dest, int size})>[];
    for (final f in _files) {
      final dest = _outDir == null
          ? '${f.path}.safefile'
          : '${_outDir!}${Platform.pathSeparator}${f.name}.safefile';
      jobs.add((source: f.path, dest: dest, size: f.size));
    }
    // 先确认输出目录真的可写：否则引擎只会抛 `IO 错误：拒绝访问。(os error 5)`，
    // 用户既看不懂也不知道该改哪里。
    for (final dir in {for (final j in jobs) File(j.dest).parent.path}) {
      final bad = await checkWritableDir(dir);
      if (bad == null) continue;
      if (!mounted) return;
      setState(() => _error = bad);
      return;
    }
    try {
      widget.state.startBatch(decrypt: false, password: _pw.text, jobs: jobs);
    } catch (e) {
      setState(() => _error = '无法启动加密任务：$e');
      return;
    }
    setState(() => _error = null);
    widget.onNavigate(4);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final totalBytes = _files.fold<int>(0, (sum, f) => sum + f.size);
    return ListView(
      padding: Tokens.pageInsets(context),
      children: [
        PageHeader(
          title: '文件加密',
          subtitle: '使用 XChaCha20-Poly1305 流式加密，每个文件独立随机盐与密钥',
          actions: [
            OutlinedButton.icon(
              onPressed: _pickFolder,
              icon: const Icon(Icons.folder_outlined, size: 18),
              label: const Text('选择文件夹'),
            ),
            const SizedBox(width: 8),
            FilledButton.icon(
              onPressed: _pickFiles,
              icon: const Icon(Icons.add, size: 18),
              label: const Text('选择文件'),
            ),
          ],
        ),
        const SizedBox(height: Tokens.gapLg),
        AdaptiveSplit(
          main: Column(
            children: [
                  if (!Tokens.isCompact(context)) ...[
                    DropTarget(
                    onDragEntered: (_) => setState(() => _dragging = true),
                    onDragExited: (_) => setState(() => _dragging = false),
                    onDragDone: (details) {
                      setState(() => _dragging = false);
                      _addPaths(details.files.map((f) => f.path).toList());
                    },
                    child: Card(
                      color: _dragging ? theme.colorScheme.primary.withValues(alpha: 0.06) : null,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(Tokens.radius),
                        side: BorderSide(
                          color: _dragging ? theme.colorScheme.primary : theme.dividerColor,
                          width: _dragging ? 1.6 : 1,
                        ),
                      ),
                      child: Padding(
                        padding: const EdgeInsets.all(28),
                        child: Column(
                          children: [
                            Icon(Icons.upload_file_outlined, size: 30, color: theme.colorScheme.primary),
                            const SizedBox(height: 10),
                            Text(
                              Tokens.isCompact(context) ? '点上方按钮选择文件' : '把文件或文件夹拖到这里',
                              style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.w600),
                            ),
                            const SizedBox(height: 4),
                            Text(
                              Tokens.isCompact(context)
                                  ? '支持单文件、多文件与整个文件夹；.safefile 会被自动跳过'
                                  : '也可以使用右上角按钮选择；.safefile 会被自动跳过',
                              textAlign: TextAlign.center,
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: Tokens.gap),
                  ],
                  SectionCard(
                    title: '待加密文件',
                    subtitle: _files.isEmpty ? '尚未选择文件' : '共 ${_files.length} 个 · ${formatBytes(totalBytes)}',
                    trailing: _files.isEmpty
                        ? null
                        : TextButton(
                            onPressed: () => setState(_files.clear),
                            child: const Text('清空'),
                          ),
                    child: _files.isEmpty
                        ? const EmptyHint(
                            title: '列表为空',
                            description: '支持单文件、多文件与整个文件夹，保留原有目录结构',
                            icon: Icons.folder_open_outlined,
                          )
                        : Column(
                            children: [
                              for (final f in _files)
                                PickedFileTile(
                                  name: f.name,
                                  sizeLabel: formatBytes(f.size),
                                  subtitle: f.path,
                                  onRemove: () => setState(() => _files.remove(f)),
                                ),
                            ],
                          ),
                  ),
                ],
          ),
          side: Column(
            children: [
                  SectionCard(
                    title: '加密设置',
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        PasswordFields(
                          controller: _pw,
                          confirmController: _pw2,
                          onStrength: widget.state.passwordStrength,
                        ),
                        const SizedBox(height: Tokens.gap),
                        DropdownButtonFormField<int>(
                          initialValue: _chunkSize,
                          decoration: const InputDecoration(labelText: '分块大小'),
                          items: const [
                            DropdownMenuItem(value: 65536, child: Text('64 KiB（默认）')),
                            DropdownMenuItem(value: 262144, child: Text('256 KiB')),
                            DropdownMenuItem(value: 1048576, child: Text('1 MiB（大文件）')),
                          ],
                          onChanged: (v) => setState(() => _chunkSize = v ?? 65536),
                        ),
                        const SizedBox(height: Tokens.gap),
                        Row(
                          children: [
                            Expanded(
                              child: Text(
                                _outLabel(),
                                maxLines: 2,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: _outDir == null && Platform.isAndroid
                                      ? theme.colorScheme.error
                                      : theme.colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ),
                            if (Platform.isAndroid && !widget.state.storageGranted)
                              TextButton(onPressed: _ensureStorage, child: const Text('去授权')),
                            TextButton(onPressed: _pickOutDir, child: const Text('更改')),
                          ],
                        ),
                        const SizedBox(height: 6),
                        Text(
                          '密钥派生：${widget.state.kdfPreset.label}',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: Tokens.gap),
                  SectionCard(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        if (_error != null) ...[
                          Text(
                            _error!,
                            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
                          ),
                          const SizedBox(height: 10),
                        ],
                        FilledButton.icon(
                          onPressed: widget.state.isBusy ? null : _start,
                          icon: const Icon(Icons.lock_outline, size: 18),
                          label: Text(widget.state.isBusy ? '任务进行中' : '开始加密'),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          '密码遗失后无法恢复，产品不提供找回通道。',
                          textAlign: TextAlign.center,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
            ],
          ),
        ),
      ],
    );
  }
}

/// 文件解密页。
class DecryptPage extends StatefulWidget {
  const DecryptPage({super.key, required this.state, required this.onNavigate});

  final AppState state;
  final ValueChanged<int> onNavigate;

  @override
  State<DecryptPage> createState() => _DecryptPageState();
}

class _DecryptPageState extends State<DecryptPage> {
  final _pw = TextEditingController();
  final List<PickedFile> _files = [];
  String? _outDir;
  String? _error;
  Map<String, dynamic>? _info;
  bool _verifying = false;
  String? _verifyResult;
  bool _dragging = false;

  @override
  void initState() {
    super.initState();
    widget.state.addListener(_refreshOutDir);
    _refreshOutDir();
  }

  void _refreshOutDir() {
    if (_outDir != null) return;
    if (Platform.isAndroid && !widget.state.storageGranted) return;
    defaultOutputDir().then((dir) {
      if (mounted && dir.isNotEmpty) setState(() => _outDir = dir);
    });
  }

  @override
  void dispose() {
    widget.state.removeListener(_refreshOutDir);
    _pw.dispose();
    super.dispose();
  }

  void _addPaths(List<String> paths) {
    var added = 0;
    for (final path in paths) {
      final type = FileSystemEntity.typeSync(path);
      if (type == FileSystemEntityType.directory) {
        final scan = widget.state.scan([path], safefileOnly: true);
        for (final f in (scan['files'] as List? ?? const [])) {
          final m = Map<String, dynamic>.from(f as Map);
          final p = m['path'] as String;
          if (_files.any((e) => e.path == p)) continue;
          _files.add(PickedFile(p, (m['size'] as num?)?.toInt() ?? 0));
          added++;
        }
      } else if (type == FileSystemEntityType.file) {
        if (_files.any((e) => e.path == path)) continue;
        _files.add(PickedFile(path, File(path).lengthSync()));
        added++;
      }
    }
    setState(() {
      _error = added == 0 ? '没有新增 .safefile 文件' : null;
      _outDir ??= _files.isNotEmpty ? File(_files.first.path).parent.path : null;
    });
    if (_files.isNotEmpty) _inspectFirst();
  }

  Future<void> _inspectFirst() async {
    final path = _files.first.path;
    final info = await widget.state.inspectOffThread(path);
    if (mounted) setState(() => _info = info);
  }

  Future<void> _pickFiles() async {
    if (!widget.state.storageGranted && !await _ensureStorage()) return;
    if (Platform.isAndroid) {
      if (!mounted) return;
      final picked = await showFileBrowser(context, title: '选择要解密的容器', safefileOnly: true);
      if (picked != null && picked.isNotEmpty) _addPaths(picked);
      return;
    }
    final group = const XTypeGroup(label: 'SafeFile 加密文件', extensions: ['safefile']);
    final files = await openFiles(acceptedTypeGroups: [group]);
    _addPaths(files.map((f) => f.path).toList());
  }

  Future<void> _pickFolder() async {
    if (!widget.state.storageGranted && !await _ensureStorage()) return;
    final dir = Platform.isAndroid
        ? (mounted ? await showDirectoryPicker(context, title: '选择包含 .safefile 的文件夹') : null)
        : await getDirectoryPath(confirmButtonText: '选择包含 .safefile 的文件夹');
    if (dir != null) _addPaths([dir]);
  }

  Future<void> _pickOutDir() async {
    if (!widget.state.storageGranted && !await _ensureStorage()) return;
    final dir = Platform.isAndroid
        ? (mounted ? await showDirectoryPicker(context, title: '选择输出目录') : null)
        : await getDirectoryPath(confirmButtonText: '选择输出目录');
    if (dir != null) setState(() => _outDir = dir);
  }

  /// Android：拉起「所有文件访问权限」授权，并刷新默认输出目录。
  Future<bool> _ensureStorage() async {
    final ok = await widget.state.ensureStorageAccess();
    if (!mounted) return ok;
    if (!ok) {
      setState(() => _error = '需要允许「所有文件访问权限」，否则无法读取文件夹或写入存储目录');
      return false;
    }
    final dir = await defaultOutputDir();
    if (!mounted) return true;
    setState(() {
      _error = null;
      if (dir.isNotEmpty) _outDir = dir;
    });
    return true;
  }

  Future<void> _verify() async {
    if (_files.isEmpty || _pw.text.isEmpty) {
      setState(() => _error = '请选择文件并输入密码');
      return;
    }
    setState(() {
      _verifying = true;
      _verifyResult = null;
    });
    Map<String, dynamic> result;
    try {
      result = await widget.state.verifyOffThread(_files.first.path, _pw.text);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _verifying = false;
        _verifyResult = '校验失败：$e';
      });
      return;
    }
    if (!mounted) return;
    setState(() {
      _verifying = false;
      _verifyResult = result['ok'] == true
          ? '校验通过：${(result['metadata'] as Map?)?['filename'] ?? ''}'
          : '校验失败：${result['message'] ?? '未知错误'}';
    });
  }

  String _outLabel() {
    if (_outDir != null) return '输出目录：$_outDir';
    if (Platform.isAndroid) {
      return widget.state.storageGranted
          ? '输出目录不可写：请检查 ${AndroidStorage.publicRoot} 是否可创建'
          : '未授权：授予「所有文件访问权限」后输出到 ${AndroidStorage.publicRoot}';
    }
    return '输出到容器所在目录';
  }

  Future<void> _start() async {
    if (Platform.isAndroid && !widget.state.storageGranted) {
      setState(() => _error = '需要「所有文件访问权限」才能把解密产物写进手机存储；点「去授权」后重试');
      return;
    }
    if (_files.isEmpty) {
      setState(() => _error = '请先选择 .safefile 文件');
      return;
    }
    if (_pw.text.isEmpty) {
      setState(() => _error = '密码不能为空');
      return;
    }
    final jobs = <({String source, String dest, int size})>[];
    for (final f in _files) {
      final dir = _outDir ?? File(f.path).parent.path;
      // 传入目录：由 Rust 引擎按加密元数据还原原始文件名（含路径穿越防护）
      jobs.add((source: f.path, dest: dir, size: f.size));
    }
    for (final dir in {for (final j in jobs) j.dest}) {
      final bad = await checkWritableDir(dir);
      if (bad == null) continue;
      if (!mounted) return;
      setState(() => _error = bad);
      return;
    }
    try {
      widget.state.startBatch(decrypt: true, password: _pw.text, jobs: jobs);
    } catch (e) {
      setState(() => _error = '无法启动解密任务：$e');
      return;
    }
    setState(() => _error = null);
    widget.onNavigate(4);
  }
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListView(
      padding: Tokens.pageInsets(context),
      children: [
        PageHeader(
          title: '文件解密',
          subtitle: '先用文件头参数重新派生密钥，再逐块校验认证标签',
          actions: [
            OutlinedButton.icon(
              onPressed: _pickFolder,
              icon: const Icon(Icons.folder_outlined, size: 18),
              label: const Text('选择文件夹'),
            ),
            const SizedBox(width: 8),
            FilledButton.icon(
              onPressed: _pickFiles,
              icon: const Icon(Icons.add, size: 18),
              label: const Text('选择文件'),
            ),
          ],
        ),
        const SizedBox(height: Tokens.gapLg),
        AdaptiveSplit(
          main: Column(
            children: [
                  if (!Tokens.isCompact(context)) ...[
                    DropTarget(
                    onDragEntered: (_) => setState(() => _dragging = true),
                    onDragExited: (_) => setState(() => _dragging = false),
                    onDragDone: (details) {
                      setState(() => _dragging = false);
                      _addPaths(details.files.map((f) => f.path).toList());
                    },
                    child: Card(
                      color: _dragging ? theme.colorScheme.primary.withValues(alpha: 0.06) : null,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(Tokens.radius),
                        side: BorderSide(
                          color: _dragging ? theme.colorScheme.primary : theme.dividerColor,
                          width: _dragging ? 1.6 : 1,
                        ),
                      ),
                      child: Padding(
                        padding: const EdgeInsets.all(28),
                        child: Column(
                          children: [
                            Icon(Icons.lock_open_outlined, size: 30, color: theme.colorScheme.primary),
                            const SizedBox(height: 10),
                            Text(
                              '把 .safefile 文件拖到这里',
                              style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.w600),
                            ),
                            const SizedBox(height: 4),
                            Text(
                              '解密后会在输出目录还原原始文件名与目录结构',
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: Tokens.gap),
                  ],
                  if (_info != null) ...[
                    ContainerInfoCards(info: _info!),
                    const SizedBox(height: Tokens.gap),
                  ],
                  SectionCard(
                    title: '待解密文件',
                    subtitle: _files.isEmpty ? '尚未选择文件' : '共 ${_files.length} 个',
                    trailing: _files.isEmpty
                        ? null
                        : TextButton(onPressed: () => setState(_files.clear), child: const Text('清空')),
                    child: _files.isEmpty
                        ? const EmptyHint(
                            title: '列表为空',
                            description: '点上方按钮选择 .safefile 文件；可一次处理整个文件夹',
                            icon: Icons.lock_outline,
                          )
                        : Column(
                            children: [
                              for (final f in _files)
                                PickedFileTile(
                                  name: f.name,
                                  sizeLabel: formatBytes(f.size),
                                  subtitle: f.path,
                                  onRemove: () => setState(() => _files.remove(f)),
                                ),
                            ],
                          ),
                  ),
                ],
          ),
          side: Column(
            children: [
                  SectionCard(
                    title: '解密设置',
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        PasswordFields(
                          controller: _pw,
                          onStrength: widget.state.passwordStrength,
                        ),
                        const SizedBox(height: Tokens.gap),
                        Row(
                          children: [
                            Expanded(
                              child: Text(
                                _outLabel(),
                                maxLines: 2,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: _outDir == null && Platform.isAndroid
                                      ? theme.colorScheme.error
                                      : theme.colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ),
                            if (Platform.isAndroid && !widget.state.storageGranted)
                              TextButton(onPressed: _ensureStorage, child: const Text('去授权')),
                            TextButton(onPressed: _pickOutDir, child: const Text('更改')),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: Tokens.gap),
                  SectionCard(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        if (_error != null) ...[
                          Text(
                            _error!,
                            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
                          ),
                          const SizedBox(height: 10),
                        ],
                        if (_verifyResult != null) ...[
                          Text(
                            _verifyResult!,
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: _verifyResult!.startsWith('校验通过')
                                  ? const Color(0xFF1B8A5A)
                                  : theme.colorScheme.error,
                            ),
                          ),
                          const SizedBox(height: 10),
                        ],
                        FilledButton.icon(
                          onPressed: widget.state.isBusy ? null : _start,
                          icon: const Icon(Icons.lock_open_outlined, size: 18),
                          label: Text(widget.state.isBusy ? '任务进行中' : '开始解密'),
                        ),
                        const SizedBox(height: 8),
                        OutlinedButton(
                          onPressed: _verifying ? null : _verify,
                          child: Text(_verifying ? '校验中…' : '仅校验不解密'),
                        ),
                      ],
                    ),
                  ),
            ],
          ),
        ),
      ],
    );
  }
}

/// 安全预览页：解密到受控临时目录后展示，关闭即清理。
class PreviewPage extends StatefulWidget {
  const PreviewPage({super.key, required this.state, this.onNavigate});

  final AppState state;

  /// 窄屏没有「文件预览」的底部入口，页面内需要提供回首页的出口。
  final ValueChanged<int>? onNavigate;

  @override
  State<PreviewPage> createState() => _PreviewPageState();
}

class _PreviewPageState extends State<PreviewPage> {
  final _pw = TextEditingController();
  String? _container;
  String? _error;
  bool _busy = false;
  bool _opened = false;
  Map<String, dynamic> _meta = const {};
  int _openSeq = 0;

  @override
  void dispose() {
    _pw.dispose();
    super.dispose();
  }

  Future<void> _cleanup() async {
    // 纯内存预览不再产生临时目录；这里只清掉旧版本遗留的预览缓存。
    await sweepStalePreviewDirs();
  }

  Future<void> _pick() async {
    // Android 走自带真实路径浏览器：file_selector 的 SAF 实现会把整个文件
    // readFully 成一个 byte[]（file_selector_android 的 FileSelectorApiImpl），
    // 选一个 200 MiB 的容器就直接 OOM 闪退，拿到的还是缓存副本路径。
    if (Platform.isAndroid) {
      if (!mounted) return;
      final picked = await showFileBrowser(
        context,
        title: '选择加密文件',
        safefileOnly: true,
      );
      if (picked == null || picked.isEmpty) return;
      setState(() {
        _container = picked.first;
        _error = null;
      });
      return;
    }
    final group = const XTypeGroup(label: 'SafeFile 加密文件', extensions: ['safefile']);
    final files = await openFiles(acceptedTypeGroups: [group]);
    if (files.isEmpty) return;
    setState(() {
      _container = files.first.path;
      _error = null;
    });
  }

  Future<void> _open() async {
    if (_container == null || _pw.text.isEmpty) {
      setState(() => _error = '请选择加密文件并输入密码');
      return;
    }
    final seq = ++_openSeq;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      // 先校验密码与完整性：错误密码不必让预览组件再跑一遍解密。
      final res = await widget.state.verifyOffThread(_container!, _pw.text);
      if (!mounted || seq != _openSeq) return;
      if (res['ok'] != true) {
        setState(() {
          _busy = false;
          _opened = false;
          _error = '${res['message'] ?? '密码或文件不正确'}';
        });
        return;
      }
      final meta = Map<String, dynamic>.from(res['metadata'] as Map? ?? const {});
      await _cleanup();
      if (!mounted || seq != _openSeq) return;
      setState(() {
        _meta = meta;
        _opened = true;
        _busy = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _opened = false;
        _error = '$e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListView(
      padding: Tokens.pageInsets(context),
      children: [
        PageHeader(
          title: '安全预览',
          subtitle: '解密与解析均在内存中完成，不写入磁盘',
          actions: [
            OutlinedButton.icon(
              onPressed: _pick,
              icon: const Icon(Icons.folder_open_outlined, size: 18),
              label: const Text('选择加密文件'),
            ),
            const SizedBox(width: 8),
            FilledButton.icon(
              onPressed: _busy ? null : _open,
              icon: const Icon(Icons.visibility_outlined, size: 18),
              label: Text(_busy ? '解密中…' : '打开预览'),
            ),
          ],
        ),
        const SizedBox(height: Tokens.gapLg),
        SectionCard(
          title: '目标文件',
          subtitle: _container ?? '尚未选择',
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Expanded(
                child: PasswordFields(controller: _pw, onStrength: widget.state.passwordStrength, label: '文件密码'),
              ),
            ],
          ),
        ),
        const SizedBox(height: Tokens.gap),
        if (_error != null)
          SectionCard(
            child: Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
          ),
        if (_opened && _container != null) ...[
          const SizedBox(height: Tokens.gap),
          SectionCard(
            title: '${_meta['filename'] ?? '加密文件'}',
            subtitle:
                '${formatBytes((_meta['original_size'] as num?)?.toInt() ?? 0)} · ${_meta['kind'] ?? ''} · 纯内存预览（磁盘上没有明文）',
            trailing: TextButton(
              onPressed: () => setState(() => _opened = false),
              child: const Text('关闭预览'),
            ),
            child: _buildPreview(theme),
          ),
        ],
      ],
    );
  }

  Widget _buildPreview(ThemeData theme) {
    return SafePreview(
      key: ValueKey('${_container!}|${_pw.text.hashCode}'),
      container: _container!,
      password: _pw.text,
    );
  }
}
