import 'dart:async';
import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';

import '../core/android_storage.dart';
import '../core/app_state.dart';
import '../core/paths.dart';
import '../core/share_core.dart';
import 'file_browser.dart';
import 'theme.dart';
import 'widgets.dart';

/// 局域网共享页。
///
/// 设计要点（与 Rust 侧 v2 协议一致）：
/// - 没有配对码：每台设备首次启动生成 Ed25519 身份，名称由公钥派生并持久化，
///   所以同一台设备永远只有一个名字；
/// - 固定端口 UDP 广播签名公告，双方在同一网段就自动出现在列表里；
/// - 连接时双向签名认证 + X25519 临时密钥协商，之后所有帧都是
///   XChaCha20-Poly1305 密文，界面显示 6 位短认证串供人眼核对。
class SharePage extends StatefulWidget {
  const SharePage({
    super.key,
    required this.state,
    this.configDirOverride,
    this.saveDirOverride,
    this.autoStart = true,
  });

  final AppState state;

  /// 测试用：固定身份/信任库目录（默认取应用支持目录下的 `lan`）。
  final String? configDirOverride;

  /// 测试用：固定接收目录（默认按平台选公共目录）。
  final String? saveDirOverride;

  /// 进入页面后是否自动开始等待接收（默认打开，免去用户多点一次）。
  final bool autoStart;

  @override
  State<SharePage> createState() => _SharePageState();
}

class _SharePageState extends State<SharePage> {
  bool _tabReceive = true;

  LanStatus? _lan;
  bool _lanFailed = false;
  String _lanError = '';

  ShareListener? _listener;
  Timer? _listenTimer;
  ShareProgress _listenProgress = const ShareProgress();
  String _saveDir = '';
  bool _overwrite = false;

  List<SharePeer> _peers = const <SharePeer>[];
  bool _scanning = false;
  Timer? _peerTimer;
  String _selectedId = '';

  final TextEditingController _addrCtrl = TextEditingController();
  final List<String> _sendPaths = <String>[];
  ShareSender? _sender;
  Timer? _sendTimer;
  ShareProgress _sendProgress = const ShareProgress();

  @override
  void initState() {
    super.initState();
    widget.state.addListener(_refreshSaveDir);
    _boot();
  }

  /// 保存目录为空（多为 Android 未授权）时，等权限到位后自动补上真实路径。
  void _refreshSaveDir() {
    if (_saveDir.isNotEmpty || _listener != null) return;
    if (Platform.isAndroid && !widget.state.storageGranted) return;
    _loadSaveDir();
  }

  Future<void> _boot() async {
    final status = await initLanAuto(preferred: widget.configDirOverride);
    if (!mounted) return;
    setState(() {
      _lan = status;
      _lanFailed = status == null;
      _lanError = status == null ? lanLastError : '';
    });
    await _loadSaveDir();
    if (!mounted) return;
    if (widget.autoStart && _listener == null && _saveDir.isNotEmpty) {
      await _startReceive(auto: true);
    }
  }

  Future<void> _loadSaveDir() async {
    final override = widget.saveDirOverride;
    final dir = override ?? await defaultSaveDir();
    if (!mounted) return;
    setState(() => _saveDir = dir);
  }

  @override
  void dispose() {
    widget.state.removeListener(_refreshSaveDir);
    _listenTimer?.cancel();
    _sendTimer?.cancel();
    _peerTimer?.cancel();
    _listener?.stop();
    _sender?.free();
    _addrCtrl.dispose();
    super.dispose();
  }

  // ---------- 设备发现 ----------

  void _watchPeers() {
    _peerTimer?.cancel();
    _peerTimer = Timer.periodic(const Duration(milliseconds: 2500), (_) async {
      final peers = await lanPeers();
      if (!mounted) return;
      setState(() {
        _peers = peers;
        _pruneSelection();
      });
    });
  }

  void _pruneSelection() {
    if (_selectedId.isEmpty) return;
    if (!_peers.any((p) => p.id == _selectedId)) _selectedId = '';
  }

  Future<void> _refreshPeers() async {
    if (_scanning) return;
    setState(() => _scanning = true);
    final peers = await discoverPeers(const Duration(milliseconds: 1200));
    if (!mounted) return;
    setState(() {
      _peers = peers;
      _scanning = false;
      _pruneSelection();
    });
    if (peers.isEmpty) {
      _snack('还没发现设备：确认两台设备在同一 Wi-Fi，且对方开着「等待接收」');
    }
  }

  // ---------- 接收 ----------

  Future<void> _startReceive({bool auto = false}) async {
    if (!widget.state.storageGranted) {
      if (auto) return;
      final ok = await widget.state.ensureStorageAccess();
      if (!ok) return;
      await _loadSaveDir();
      if (!mounted) return;
    }
    if (_saveDir.isEmpty) {
      if (!auto) _snack('保存目录不可用：请授予「所有文件访问权限」，或点「更改」另选一个目录');
      return;
    }
    final listener = ShareListener.start(
      _saveDir,
      overwrite: _overwrite,
      durable: false,
    );
    if (listener == null) {
      if (!auto) _snack('无法开始接收：保存目录不可写，或端口被占用');
      return;
    }
    setState(() {
      _listener = listener;
      _tabReceive = true;
      _listenProgress = const ShareProgress();
    });
    _listenTimer?.cancel();
    _listenTimer = Timer.periodic(const Duration(milliseconds: 400), (_) {
      final l = _listener;
      if (l == null) return;
      final p = l.poll();
      if (!mounted) return;
      setState(() => _listenProgress = p);
      if (p.finished && p.peer.isNotEmpty && p.error == null) {
        _snack('已接收 ${p.filesDone} 个文件（来自 ${p.peer}）');
      }
    });
  }

  void _stopReceive() {
    _listenTimer?.cancel();
    _listenTimer = null;
    _listener?.stop();
    setState(() {
      _listener = null;
      _listenProgress = const ShareProgress();
    });
  }

  // ---------- 发送 ----------

  Future<void> _pickFiles() async {
    if (!widget.state.storageGranted) {
      final ok = await widget.state.ensureStorageAccess();
      if (!ok) return;
    }
    if (Platform.isAndroid) {
      if (!mounted) return;
      final picked = await showFileBrowser(context, title: '选择要发送的文件');
      if (picked != null && picked.isNotEmpty) {
        setState(() {
          for (final p in picked) {
            if (!_sendPaths.contains(p)) _sendPaths.add(p);
          }
        });
      }
      return;
    }
    // 桌面端用系统原生对话框：应用内的 /storage 浏览器只适用于 Android。
    if (!mounted) return;
    final picked = await FilePick.pickFiles();
    if (picked.isEmpty) return;
    setState(() {
      for (final p in picked) {
        if (!_sendPaths.contains(p)) _sendPaths.add(p);
      }
    });
  }

  /// 选一个目录，把里面所有文件加入发送列表。
  ///
  /// 传输协议只携带文件名（接收端会收敛到 basename 防穿越），所以目录层级
  /// 不保留；这里在提示里说明，避免用户以为会还原目录结构。
  Future<void> _pickDir() async {
    if (!mounted) return;
    final dir = Platform.isAndroid
        ? await showDirectoryPicker(context, title: '选择要发送的目录')
        : await getDirectoryPath(confirmButtonText: '选择此目录');
    if (dir == null || !mounted) return;

    const cap = 5000;
    final found = <String>[];
    var truncated = false;
    try {
      await for (final entry
          in Directory(dir).list(recursive: true, followLinks: false)) {
        if (entry is! File) continue;
        final name = _baseName(entry.path);
        if (name.startsWith('.')) continue;
        found.add(entry.path);
        if (found.length >= cap) {
          truncated = true;
          break;
        }
      }
    } catch (e) {
      _snack('无法读取目录：$e');
      return;
    }
    if (found.isEmpty) {
      _snack('这个目录里没有文件');
      return;
    }
    setState(() {
      for (final path in found) {
        if (!_sendPaths.contains(path)) _sendPaths.add(path);
      }
    });
    _snack('已加入 ${found.length} 个文件'
        '${truncated ? '（超过 $cap 个，已截断）' : ''}；接收端按文件名保存，不保留目录层级');
  }

  void _startSend() {
    final selected = _peers.where((p) => p.id == _selectedId).toList();
    final peer = selected.isNotEmpty ? selected.first.addr : _addrCtrl.text.trim();
    if (peer.isEmpty) {
      _snack('先在列表里选一台设备，或填对方地址');
      return;
    }
    if (selected.isNotEmpty && selected.first.trust == PeerTrust.changed) {
      _snack('对方设备身份已变更，按安全策略拒绝连接。');
      return;
    }
    if (_sendPaths.isEmpty) {
      _snack('先选要发送的文件');
      return;
    }
    final sender = ShareSender.start(peer, List<String>.from(_sendPaths));
    if (sender == null) {
      _snack('无法开始发送：检查设备地址与文件是否可读');
      return;
    }
    setState(() {
      _sender = sender;
      _sendProgress = const ShareProgress();
    });
    _sendTimer?.cancel();
    _sendTimer = Timer.periodic(const Duration(milliseconds: 400), (_) {
      final s = _sender;
      if (s == null) return;
      final p = s.poll();
      if (!mounted) return;
      setState(() => _sendProgress = p);
      if (p.finished) {
        _sendTimer?.cancel();
        _sendTimer = null;
        final error = p.error;
        if (error != null) {
          _snack('发送失败：${_friendly(error)}');
        } else {
          final who = p.peer.isEmpty ? '' : '给 ${p.peer}';
          _snack('$who 发送完成：${p.filesDone} 个文件');
        }
        s.free();
        setState(() => _sender = null);
      }
    });
  }

  void _cancelSend() {
    _sender?.cancel();
    _sendTimer?.cancel();
    _sendTimer = null;
    _sender?.free();
    setState(() => _sender = null);
  }

  String _friendly(String raw) {
    if (raw.contains('identity_changed')) return '对方设备身份已变更，按安全策略拒绝连接。';
    if (raw.contains('peer_busy')) return '对方正在与另一台设备传输。';
    if (raw.contains('peer_not_found')) return '未找到该设备，请刷新设备列表。';
    if (raw.contains('auth_failed') || raw.contains('protocol')) {
      return '握手校验未通过，连接已终止。';
    }
    if (raw.contains('Connection refused') || raw.contains('os error 10061')) {
      return '连接被拒绝，请确认对方处于「等待接收」状态且未被防火墙拦截。';
    }
    if (raw.contains('timed out') || raw.contains('os error 110')) {
      return '连接超时，请确认双方处于同一局域网且未被防火墙拦截。';
    }
    return raw;
  }

  void _snack(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  /// 文件/目录的显示名：Windows 用 `\`，别按 `/` 切。
  static String _baseName(String path) {
    final cut = path.lastIndexOf(RegExp(r'[\\/]'));
    return cut < 0 ? path : path.substring(cut + 1);
  }

  @override
  Widget build(BuildContext context) {
    final pageInsets = Tokens.pageInsets(context);
    return ListView(
      padding: pageInsets,
      children: [
        _Header(receiving: _listener != null),
        const SizedBox(height: 12),
        SegmentedButton<bool>(
          segments: const [
            ButtonSegment(value: true, icon: Icon(Icons.download), label: Text('接收')),
            ButtonSegment(value: false, icon: Icon(Icons.upload), label: Text('发送')),
          ],
          selected: {_tabReceive},
          onSelectionChanged: (v) {
            setState(() => _tabReceive = v.first);
            if (!v.first) {
              _refreshPeers();
              _watchPeers();
            } else {
              _peerTimer?.cancel();
              _peerTimer = null;
            }
          },
        ),
        const SizedBox(height: 16),
        ..._identitySection(context),
        const SizedBox(height: 12),
        if (_tabReceive) ..._receiveSection(context) else ..._sendSection(context),
      ],
    );
  }

  // ---------- 我的设备 ----------

  List<Widget> _identitySection(BuildContext context) {
    final theme = Theme.of(context);
    final lan = _lan;
    if (_lanFailed || lan == null) {
      return [
        _Card(
          title: '本机身份',
          trailing: TextButton.icon(
            onPressed: _boot,
            icon: const Icon(Icons.refresh, size: 16),
            label: const Text('重试'),
          ),
          children: [
            Text(
              '本机网络身份尚未就绪。局域网传输可使用「手动地址」直连；'
              '自动发现与公开接收功能在身份就绪后生效。',
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
            ),
            if (_lanError.isNotEmpty) ...[
              const SizedBox(height: 6),
              SelectableText(
                '原因：$_lanError',
                style: theme.textTheme.labelSmall?.copyWith(
                  fontFamily: 'monospace',
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            const SizedBox(height: 6),
            Text(
              '排查：确认 safefile_ffi.dll 与 safefile.exe 在同一目录；'
              '若提示目录不可写，可用环境变量 SAFEFILE_CONFIG_DIR 指定一个可写目录后重启。',
              style: theme.textTheme.labelSmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ];
    }
    return [
      _Card(
        title: '我的设备',
        trailing: _listener != null
            ? Chip(
                visualDensity: VisualDensity.compact,
                avatar: Icon(Icons.wifi_tethering, size: 16, color: theme.colorScheme.primary),
                label: const Text('等待接收'),
              )
            : null,
        children: [
          Text(
            lan.name,
            style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 4),
          SelectableText(
            '地址 ${lan.endpoint}',
            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
          ),
          const SizedBox(height: 2),
          SelectableText(
            '指纹 ${lan.fingerprint}',
            style: theme.textTheme.labelSmall?.copyWith(
              fontFamily: 'monospace',
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          if (lan.discoveryError != null)
            Text(
              '广播不可用：${lan.discoveryError}',
              style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.error),
            ),
        ],
      ),
    ];
  }

  // ---------- 接收区 ----------

  List<Widget> _receiveSection(BuildContext context) {
    final theme = Theme.of(context);
    final session = _listener?.session;
    return [
      _Card(
        title: '保存位置',
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  _saveDir.isNotEmpty
                      ? _saveDir
                      : (Platform.isAndroid
                          ? '未授权：授予「所有文件访问权限」后保存到 ${AndroidStorage.publicRoot}'
                          : '（未设置）'),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: _saveDir.isEmpty && Platform.isAndroid ? theme.colorScheme.error : null,
                  ),
                ),
              ),
              if (Platform.isAndroid && _saveDir.isEmpty)
                TextButton(
                  onPressed: _listener != null
                      ? null
                      : () async {
                          final ok = await widget.state.ensureStorageAccess();
                          if (!ok || !mounted) return;
                          await _loadSaveDir();
                        },
                  child: const Text('去授权'),
                ),
              TextButton(
                onPressed: _listener != null
                    ? null
                    : () async {
                        // 桌面端用系统目录对话框；应用内 /storage 浏览器只适用于 Android。
                        final dir = Platform.isAndroid
                            ? await showDirectoryPicker(context, title: '选择接收目录')
                            : await getDirectoryPath(confirmButtonText: '选择此目录');
                        if (dir != null && mounted) setState(() => _saveDir = dir);
                      },
                child: const Text('更改'),
              ),
            ],
          ),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            value: _overwrite,
            onChanged: _listener != null ? null : (v) => setState(() => _overwrite = v),
            title: const Text('覆盖同名文件'),
            subtitle: const Text('关闭时同名文件直接跳过，不会改动已有内容'),
          ),
        ],
      ),
      const SizedBox(height: 12),
      if (session == null)
        _Card(
          title: '等待接收',
          children: [
            Text(
              '开启后本机将在固定端口广播可接收状态，同一局域网内的设备将自动发现本机，无需配对码。',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: _startReceive,
                icon: const Icon(Icons.wifi_tethering),
                label: const Text('开始接收'),
              ),
            ),
          ],
        )
      else
        _Card(
          title: '正在等待发送端',
          children: [
            Text(
              '其他设备会在列表里看到「${session.name}」，选中即可直连；'
              '连接建立后本页显示 6 位安全码；该安全码与对方屏幕一致，即可确认连接未经中间人替换。',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            if (_listenProgress.sas.isNotEmpty)
              Row(
                children: [
                  Text('安全码 ', style: theme.textTheme.bodySmall),
                  Text(
                    _listenProgress.sas,
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                      letterSpacing: 4,
                      color: theme.colorScheme.primary,
                    ),
                  ),
                  const SizedBox(width: 8),
                  if (_listenProgress.peer.isNotEmpty)
                    Text(
                      '· ${_listenProgress.peer}',
                      style: theme.textTheme.bodySmall,
                    ),
                ],
              ),
            const SizedBox(height: 12),
            _ProgressBlock(progress: _listenProgress, receiving: true),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: Text(
                    '已接收 ${_listenProgress.sessions} 次会话',
                    style: theme.textTheme.labelSmall,
                  ),
                ),
                OutlinedButton(onPressed: _stopReceive, child: const Text('停止接收')),
              ],
            ),
            if (_listenProgress.reason != null)
              Text(
                '最近一次问题：${_listenProgress.reason}',
                style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.error),
              ),
          ],
        ),
    ];
  }

  // ---------- 发送区 ----------

  List<Widget> _sendSection(BuildContext context) {
    final theme = Theme.of(context);
    final sending = _sender != null && !_sendProgress.finished;
    return [
      _Card(
        title: '附近设备',
        trailing: TextButton(
          onPressed: _scanning || sending ? null : _refreshPeers,
          child: Text(_scanning ? '刷新中…' : '刷新'),
        ),
        children: [
          if (_peers.isEmpty)
            Text(
              _scanning ? '正在搜索同一 Wi-Fi 上的设备…' : '还没有发现设备，点右上角刷新试试。',
              style: theme.textTheme.bodySmall,
            )
          else
            for (final p in _peers) _peerTile(p, sending: sending),
          const SizedBox(height: 8),
          TextField(
            controller: _addrCtrl,
            enabled: !sending,
            keyboardType: TextInputType.url,
            decoration: const InputDecoration(
              labelText: '或手动填地址',
              hintText: '192.168.1.8:47778',
              isDense: true,
            ),
          ),
        ],
      ),
      const SizedBox(height: 12),
      _Card(
        title: '要发送的文件',
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextButton(
              onPressed: sending ? null : _pickDir,
              child: const Text('选文件夹'),
            ),
            TextButton(
              onPressed: sending ? null : _pickFiles,
              child: const Text('选择文件'),
            ),
          ],
        ),
        children: [
          if (_sendPaths.isEmpty)
            Text('还没有选择文件', style: theme.textTheme.bodySmall)
          else ...[
            for (final path in _sendPaths)
              ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.insert_drive_file_outlined, size: 20),
                title: Text(_baseName(path), maxLines: 1, overflow: TextOverflow.ellipsis),
                subtitle: Text(path, maxLines: 1, overflow: TextOverflow.ellipsis),
                trailing: IconButton(
                  icon: const Icon(Icons.close, size: 18),
                  onPressed: sending ? null : () => setState(() => _sendPaths.remove(path)),
                ),
              ),
            Text('共 ${_sendPaths.length} 项', style: theme.textTheme.labelSmall),
          ],
        ],
      ),
      const SizedBox(height: 12),
      if (_sender == null)
        SizedBox(
          width: double.infinity,
          child: FilledButton.icon(
            onPressed: _startSend,
            icon: const Icon(Icons.send),
            label: const Text('发送'),
          ),
        )
      else
        _Card(
          title: '传输中',
          children: [
            if (_sendProgress.sas.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(
                  '安全码 ${_sendProgress.sas}'
                  '${_sendProgress.peer.isEmpty ? '' : ' · ${_sendProgress.peer}'}',
                  style: theme.textTheme.bodySmall,
                ),
              ),
            _ProgressBlock(progress: _sendProgress, receiving: false),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerRight,
              child: OutlinedButton(onPressed: _cancelSend, child: const Text('取消')),
            ),
          ],
        ),
    ];
  }

  Widget _peerTile(SharePeer p, {required bool sending}) {
    final theme = Theme.of(context);
    final selected = p.id == _selectedId;
    final blocked = p.trust == PeerTrust.changed;
    final trustLabel = switch (p.trust) {
      PeerTrust.trusted => '已信任',
      PeerTrust.fresh => '首次连接',
      PeerTrust.changed => '身份已变化',
      PeerTrust.unknown => '',
    };
    return ListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      selected: selected,
      enabled: !sending && !blocked,
      leading: Icon(
        blocked ? Icons.gpp_bad_outlined : Icons.devices,
        size: 20,
        color: blocked ? theme.colorScheme.error : null,
      ),
      title: Text(p.name, maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: Text(
        [
          p.addr,
          if (p.accepting) '可接收',
          if (trustLabel.isNotEmpty) trustLabel,
        ].join(' · '),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: selected ? const Icon(Icons.check_circle, size: 18) : null,
      onTap: sending || blocked
          ? null
          : () => setState(() => _selectedId = selected ? '' : p.id),
    );
  }
}

class _Card extends StatelessWidget {
  const _Card({required this.title, this.trailing, required this.children});

  final String title;
  final Widget? trailing;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => SectionCard(
    title: title,
    trailing: trailing,
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: children),
  );
}

class _Header extends StatelessWidget {
  const _Header({required this.receiving});

  final bool receiving;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('局域网传输', style: theme.textTheme.titleLarge),
        const SizedBox(height: 4),
        Text(
          receiving
              ? '局域网内自动发现 · 设备签名认证 · XChaCha20-Poly1305 全程加密'
              : '选设备直连 · 无需配对码 · 逐文件 BLAKE3 校验',
          style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
        ),
      ],
    );
  }
}

class _ProgressBlock extends StatelessWidget {
  const _ProgressBlock({required this.progress, required this.receiving});

  final ShareProgress progress;
  final bool receiving;

  String _bytes(int v) {
    if (v < 1024) return '$v B';
    if (v < 1024 * 1024) return '${(v / 1024).toStringAsFixed(1)} KiB';
    if (v < 1024 * 1024 * 1024) return '${(v / (1024 * 1024)).toStringAsFixed(1)} MiB';
    return '${(v / (1024 * 1024 * 1024)).toStringAsFixed(2)} GiB';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final p = progress;
    final speed = p.speedBps <= 0 ? '' : ' · ${_bytes(p.speedBps.round())}/s';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (p.current.isNotEmpty)
          Text(p.current, maxLines: 1, overflow: TextOverflow.ellipsis, style: theme.textTheme.bodySmall),
        const SizedBox(height: 6),
        LinearProgressIndicator(value: p.totalBytes > 0 ? p.fraction : null),
        const SizedBox(height: 6),
        Text(
          '${receiving ? '已接收' : '已发送'} ${_bytes(p.doneBytes)}'
          '${p.totalBytes > 0 ? ' / ${_bytes(p.totalBytes)}' : ''}'
          ' · 文件 ${p.filesDone}/${p.filesTotal}'
          '${p.skipped > 0 ? ' · 跳过 ${p.skipped}' : ''}$speed',
          style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
        ),
        if (p.error != null)
          Text(p.error!, style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.error)),
      ],
    );
  }
}
