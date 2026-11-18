import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:path_provider/path_provider.dart';

import 'native_core.dart' show NativeCore;

/// 局域网共享的 FFI 封装（v2：无配对码）。
///
/// 与加密接口同一份动态库：收/发都在 Rust 线程里跑，Dart 只负责起停与轮询快照。
/// 身份私钥、会话密钥、明文都不经过 Dart，也不写日志。
///
/// 安全模型：每台设备首次启动生成一份 Ed25519 身份并持久保存，显示名由公钥
/// 派生后固定下来；发现靠固定端口 UDP 广播的签名公告，连接时双向签名认证 +
/// X25519 临时密钥协商，会话内所有帧用 XChaCha20-Poly1305 加密。

/// 本机节点状态（我是谁、在哪个地址、能否被局域网发现）。
class LanStatus {
  const LanStatus({
    required this.id,
    required this.name,
    required this.fingerprint,
    required this.port,
    required this.discoveryPort,
    required this.addrs,
    required this.accepting,
    required this.discoveryOk,
    this.discoveryError,
    this.trustedPeerCount = 0,
    this.peerCount = 0,
  });

  final String id;
  final String name;
  final String fingerprint;
  final int port;
  final int discoveryPort;
  final List<String> addrs;
  final bool accepting;
  final bool discoveryOk;
  final String? discoveryError;
  final int trustedPeerCount;
  final int peerCount;

  String get endpoint {
    final host = addrs.isNotEmpty ? addrs.first : '0.0.0.0';
    return '$host:$port';
  }

  factory LanStatus.fromJson(Map<String, dynamic> json) => LanStatus(
    id: (json['id'] as String?) ?? '',
    name: (json['name'] as String?) ?? '未知设备',
    fingerprint: (json['fingerprint'] as String?) ?? '',
    port: (json['port'] as num?)?.toInt() ?? 0,
    discoveryPort: (json['discovery_port'] as num?)?.toInt() ?? 0,
    addrs:
        (json['addrs'] as List?)?.map((e) => e.toString()).toList() ?? const <String>[],
    accepting: json['accepting'] == true,
    discoveryOk: json['discovery_ok'] == true,
    discoveryError: json['discovery_error'] as String?,
    trustedPeerCount: (json['trusted_peer_count'] as num?)?.toInt() ?? 0,
    peerCount: (json['peer_count'] as num?)?.toInt() ?? 0,
  );
}

/// 接收端会话信息。
class ShareSession {
  const ShareSession({
    required this.name,
    required this.id,
    required this.fingerprint,
    required this.port,
    required this.addrs,
  });

  final String name;
  final String id;
  final String fingerprint;
  final int port;
  final List<String> addrs;

  /// 供界面展示的「地址:端口」。
  String get endpoint {
    final host = addrs.isNotEmpty ? addrs.first : '0.0.0.0';
    return '$host:$port';
  }
}

/// 一段传输的进度快照。
class ShareProgress {
  const ShareProgress({
    this.filesTotal = 0,
    this.filesDone = 0,
    this.totalBytes = 0,
    this.doneBytes = 0,
    this.current = '',
    this.skipped = 0,
    this.finished = false,
    this.running = false,
    this.sessions = 0,
    this.speedBps = 0,
    this.error,
    this.reason,
    this.peer = '',
    this.peerId = '',
    this.sas = '',
    this.encrypted = false,
  });

  final int filesTotal;
  final int filesDone;
  final int totalBytes;
  final int doneBytes;
  final String current;
  final int skipped;
  final bool finished;
  final bool running;
  final int sessions;
  final double speedBps;
  final String? error;
  final String? reason;

  /// 对端设备名 / 设备 id。
  final String peer;
  final String peerId;

  /// 6 位短认证串：两侧相同才说明没有中间人。
  final String sas;
  final bool encrypted;

  double get fraction {
    if (totalBytes <= 0) return finished ? 1 : 0;
    return (doneBytes / totalBytes).clamp(0, 1).toDouble();
  }

  factory ShareProgress.fromJson(Map<String, dynamic> json) => ShareProgress(
    filesTotal: (json['files_total'] as num?)?.toInt() ?? 0,
    filesDone: (json['files_done'] as num?)?.toInt() ?? 0,
    totalBytes: (json['total_bytes'] as num?)?.toInt() ?? 0,
    doneBytes: (json['done_bytes'] as num?)?.toInt() ?? 0,
    current: (json['current'] as String?) ?? '',
    skipped: (json['skipped'] as num?)?.toInt() ?? 0,
    finished: json['finished'] == true,
    running: json['running'] == true,
    sessions: (json['sessions'] as num?)?.toInt() ?? 0,
    speedBps: (json['speed_bps'] as num?)?.toDouble() ?? 0,
    error: json['error'] as String?,
    reason: json['reason'] as String?,
    peer: (json['peer'] as String?) ?? '',
    peerId: (json['peer_id'] as String?) ?? '',
    sas: (json['sas'] as String?) ?? '',
    encrypted: json['encrypted'] == true,
  );
}

/// 信任状态。
enum PeerTrust { trusted, fresh, changed, unknown }

PeerTrust _trustOf(String? raw) => switch (raw) {
  'trusted' => PeerTrust.trusted,
  'new' => PeerTrust.fresh,
  'changed' => PeerTrust.changed,
  _ => PeerTrust.unknown,
};

/// 局域网内发现的设备。
class SharePeer {
  const SharePeer({
    required this.id,
    required this.name,
    required this.addr,
    this.fingerprint = '',
    this.accepting = false,
    this.lastSeenMs = 0,
    this.trust = PeerTrust.unknown,
  });

  final String id;
  final String name;

  /// `ip:port`，直接传给发送接口即可。
  final String addr;
  final String fingerprint;

  /// 对端是否正在等待接收。
  final bool accepting;
  final int lastSeenMs;
  final PeerTrust trust;

  factory SharePeer.fromJson(Map<String, dynamic> j) => SharePeer(
    id: (j['id'] as String?) ?? '',
    name: (j['name'] as String?) ?? '未知设备',
    addr: (j['addr'] as String?) ?? '',
    fingerprint: (j['fingerprint'] as String?) ?? '',
    accepting: j['accepting'] == true,
    lastSeenMs: (j['last_seen_ms'] as num?)?.toInt() ?? 0,
    trust: _trustOf(j['trust'] as String?),
  );
}

class _Bindings {
  _Bindings(this.lib);

  final DynamicLibrary lib;

  late final Pointer<Utf8> Function(Pointer<Utf8>, int) lanInit = lib
      .lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>, Int32),
        Pointer<Utf8> Function(Pointer<Utf8>, int)
      >('sf_lan_init');
  late final Pointer<Utf8> Function() lanStatus = lib
      .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('sf_lan_status');
  late final Pointer<Utf8> Function() lanPeersFfi = lib
      .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('sf_lan_peers');
  late final Pointer<Utf8> Function() lanRefreshFfi = lib
      .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('sf_lan_refresh');
  late final Pointer<Utf8> Function() lanFingerprintFfi = lib
      .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>(
        'sf_lan_fingerprint',
      );
  late final Pointer<Utf8> Function() localAddrs = lib
      .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('sf_local_addrs');
  late final Pointer<Void> Function(Pointer<Utf8>, int, bool, bool) shareStart = lib
      .lookupFunction<
        Pointer<Void> Function(Pointer<Utf8>, Int32, Bool, Bool),
        Pointer<Void> Function(Pointer<Utf8>, int, bool, bool)
      >('sf_share_start');
  late final Pointer<Utf8> Function(Pointer<Void>) shareInfo = lib
      .lookupFunction<Pointer<Utf8> Function(Pointer<Void>), Pointer<Utf8> Function(Pointer<Void>)>(
        'sf_share_info',
      );
  late final Pointer<Utf8> Function(Pointer<Void>) sharePoll = lib
      .lookupFunction<Pointer<Utf8> Function(Pointer<Void>), Pointer<Utf8> Function(Pointer<Void>)>(
        'sf_share_poll',
      );
  late final void Function(Pointer<Void>) shareFree = lib
      .lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>('sf_share_free');
  late final Pointer<Void> Function(Pointer<Utf8>, Pointer<Utf8>) sendStart = lib
      .lookupFunction<
        Pointer<Void> Function(Pointer<Utf8>, Pointer<Utf8>),
        Pointer<Void> Function(Pointer<Utf8>, Pointer<Utf8>)
      >('sf_send_start');
  late final Pointer<Utf8> Function(Pointer<Void>) sendPoll = lib
      .lookupFunction<Pointer<Utf8> Function(Pointer<Void>), Pointer<Utf8> Function(Pointer<Void>)>(
        'sf_send_poll',
      );
  late final void Function(Pointer<Void>) sendCancel = lib
      .lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>('sf_send_cancel');
  late final void Function(Pointer<Void>) sendFree = lib
      .lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>('sf_send_free');
  late final void Function(Pointer<Utf8>) freeString = lib
      .lookupFunction<Void Function(Pointer<Utf8>), void Function(Pointer<Utf8>)>('sf_free_string');

  String _take(Pointer<Utf8> p) {
    if (p == nullptr) return '{"ok":false,"code":"null_result"}';
    try {
      return p.toDartString();
    } finally {
      freeString(p);
    }
  }

  Map<String, dynamic> _json(Pointer<Utf8> p) {
    final raw = _take(p);
    final decoded = jsonDecode(raw);
    return decoded is Map<String, dynamic> ? decoded : <String, dynamic>{'ok': false};
  }

  static _Bindings? _instance;
  static _Bindings get instance => _instance ??= _Bindings(DynamicLibrary.open(_libPath()));

  static String _libPath() {
    final name = Platform.isWindows
        ? 'safefile_ffi.dll'
        : Platform.isMacOS
            ? 'libsafefile_ffi.dylib'
            : 'libsafefile_ffi.so';
    // 优先用可执行文件同目录的副本：从快捷方式/其他工作目录启动时也能加载。
    try {
      final exeDir = File(Platform.resolvedExecutable).parent.path;
      final beside = '$exeDir${Platform.pathSeparator}$name';
      if (File(beside).existsSync()) return beside;
    } catch (_) {
      // 取不到可执行文件路径时退回系统搜索路径。
    }
    return name;
  }
}

/// 初始化本机局域网身份与发现（幂等，可重复调用）。
///
/// `configDir` 用来保存身份密钥与信任库；Android 传应用私有目录，
/// Windows 传 `%APPDATA%\\SafeFile`。失败返回 null。
Future<LanStatus?> initLan(String configDir, {int discoveryPort = 0}) async {
  return _guard<LanStatus?>(() {
    final b = _Bindings.instance;
    final ptr = configDir.toNativeUtf8();
    try {
      final json = b._json(b.lanInit(ptr, discoveryPort));
      if (json['ok'] != true) {
        lanLastError = (json['error'] as String?) ?? '初始化失败（ok=false）';
        return null;
      }
      lanLastError = '';
      return LanStatus.fromJson(json);
    } finally {
      malloc.free(ptr);
    }
  });
}

/// 本机状态；节点尚未初始化时返回 null。
Future<LanStatus?> lanStatus() async {
  return _guard<LanStatus?>(() {
    final b = _Bindings.instance;
    final json = b._json(b.lanStatus());
    return json['ok'] == true ? LanStatus.fromJson(json) : null;
  });
}

/// 当前看到的设备列表。
Future<List<SharePeer>> lanPeers() async {
  return _guard(() => _peersOf(_Bindings.instance._json(_Bindings.instance.lanPeersFfi()))) ??
      const <SharePeer>[];
}

/// 重新浏览设备列表（立刻发一次探测，稍后再拉一次才完整）。
Future<List<SharePeer>> discoverPeers([Duration wait = const Duration(milliseconds: 900)]) async {
  // 立刻发一次探测；对端收到后会马上回广播，稍后再拉列表才完整。
  _guard<List<SharePeer>>(
    () => _peersOf(_Bindings.instance._json(_Bindings.instance.lanRefreshFfi())),
  );
  if (wait > Duration.zero) {
    await Future<void>.delayed(wait);
  }
  return lanPeers();
}

List<SharePeer> _peersOf(Map<String, dynamic> json) {
  if (json['ok'] != true) return const <SharePeer>[];
  final peers = (json['peers'] as List?) ?? const <Object?>[];
  return [
    for (final p in peers)
      if (p is Map) SharePeer.fromJson(Map<String, dynamic>.from(p)),
  ];
}

T? _guard<T>(T Function() body) {
  try {
    return body();
  } catch (e) {
    lanLastError = e.toString();
    return null;
  }
}

/// 最近一次局域网相关调用的失败原因（给界面显示，便于区分「缺少动态库」和
/// 「配置目录不可写」）。成功后清空。
String lanLastError = '';

/// 初始化局域网节点，按优先级依次尝试可写目录。
///
/// 顺序：`SAFEFILE_CONFIG_DIR` → 应用支持目录 → 可执行文件旁的 `safefile-data`
/// → 系统临时目录。命中第一个可写目录即返回；全部失败返回 null，
/// 具体原因留在 [lanLastError]。
Future<LanStatus?> initLanAuto({String? preferred}) async {
  final candidates = <String>[];
  void add(String path) {
    if (path.isEmpty) return;
    if (!candidates.contains(path)) candidates.add(path);
  }

  if (preferred != null) add(preferred);
  final env = Platform.environment['SAFEFILE_CONFIG_DIR'];
  if (env != null && env.trim().isNotEmpty) {
    add('${env.trim()}${Platform.pathSeparator}lan');
  }
  try {
    add('${(await getApplicationSupportDirectory()).path}${Platform.pathSeparator}lan');
  } catch (_) {
    // 没有 path_provider 时继续用后面的候选。
  }
  try {
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    add('$exeDir${Platform.pathSeparator}safefile-data');
  } catch (_) {
    // 某些平台拿不到可执行文件路径。
  }
  add('${Directory.systemTemp.path}${Platform.pathSeparator}safefile-lan');

  lanLastError = '';
  for (final dir in candidates) {
    if (dir.isEmpty) continue;
    final status = await initLan(dir);
    if (status != null) return status;
    // 记录是哪一级目录失败，方便用户自查。
    if (lanLastError.isNotEmpty) {
      lanLastError = '$dir: $lanLastError';
    }
  }
  return null;
}

/// 本机 IPv4 地址列表。
Future<List<String>> localAddrs() async {
  return _guard<List<String>>(() {
    final b = _Bindings.instance;
    final json = b._json(b.localAddrs());
    if (json['ok'] != true) return const <String>[];
    return [for (final a in (json['addrs'] as List?) ?? const <Object?>[]) a.toString()];
  }) ??
      const <String>[];
}

/// 本机身份（名字 / id / 指纹），不需要启动接收端也能用。
Future<LanStatus?> lanIdentity() async {
  return _guard<LanStatus?>(() {
    final b = _Bindings.instance;
    final json = b._json(b.lanFingerprintFfi());
    if (json['ok'] != true) return null;
    return LanStatus(
      id: (json['id'] as String?) ?? '',
      name: (json['name'] as String?) ?? '',
      fingerprint: (json['fingerprint'] as String?) ?? '',
      port: 0,
      discoveryPort: 0,
      addrs: const <String>[],
      accepting: false,
      discoveryOk: true,
    );
  });
}

/// 接收端（广播可接收状态、等待发送端连接）。
class ShareListener {
  ShareListener._(this._handle, this.session);

  final Pointer<Void> _handle;
  final ShareSession session;
  bool _freed = false;

  /// 启动失败返回 null（目录不可写、端口被占用等）。
  static ShareListener? start(
    String saveDir, {
    int port = 0,
    bool overwrite = false,
    bool durable = false,
  }) {
    final b = _Bindings.instance;
    final dirPtr = saveDir.toNativeUtf8();
    try {
      final handle = b.shareStart(dirPtr, port, overwrite, durable);
      if (handle == nullptr) return null;
      final info = b._json(b.shareInfo(handle));
      if (info['ok'] != true) {
        b.shareFree(handle);
        return null;
      }
      final addrs =
          (info['addrs'] as List?)?.map((e) => e.toString()).toList() ?? const <String>[];
      return ShareListener._(
        handle,
        ShareSession(
          name: (info['name'] as String?) ?? '',
          id: (info['id'] as String?) ?? '',
          fingerprint: (info['fingerprint'] as String?) ?? '',
          port: (info['port'] as num?)?.toInt() ?? 0,
          addrs: addrs,
        ),
      );
    } finally {
      malloc.free(dirPtr);
    }
  }

  ShareProgress poll() {
    if (_freed) return const ShareProgress();
    final b = _Bindings.instance;
    final json = b._json(b.sharePoll(_handle));
    if (json['ok'] != true) {
      return ShareProgress(error: json['message'] as String? ?? '读取进度失败');
    }
    return ShareProgress.fromJson(json);
  }

  void stop() {
    if (_freed) return;
    _freed = true;
    _Bindings.instance.shareFree(_handle);
  }
}

/// 发送端。
class ShareSender {
  ShareSender._(this._handle);

  final Pointer<Void> _handle;
  bool _freed = false;

  /// 启动失败返回 null（路径非法、地址为空等）。
  static ShareSender? start(String peer, List<String> paths) {
    if (paths.isEmpty || peer.trim().isEmpty) return null;
    final b = _Bindings.instance;
    final peerPtr = peer.trim().toNativeUtf8();
    final pathsPtr = jsonEncode(paths).toNativeUtf8();
    try {
      final handle = b.sendStart(peerPtr, pathsPtr);
      if (handle == nullptr) return null;
      return ShareSender._(handle);
    } finally {
      malloc.free(peerPtr);
      malloc.free(pathsPtr);
    }
  }

  ShareProgress poll() {
    if (_freed) return const ShareProgress();
    final b = _Bindings.instance;
    final json = b._json(b.sendPoll(_handle));
    if (json['ok'] != true) {
      return ShareProgress(error: json['message'] as String? ?? '读取进度失败');
    }
    return ShareProgress.fromJson(json);
  }

  void cancel() {
    if (_freed) return;
    _Bindings.instance.sendCancel(_handle);
  }

  void free() {
    if (_freed) return;
    _freed = true;
    _Bindings.instance.sendFree(_handle);
  }
}

/// 供调试：确认动态库能正常打开（页面初始化时调用一次）。
bool shareAvailable() {
  try {
    NativeCore.instance;
    _Bindings.instance;
    return true;
  } catch (_) {
    return false;
  }
}
