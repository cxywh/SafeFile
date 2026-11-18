import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'android_storage.dart';
import 'background_task.dart';
import 'native_core.dart';

/// KDF 预设（与 Rust 侧 `KdfParams` 对齐）。
enum KdfPreset { mobile, desktop, maximum }

extension KdfPresetInfo on KdfPreset {
  String get label => switch (this) {
    KdfPreset.mobile => '移动（32 MiB / 3 轮 / 2 并行）',
    KdfPreset.desktop => '桌面（64 MiB / 3 轮 / 4 并行）',
    KdfPreset.maximum => '高强度（256 MiB / 4 轮 / 8 并行）',
  };

  String get shortLabel => switch (this) {
    KdfPreset.mobile => '移动',
    KdfPreset.desktop => '桌面',
    KdfPreset.maximum => '高强度',
  };

  int get mCostKib => switch (this) {
    KdfPreset.mobile => 32768,
    KdfPreset.desktop => 65536,
    KdfPreset.maximum => 262144,
  };
  int get tCost => switch (this) {
    KdfPreset.mobile => 3,
    KdfPreset.desktop => 3,
    KdfPreset.maximum => 4,
  };
  int get pCost => switch (this) {
    KdfPreset.mobile => 2,
    KdfPreset.desktop => 4,
    KdfPreset.maximum => 8,
  };
}

/// 性能模式（与 Rust `PerfMode` 对齐：0 节能 / 1 均衡 / 2 高性能 / 3 自定义）。
enum PerfMode { eco, balanced, high, custom }

extension PerfModeInfo on PerfMode {
  int get code => index;
  String get label => switch (this) {
    PerfMode.eco => '节能',
    PerfMode.balanced => '均衡',
    PerfMode.high => '高性能',
    PerfMode.custom => '自定义',
  };
  String get description => switch (this) {
    PerfMode.eco => '单任务串行，最低资源占用',
    PerfMode.balanced => '并发数为 CPU 核数的一半',
    PerfMode.high => '并发数等于 CPU 核数',
    PerfMode.custom => '手动指定并发数',
  };
}

/// 单个任务的状态（来自 Rust 快照）。
class TaskItem {
  TaskItem({
    required this.id,
    required this.source,
    required this.dest,
    required this.size,
    required this.processed,
    required this.status,
    this.deleted = false,
    this.errorCode,
    this.errorMessage,
  });

  final int id;
  final String source;
  final String dest;
  final int size;
  final int processed;
  final String status;
  /// 该条目的输入文件是否已在成功后删除。
  final bool deleted;
  final String? errorCode;
  final String? errorMessage;

  String get name => source.split(RegExp(r'[\\/]')).last;

  /// 单个文件的完成度。
  /// 已成功的条目一律视为 100%：解密时「已处理字节」以明文计、而容器还带 4 KiB 元数据块与
  /// 每块 17 B 认证标签，用明文除以容器大小会得到 57% 这种假进度。
  double get progress {
    if (status == 'success') return 1;
    if (size <= 0) return 0;
    return (processed / size).clamp(0, 1);
  }

  String get statusLabel => switch (status) {
    'pending' => '等待',
    'running' => '处理中',
    'success' => '已完成',
    'failed' => '失败',
    'cancelled' => '已取消',
    _ => status,
  };

  factory TaskItem.fromMap(Map<String, dynamic> m) => TaskItem(
    id: (m['id'] as num?)?.toInt() ?? 0,
    source: m['source'] as String? ?? '',
    dest: m['dest'] as String? ?? '',
    size: (m['size'] as num?)?.toInt() ?? 0,
    processed: (m['processed'] as num?)?.toInt() ?? 0,
    status: m['status'] as String? ?? 'pending',
    deleted: m['deleted'] == true,
    errorCode: m['error_code'] as String?,
    errorMessage: m['error_message'] as String?,
  );
}

/// 批量任务运行状态。
class BatchState {
  BatchState({
    required this.decrypt,
    required this.items,
    required this.totalItems,
    required this.finishedItems,
    required this.successItems,
    required this.failedItems,
    required this.cancelledItems,
    required this.totalBytes,
    required this.processedBytes,
    required this.elapsedMs,
    required this.speedBps,
    required this.isDone,
    required this.isPaused,
    required this.concurrency,
    this.note,
  });

  final bool decrypt;
  final List<TaskItem> items;
  final int totalItems;
  final int finishedItems;
  final int successItems;
  final int failedItems;
  final int cancelledItems;
  final int totalBytes;
  final int processedBytes;
  final int elapsedMs;
  final int speedBps;
  final bool isDone;
  final bool isPaused;
  final int concurrency;

  /// 停止原因等诊断信息（如「引擎无进度，已自动取消」），不含密码与明文。
  final String? note;

  double get progress => totalItems == 0 ? 0 : finishedItems / totalItems;

  BatchState copyWith({
    bool? isDone,
    bool? isPaused,
    int? finishedItems,
    int? failedItems,
    int? cancelledItems,
    String? note,
  }) => BatchState(
    decrypt: decrypt,
    items: items,
    totalItems: totalItems,
    finishedItems: finishedItems ?? this.finishedItems,
    successItems: successItems,
    failedItems: failedItems ?? this.failedItems,
    cancelledItems: cancelledItems ?? this.cancelledItems,
    totalBytes: totalBytes,
    processedBytes: processedBytes,
    elapsedMs: elapsedMs,
    speedBps: speedBps,
    isDone: isDone ?? this.isDone,
    isPaused: isPaused ?? this.isPaused,
    concurrency: concurrency,
    note: note ?? this.note,
  );
}

/// 最近处理记录（本地持久化，不含密码/密钥）。
class RecentEntry {
  RecentEntry({required this.path, required this.action, required this.status, required this.timeMs});

  final String path;
  final String action; // encrypt / decrypt
  final String status; // success / failed
  final int timeMs;

  String get name => path.split(RegExp(r'[\\/]')).last;

  Map<String, dynamic> toJson() => {'path': path, 'action': action, 'status': status, 'time': timeMs};

  factory RecentEntry.fromJson(Map<String, dynamic> m) => RecentEntry(
    path: m['path'] as String? ?? '',
    action: m['action'] as String? ?? 'encrypt',
    status: m['status'] as String? ?? 'success',
    timeMs: (m['time'] as num?)?.toInt() ?? 0,
  );
}

/// 应用全局状态：设置、任务、最近记录、核心自检结果。
class AppState extends ChangeNotifier {
  AppState() {
    _core = NativeCore.instance;
    coreInfo = _core.version();
  }

  late final NativeCore _core;
  late Map<String, dynamic> coreInfo;

  KdfPreset kdfPreset = KdfPreset.desktop;
  PerfMode perfMode = PerfMode.balanced;
  int customConcurrency = 4;
  bool overwriteOutput = false;
  /// 成功后删除原文件（加密删明文、解密删容器）。失败与取消一律不删。
  bool deleteSource = false;
  /// 批量任务在应用退到后台时继续执行（Android 用前台服务保活并显示进度通知）。
  bool backgroundRun = true;
  bool darkMode = false;

  /// Android「所有文件访问权限」状态；非 Android 恒为 true。
  bool storageGranted = true;

  BatchHandle? _handle;
  Timer? _timer;
  int _lastProcessed = -1;
  DateTime _lastProgressAt = DateTime.now();
  static const int _noProgressLimitSeconds = 45;
  BatchState? batch;
  final List<RecentEntry> recent = [];
  String? lastMessage;
  Map<String, dynamic>? selftestResult;

  bool get isBusy => batch != null && !batch!.isDone;

  Future<void> load() async {
    final prefs = await SharedPreferences.getInstance();
    kdfPreset = KdfPreset.values[(prefs.getInt('kdf') ?? KdfPreset.desktop.index).clamp(0, 2)];
    perfMode = PerfMode.values[(prefs.getInt('perf') ?? PerfMode.balanced.index).clamp(0, 3)];
    customConcurrency = prefs.getInt('concurrency') ?? 4;
    overwriteOutput = prefs.getBool('overwrite') ?? false;
    deleteSource = prefs.getBool('delete_source') ?? false;
    backgroundRun = prefs.getBool('background_run') ?? true;
    darkMode = prefs.getBool('dark') ?? false;
    storageGranted = await AndroidStorage.hasAllFilesAccess();
    final raw = prefs.getStringList('recent') ?? const [];
    recent
      ..clear()
      ..addAll(
        raw
            .map((s) => RecentEntry.fromJson(Map<String, dynamic>.from((s.isEmpty ? {} : _decodeLoose(s)))))
            .where((e) => e.path.isNotEmpty),
      );
    notifyListeners();
  }

  /// Android：确保「所有文件访问权限」。返回是否可用（非 Android 恒 true）。
  Future<bool> ensureStorageAccess() async {
    if (!Platform.isAndroid) return true;
    if (storageGranted) return true;
    storageGranted = await AndroidStorage.requestAllFilesAccess();
    notifyListeners();
    return storageGranted;
  }

  /// 用户可能刚从系统设置页返回，需要重新读一次状态。
  Future<void> refreshStorageAccess() async {
    if (!Platform.isAndroid) return;
    final next = await AndroidStorage.hasAllFilesAccess();
    if (next != storageGranted) {
      storageGranted = next;
      notifyListeners();
    }
  }

  Map<String, dynamic> _decodeLoose(String s) {
    try {
      final v = jsonDecode(s);
      return v is Map ? Map<String, dynamic>.from(v) : <String, dynamic>{};
    } catch (_) {
      return <String, dynamic>{};
    }
  }

  Future<void> _persist() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setInt('kdf', kdfPreset.index);
      await prefs.setInt('perf', perfMode.index);
      await prefs.setInt('concurrency', customConcurrency);
      await prefs.setBool('overwrite', overwriteOutput);
      await prefs.setBool('delete_source', deleteSource);
      await prefs.setBool('background_run', backgroundRun);
      await prefs.setBool('dark', darkMode);
      await prefs.setStringList('recent', recent.map((e) => jsonEncode(e.toJson())).toList());
    } catch (_) {
      // 偏好写入失败不影响当前操作：这些设置只作为下次启动的默认值。
    }
  }

  void setKdfPreset(KdfPreset value) {
    kdfPreset = value;
    _persist();
    notifyListeners();
  }

  void setPerfMode(PerfMode value) {
    perfMode = value;
    _persist();
    notifyListeners();
  }

  void setCustomConcurrency(int value) {
    customConcurrency = value.clamp(1, 32);
    _persist();
    notifyListeners();
  }

  void setOverwrite(bool value) {
    overwriteOutput = value;
    _persist();
    notifyListeners();
  }

  void setDeleteSource(bool value) {
    deleteSource = value;
    _persist();
    notifyListeners();
  }

  void setBackgroundRun(bool value) {
    backgroundRun = value;
    _persist();
    notifyListeners();
  }

  void setDarkMode(bool value) {
    darkMode = value;
    _persist();
    notifyListeners();
  }

  void addRecent(RecentEntry entry) {
    recent.insert(0, entry);
    if (recent.length > 20) recent.removeRange(20, recent.length);
    _persist();
    notifyListeners();
  }

  void clearRecent() {
    recent.clear();
    _persist();
    notifyListeners();
  }

  /// 启动批量任务。`jobs` 为 (源路径, 目标路径, 字节数)。
  void startBatch({
    required bool decrypt,
    required String password,
    required List<({String source, String dest, int size})> jobs,
  }) {
    if (jobs.isEmpty) return;
    cancelBatch();
    _lastProcessed = -1;
    _lastProgressAt = DateTime.now();
    _handle?.dispose();
    final handle = _core.newBatch(
      decrypt: decrypt,
      perfMode: perfMode.code,
      concurrency: customConcurrency,
      overwrite: overwriteOutput,
      deleteSource: deleteSource,
      mCostKib: kdfPreset.mCostKib,
      tCost: kdfPreset.tCost,
      pCost: kdfPreset.pCost,
      password: password,
    );
    for (final job in jobs) {
      handle.add(source: job.source, dest: job.dest, size: job.size);
    }
    _handle = handle;
    assert(() {
      debugPrint('[batch] start decrypt=$decrypt jobs=${jobs.length}');
      return true;
    }());
    _batchStartedAt = DateTime.now();
    _notificationClosed = false;
    // 先把前台服务与通知拉起来，再开始干活：小文件批次只要几百毫秒，
    // 反过来的话通知还没发出任务就结束了，用户什么都看不到。
    if (backgroundRun && BackgroundTask.supported) {
      final title = decrypt ? '正在解密' : '正在加密';
      unawaited(
        BackgroundTask.start(title: title, text: '已完成 0/${jobs.length}').then((_) => handle.start()),
      );
    } else {
      handle.start();
    }
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(milliseconds: 250), (_) => _poll(decrypt: decrypt));
    _poll(decrypt: decrypt);
  }

  DateTime _lastNotifyAt = DateTime.fromMillisecondsSinceEpoch(0);
  DateTime? _batchStartedAt;
  bool _notificationClosed = false;

  /// 通知文案用的体量格式（与界面同一套进位，避免两处不一致）。
  static String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    const units = ['KiB', 'MiB', 'GiB', 'TiB'];
    var value = bytes / 1024;
    var unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return '${value.toStringAsFixed(1)} ${units[unit]}';
  }

  void _refreshNotification({required bool decrypt}) {
    final current = batch;
    if (current == null || !BackgroundTask.supported) return;
    if (!current.isDone) {
      final now = DateTime.now();
      if (now.difference(_lastNotifyAt).inMilliseconds < 2000) return;
      _lastNotifyAt = now;
      unawaited(
        BackgroundTask.update(
          title: decrypt ? '正在解密' : '正在加密',
          text: '已完成 ${current.finishedItems}/${current.totalItems} · ${_formatBytes(current.processedBytes)}',
        ),
      );
      return;
    }
    if (_notificationClosed) return;
    _notificationClosed = true;
    final action = decrypt ? '解密' : '加密';
    final failed = current.failedItems;
    final text = failed == 0
        ? '完成 · ${current.successItems} 个文件 · ${_formatBytes(current.processedBytes)}'
        : '完成 · 成功 ${current.successItems} 个，失败 $failed 个';
    unawaited(BackgroundTask.update(title: '$action完成', text: text));
    // 再快的批次也让通知至少可见一会儿，否则用户以为没有后台任务。
    final elapsed = DateTime.now().difference(_batchStartedAt ?? DateTime.now());
    final wait = const Duration(milliseconds: 4000) - elapsed;
    Future<void>.delayed(wait.isNegative ? Duration.zero : wait, () {
      if (_notificationClosed) unawaited(BackgroundTask.stop());
    });
  }

  void _poll({required bool decrypt}) {
    final handle = _handle;
    if (handle == null) return;
    try {
      final summary = handle.summary();
      final items = handle.snapshot().map(TaskItem.fromMap).toList();
      final processed = (summary['processed_bytes'] as num?)?.toInt() ?? 0;
      if (processed != _lastProcessed) {
        _lastProcessed = processed;
        _lastProgressAt = DateTime.now();
      }
      batch = BatchState(
        decrypt: decrypt,
        items: items,
        totalItems: (summary['total_items'] as num?)?.toInt() ?? items.length,
        finishedItems: (summary['finished_items'] as num?)?.toInt() ?? 0,
        successItems: (summary['success_items'] as num?)?.toInt() ?? 0,
        failedItems: (summary['failed_items'] as num?)?.toInt() ?? 0,
        cancelledItems: (summary['cancelled_items'] as num?)?.toInt() ?? 0,
        totalBytes: (summary['total_bytes'] as num?)?.toInt() ?? 0,
        processedBytes: processed,
        elapsedMs: (summary['elapsed_ms'] as num?)?.toInt() ?? 0,
        speedBps: (summary['speed_bps'] as num?)?.toInt() ?? 0,
        isDone: summary['is_done'] == true,
        isPaused: summary['is_paused'] == true,
        concurrency: (summary['concurrency'] as num?)?.toInt() ?? 1,
      );
      if (batch!.isDone) {
        _timer?.cancel();
        _timer = null;
        for (final item in items.where((i) => i.status == 'success' || i.status == 'failed')) {
          addRecent(
            RecentEntry(
              path: decrypt ? item.dest : item.source,
              action: decrypt ? 'decrypt' : 'encrypt',
              status: item.status,
              timeMs: DateTime.now().millisecondsSinceEpoch,
            ),
          );
        }
        // 整批都失败时把第一条错误抬到顶部，避免用户只看到「已完成」却不知为何没有产物。
        if (batch!.successItems == 0 && batch!.failedItems > 0) {
          final firstError = items.firstWhere(
            (i) => i.status == 'failed',
            orElse: () => TaskItem(
              id: 0,
              source: '',
              dest: '',
              size: 0,
              processed: 0,
              status: 'failed',
            ),
          );
          batch = batch!.copyWith(
            note: '全部失败：${firstError.errorMessage ?? firstError.errorCode ?? '未知原因'}',
          );
        }
      } else if (!batch!.isPaused &&
          DateTime.now().difference(_lastProgressAt).inSeconds >= _noProgressLimitSeconds) {
        // 引擎长时间没有任何字节推进：主动取消并说明原因，
        // 避免界面永远停在「任务进行中」且按钮被一直禁用。
        _handle?.cancel();
        _timer?.cancel();
        _timer = null;
        batch = batch!.copyWith(
          isDone: true,
          note: '$_noProgressLimitSeconds 秒无进度，已自动停止。常见原因：输出目录不可写、'
              '文件被其他应用占用，或密码派生内存不足。',
        );
      }
    } catch (e) {
      _timer?.cancel();
      _timer = null;
      batch = (batch ?? BatchState(
        decrypt: decrypt,
        items: const [],
        totalItems: 0,
        finishedItems: 0,
        successItems: 0,
        failedItems: 0,
        cancelledItems: 0,
        totalBytes: 0,
        processedBytes: 0,
        elapsedMs: 0,
        speedBps: 0,
        isDone: true,
        isPaused: false,
        concurrency: 1,
      )).copyWith(isDone: true, note: '任务状态读取失败：$e');
    }
    assert(() {
      debugPrint('[batch] poll done=${batch?.isDone} ok=${batch?.successItems} '
          'fail=${batch?.failedItems} note=${batch?.note}');
      return true;
    }());
    _refreshNotification(decrypt: decrypt);
    notifyListeners();
  }

  void pauseBatch() {
    _handle?.pause();
    notifyListeners();
  }

  void resumeBatch() {
    _handle?.resume();
    notifyListeners();
  }

  void cancelBatch() {
    _handle?.cancel();
    _timer?.cancel();
    _timer = null;
    // 取消后必须把状态收敛成「已完成」，否则 isBusy 永远为真、按钮永久禁用。
    batch = batch?.copyWith(isDone: true, note: '已取消');
    _notificationClosed = true;
    unawaited(BackgroundTask.stop());
    notifyListeners();
  }

  void clearBatch() {
    _handle?.dispose();
    _handle = null;
    batch = null;
    notifyListeners();
  }

  Map<String, dynamic> inspect(String path) => _core.inspect(path);

  Map<String, dynamic> verify(String path, String password) => _core.verify(input: path, password: password);

  /// 校验与预览解密都放到子 isolate，避免阻塞 UI（FFI 句柄不可跨 isolate，内部已重新打开库）。
  Future<Map<String, dynamic>> verifyOffThread(String path, String password) =>
      _core.verifyOffThread(input: path, password: password);

  Future<Map<String, dynamic>> inspectOffThread(String path) => _core.inspectOffThread(path);

  Future<Map<String, dynamic>> decryptOffThread({
    required String input,
    required String output,
    required String password,
    bool overwrite = false,
  }) => _core.decryptOffThread(input: input, output: output, password: password, overwrite: overwrite);

  int passwordStrength(String password) => password.isEmpty ? 0 : _core.passwordStrength(password);

  Map<String, dynamic> scan(List<String> paths, {bool safefileOnly = false}) =>
      _core.scan(paths, safefileOnly: safefileOnly);

  void runSelftest() {
    selftestResult = _core.selftest();
    notifyListeners();
  }

  @override
  void dispose() {
    unawaited(BackgroundTask.stop());
    _timer?.cancel();
    _handle?.dispose();
    super.dispose();
  }
}
