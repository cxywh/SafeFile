import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

/// 跨 isolate 入口：只接收可传递的基本类型。
///
/// `Isolate.run` 的闭包只能捕获可跨 isolate 传递的对象，而 `NativeCore` 持有
/// `DynamicLibrary` 与函数指针，传不过去（传了会抛 unsendable，Future 永远不完成，
/// 界面就卡在「校验中…」）。因此入口只收字符串/布尔，在子 isolate 内重新打开动态库。
@pragma('vm:entry-point')
Map<String, dynamic> _isolateVerify(Map<String, String> args) =>
    NativeCore.instance.verify(input: args['input']!, password: args['password']!);

@pragma('vm:entry-point')
Map<String, dynamic> _isolateInspect(String path) => NativeCore.instance.inspect(path);

@pragma('vm:entry-point')
Map<String, dynamic> _isolateDecrypt(Map<String, Object?> args) => NativeCore.instance.decrypt(
  input: args['input']! as String,
  output: args['output']! as String,
  password: args['password']! as String,
  overwrite: args['overwrite'] == true,
  deleteSource: args['delete_source'] == true,
);

@pragma('vm:entry-point')
Map<String, dynamic> _isolatePreview(Map<String, String> args) =>
    NativeCore.instance.preview(args['path']!, args['kind'] ?? '');

@pragma('vm:entry-point')
Map<String, dynamic> _isolatePreviewMem(Map<String, String> args) =>
    NativeCore.instance.previewMem(args['container']!, args['password']!);

@pragma('vm:entry-point')
Map<String, dynamic> _isolateMediaOpen(Map<String, String> args) =>
    NativeCore.instance.mediaOpen(args['container']!, args['password']!);

/// Rust 加密核心的 dart:ffi 绑定。
///
/// 所有密码学操作都在 Rust 侧完成，这里只做参数编组与 JSON 解析。
/// 统一的 JSON 约定：成功时 `ok = true`，失败时带 `code` 与 `message`（不含敏感信息）。
class NativeCore {
  NativeCore._(this._lib);

  final DynamicLibrary _lib;

  static NativeCore? _instance;
  static NativeCore get instance => _instance ??= NativeCore._(DynamicLibrary.open(_libraryPath()));

  static String _libraryPath() {
    if (Platform.isWindows) {
      return 'safefile_ffi.dll';
    }
    if (Platform.isAndroid || Platform.isLinux) {
      return 'libsafefile_ffi.so';
    }
    throw UnsupportedError('暂不支持该平台');
  }

  // ---- 低层函数指针
  late final Pointer<Utf8> Function() _version =
      _lib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('sf_version');
  late final Pointer<Utf8> Function() _selftest =
      _lib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('sf_selftest');
  late final void Function(Pointer<Utf8>) _free = _lib
      .lookupFunction<Void Function(Pointer<Utf8>), void Function(Pointer<Utf8>)>('sf_free_string');
  late final int Function(Pointer<Utf8>) _strength =
      _lib.lookupFunction<Int32 Function(Pointer<Utf8>), int Function(Pointer<Utf8>)>('sf_password_strength');
  late final Pointer<Utf8> Function(Pointer<Utf8>) _inspect =
      _lib.lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>), Pointer<Utf8> Function(Pointer<Utf8>)>('sf_inspect');
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, int, int) _decrypt = _lib
      .lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Uint8, Uint8),
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, int, int)
      >('sf_decrypt');
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, int, int, int, int, int, int)
      _encrypt = _lib.lookupFunction<
        Pointer<Utf8> Function(
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Uint32,
          Uint32,
          Uint32,
          Uint32,
          Uint8,
          Uint8,
        ),
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, int, int, int, int, int, int)
      >('sf_encrypt');
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _verify = _lib.lookupFunction<
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)
  >('sf_verify');
  late final Pointer<Utf8> Function(Pointer<Utf8>, int) _scan = _lib.lookupFunction<
    Pointer<Utf8> Function(Pointer<Utf8>, Uint8),
    Pointer<Utf8> Function(Pointer<Utf8>, int)
  >('sf_scan');
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _preview = _lib.lookupFunction<
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)
  >('sf_preview');

  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _previewMem = _lib.lookupFunction<
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)
  >('sf_preview_mem');
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _mediaOpen = _lib.lookupFunction<
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)
  >('sf_media_open');
  late final Pointer<Utf8> Function(Pointer<Utf8>) _mediaClose = _lib.lookupFunction<
    Pointer<Utf8> Function(Pointer<Utf8>),
    Pointer<Utf8> Function(Pointer<Utf8>)
  >('sf_media_close');

  // 批量引擎
  late final Pointer<Void> Function(int, int, int, int, int, int, int, int, int, Pointer<Utf8>) _batchNew = _lib
      .lookupFunction<
        Pointer<Void> Function(
          Uint8,
          Uint8,
          Uint32,
          Uint8,
          Uint8,
          Uint32,
          Uint32,
          Uint32,
          Uint32,
          Pointer<Utf8>,
        ),
        Pointer<Void> Function(int, int, int, int, int, int, int, int, int, Pointer<Utf8>)
      >('sf_batch_new');
  late final int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, int) _batchAdd = _lib.lookupFunction<
    Uint64 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Uint64),
    int Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, int)
  >('sf_batch_add');
  late final int Function(Pointer<Void>) _batchStart =
      _lib.lookupFunction<Int32 Function(Pointer<Void>), int Function(Pointer<Void>)>('sf_batch_start');
  late final Pointer<Utf8> Function(Pointer<Void>) _batchSnapshot =
      _lib.lookupFunction<Pointer<Utf8> Function(Pointer<Void>), Pointer<Utf8> Function(Pointer<Void>)>(
        'sf_batch_snapshot',
      );
  late final Pointer<Utf8> Function(Pointer<Void>) _batchSummary =
      _lib.lookupFunction<Pointer<Utf8> Function(Pointer<Void>), Pointer<Utf8> Function(Pointer<Void>)>(
        'sf_batch_summary',
      );
  late final void Function(Pointer<Void>) _batchPause =
      _lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>('sf_batch_pause');
  late final void Function(Pointer<Void>) _batchResume =
      _lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>('sf_batch_resume');
  late final void Function(Pointer<Void>) _batchCancel =
      _lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>('sf_batch_cancel');
  late final void Function(Pointer<Void>) _batchFree =
      _lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>('sf_batch_free');

  String _takeString(Pointer<Utf8> p) {
    if (p == nullptr) return '{"ok":false,"code":"internal","message":"空指针"}';
    try {
      return p.toDartString();
    } finally {
      _free(p);
    }
  }

  Map<String, dynamic> _decode(String json) {
    final value = jsonDecode(json);
    return value is Map<String, dynamic> ? value : <String, dynamic>{'ok': false, 'message': '解析失败'};
  }

  /// 核心与格式版本。
  Map<String, dynamic> version() => _decode(_takeString(_version()));

  /// 设备端自检。
  Map<String, dynamic> selftest() => _decode(_takeString(_selftest()));

  /// 密码强度 0..4。
  int passwordStrength(String password) {
    final p = password.toNativeUtf8();
    try {
      return _strength(p);
    } finally {
      malloc.free(p);
    }
  }

  Map<String, dynamic> inspect(String path) {
    final p = path.toNativeUtf8();
    try {
      return _decode(_takeString(_inspect(p)));
    } finally {
      malloc.free(p);
    }
  }

  Map<String, dynamic> encrypt({
    required String input,
    required String output,
    required String password,
    required int mCostKib,
    required int tCost,
    required int pCost,
    int chunkSize = 65536,
    bool overwrite = false,
    bool deleteSource = false,
  }) {
    final i = input.toNativeUtf8();
    final o = output.toNativeUtf8();
    final pw = password.toNativeUtf8();
    try {
      return _decode(
        _takeString(
          _encrypt(i, o, pw, mCostKib, tCost, pCost, chunkSize, overwrite ? 1 : 0, deleteSource ? 1 : 0),
        ),
      );
    } finally {
      malloc.free(i);
      malloc.free(o);
      malloc.free(pw);
    }
  }

  Map<String, dynamic> decrypt({
    required String input,
    required String output,
    required String password,
    bool overwrite = false,
    bool deleteSource = false,
  }) {
    final i = input.toNativeUtf8();
    final o = output.toNativeUtf8();
    final pw = password.toNativeUtf8();
    try {
      return _decode(_takeString(_decrypt(i, o, pw, overwrite ? 1 : 0, deleteSource ? 1 : 0)));
    } finally {
      malloc.free(i);
      malloc.free(o);
      malloc.free(pw);
    }
  }

  Map<String, dynamic> verify({required String input, required String password}) {
    final i = input.toNativeUtf8();
    final pw = password.toNativeUtf8();
    try {
      return _decode(_takeString(_verify(i, pw)));
    } finally {
      malloc.free(i);
      malloc.free(pw);
    }
  }

  /// 在独立 isolate 里校验容器：UI 不冻结，也不会因密码错误卡住。
  Future<Map<String, dynamic>> verifyOffThread({required String input, required String password}) =>
      Isolate.run(() => _isolateVerify({'input': input, 'password': password}));

  Future<Map<String, dynamic>> inspectOffThread(String path) => Isolate.run(() => _isolateInspect(path));

  Future<Map<String, dynamic>> decryptOffThread({
    required String input,
    required String output,
    required String password,
    bool overwrite = false,
    bool deleteSource = false,
  }) => Isolate.run(
    () => _isolateDecrypt({
      'input': input,
      'output': output,
      'password': password,
      'overwrite': overwrite,
      'delete_source': deleteSource,
    }),
  );

  /// 安全预览：解析已解密的明文文件，返回受限的结构化内容。
  ///
  /// 这是同步 FFI 调用，UI 侧请用 [previewOffThread] 以免阻塞帧。
  Map<String, dynamic> preview(String path, String kind) {
    final p = path.toNativeUtf8();
    final k = kind.toNativeUtf8();
    try {
      return _decode(_takeString(_preview(p, k)));
    } finally {
      malloc.free(p);
      malloc.free(k);
    }
  }

  /// 在独立 isolate 里解析预览，避免大文档卡住界面。
  Future<Map<String, dynamic>> previewOffThread({required String path, String kind = ''}) =>
      Isolate.run(() => _isolatePreview({'path': path, 'kind': kind}));
  /// 纯内存预览：解密与解析都不落盘。
  Map<String, dynamic> previewMem(String container, String password) {
    final c = container.toNativeUtf8();
    final p = password.toNativeUtf8();
    try {
      return _decode(_takeString(_previewMem(c, p)));
    } finally {
      malloc.free(c);
      malloc.free(p);
    }
  }

  Future<Map<String, dynamic>> previewMemOffThread({
    required String container,
    required String password,
  }) => Isolate.run(() => _isolatePreviewMem({'container': container, 'password': password}));

  /// 为音视频起一个只读的回环令牌端点；用完必须 [mediaClose]。
  Map<String, dynamic> mediaOpen(String container, String password) {
    final c = container.toNativeUtf8();
    final p = password.toNativeUtf8();
    try {
      return _decode(_takeString(_mediaOpen(c, p)));
    } finally {
      malloc.free(c);
      malloc.free(p);
    }
  }

  Future<Map<String, dynamic>> mediaOpenOffThread({
    required String container,
    required String password,
  }) => Isolate.run(() => _isolateMediaOpen({'container': container, 'password': password}));

  void mediaClose(String id) {
    final p = id.toNativeUtf8();
    try {
      _takeString(_mediaClose(p));
    } finally {
      malloc.free(p);
    }
  }

  Map<String, dynamic> scan(List<String> paths, {bool safefileOnly = false}) {
    final p = jsonEncode(paths).toNativeUtf8();
    try {
      return _decode(_takeString(_scan(p, safefileOnly ? 1 : 0)));
    } finally {
      malloc.free(p);
    }
  }

  BatchHandle newBatch({
    required bool decrypt,
    required int perfMode,
    required int concurrency,
    required bool overwrite,
    bool deleteSource = false,
    required int mCostKib,
    required int tCost,
    required int pCost,
    required String password,
    int chunkSize = 65536,
  }) {
    final pw = password.toNativeUtf8();
    try {
      final handle = _batchNew(
        decrypt ? 1 : 0,
        perfMode,
        concurrency,
        overwrite ? 1 : 0,
        deleteSource ? 1 : 0,
        mCostKib,
        tCost,
        pCost,
        chunkSize,
        pw,
      );
      return BatchHandle._(this, handle);
    } finally {
      malloc.free(pw);
    }
  }

  // 供 BatchHandle 调用
  int _add(Pointer<Void> h, String src, String dest, int size) {
    final s = src.toNativeUtf8();
    final d = dest.toNativeUtf8();
    try {
      return _batchAdd(h, s, d, size);
    } finally {
      malloc.free(s);
      malloc.free(d);
    }
  }
}

/// 批量任务句柄。必须调用 [dispose] 释放 Rust 侧内存。
class BatchHandle {
  BatchHandle._(this._core, this._ptr);

  final NativeCore _core;
  Pointer<Void> _ptr;
  bool _disposed = false;

  bool get isValid => !_disposed && _ptr != nullptr;

  int add({required String source, required String dest, required int size}) {
    if (!isValid) return 0;
    return _core._add(_ptr, source, dest, size);
  }

  void start() {
    if (isValid) _core._batchStart(_ptr);
  }

  void pause() {
    if (isValid) _core._batchPause(_ptr);
  }

  void resume() {
    if (isValid) _core._batchResume(_ptr);
  }

  void cancel() {
    if (isValid) _core._batchCancel(_ptr);
  }

  List<Map<String, dynamic>> snapshot() {
    if (!isValid) return const [];
    final json = _core._takeString(_core._batchSnapshot(_ptr));
    final list = jsonDecode(json);
    if (list is List) {
      return list.map((e) => Map<String, dynamic>.from(e as Map)).toList();
    }
    return const [];
  }

  Map<String, dynamic> summary() {
    if (!isValid) return const {'ok': false};
    return _core._decode(_core._takeString(_core._batchSummary(_ptr)));
  }

  void dispose() {
    if (!_disposed && _ptr != nullptr) {
      _core._batchFree(_ptr);
      _ptr = nullptr;
      _disposed = true;
    }
  }
}
