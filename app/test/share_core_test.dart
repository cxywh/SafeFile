import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:safefile/core/share_core.dart';

/// 局域网共享的 FFI 冒烟测试（Windows 下加载 safefile_ffi.dll）。
///
/// 只验证「Dart 与 Rust 的 ABI 对上了」：身份加载、监听端口、
/// 回环发送能真正落到磁盘、错误地址会及时报错。跨设备传输在真机集成测试做。
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  Directory? root;

  setUpAll(() async {
    root = Directory.systemTemp.createTempSync('sfshare-');
    await initLan(root!.path);
  });

  tearDownAll(() {
    try {
      root?.deleteSync(recursive: true);
    } catch (_) {}
  });

  test('动态库加载并探测本机地址', () async {
    expect(shareAvailable(), isTrue);
    final addrs = await localAddrs();
    expect(addrs, isA<List<String>>());
  });

  test('本机身份稳定：同一设备始终同一个名字', () async {
    final a = await lanStatus();
    final b = await lanStatus();
    final c = await lanIdentity();
    expect(a, isNotNull);
    expect(a!.id, isNotEmpty);
    expect(a.name, isNotEmpty);
    expect(a.fingerprint, isNotEmpty);
    expect(b!.name, a.name, reason: '名字应由持久身份派生，不能每次变');
    expect(b.id, a.id);
    expect(c!.id, a.id);
    expect(c.name, a.name);
  });

  test('启动接收端会给出端口与设备名', () {
    final dir = Directory.systemTemp.createTempSync('sfshare-listen-');
    final listener = ShareListener.start(dir.path, overwrite: true);
    try {
      expect(listener, isNotNull);
      final session = listener!.session;
      expect(session.name, isNotEmpty);
      expect(session.id, isNotEmpty);
      expect(session.port, greaterThan(0));
      final progress = listener.poll();
      expect(progress.sessions, 0);
      expect(progress.error, isNull);
    } finally {
      listener?.stop();
      try {
        dir.deleteSync(recursive: true);
      } catch (_) {}
    }
  });

  test('停止后端口可再次绑定（不会残留监听）', () {
    final dir = Directory.systemTemp.createTempSync('sfshare-rebind-');
    final first = ShareListener.start(dir.path);
    expect(first, isNotNull);
    final port = first!.session.port;
    first.stop();

    final second = ShareListener.start(dir.path, port: port);
    expect(second, isNotNull, reason: '同一端口应能重新绑定');
    second!.stop();
    try {
      dir.deleteSync(recursive: true);
    } catch (_) {}
  });

  test('回环发送：加密会话、安全码、文件落盘', () async {
    final dir = Directory.systemTemp.createTempSync('sfshare-send-');
    final save = Directory('${dir.path}${Platform.pathSeparator}inbox')..createSync();
    final listener = ShareListener.start(save.path, overwrite: true);
    expect(listener, isNotNull);
    final src = File('${dir.path}${Platform.pathSeparator}payload.txt')
      ..writeAsStringSync('lan payload v2');

    final sender = ShareSender.start('127.0.0.1:${listener!.session.port}', [src.path]);
    expect(sender, isNotNull);

    ShareProgress progress = const ShareProgress();
    for (var i = 0; i < 100; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
      progress = sender!.poll();
      if (progress.finished) break;
    }
    expect(progress.finished, isTrue, reason: '发送应在超时内结束');
    expect(progress.error, isNull, reason: '回环传输不该失败：${progress.error}');
    expect(progress.encrypted, isTrue);
    expect(progress.sas.length, 6);
    expect(progress.peer, isNotEmpty);

    final got = File('${save.path}${Platform.pathSeparator}payload.txt');
    expect(got.existsSync(), isTrue);
    expect(got.readAsStringSync(), 'lan payload v2');

    sender!.free();
    listener.stop();
    try {
      dir.deleteSync(recursive: true);
    } catch (_) {}
  });

  test('连不上时发送端报错而不是挂住', () async {
    final dir = Directory.systemTemp.createTempSync('sfshare-fail-');
    final src = File('${dir.path}${Platform.pathSeparator}payload.txt')
      ..writeAsStringSync('x');
    final sender = ShareSender.start('127.0.0.1:1', [src.path]);
    expect(sender, isNotNull);

    ShareProgress progress = const ShareProgress();
    for (var i = 0; i < 100; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
      progress = sender!.poll();
      if (progress.finished) break;
    }
    expect(progress.finished, isTrue, reason: '不该无限等待');
    expect(progress.error, isNotNull);

    sender!.free();
    try {
      dir.deleteSync(recursive: true);
    } catch (_) {}
  });
}
