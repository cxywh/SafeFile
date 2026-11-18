import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:safefile/core/native_core.dart';

/// 这些测试直接调用 Rust 加密核心（与界面走完全相同的 dart:ffi 路径），
/// 用来验证跨语言桥本身：符号查找、参数编组、JSON 回传、批量句柄生命周期。
void main() {
  late Directory work;

  setUpAll(() {
    work = Directory.systemTemp.createTempSync('safefile-ffi-test-');
  });

  tearDownAll(() {
    if (work.existsSync()) work.deleteSync(recursive: true);
  });

  test('核心版本可读取', () {
    final v = NativeCore.instance.version();
    expect(v['ok'], isTrue);
    expect(v['format'], 1);
  });

  test('设备端自检全部通过', () {
    final r = NativeCore.instance.selftest();
    expect(r['ok'], isTrue);
    expect(r['all_pass'], isTrue, reason: '自检未通过：${r['checks']}');
    final checks = (r['checks'] as List).cast<Map>();
    expect(checks.length, greaterThanOrEqualTo(5));
    for (final c in checks) {
      expect(c['pass'], isTrue, reason: '${c['name']}: ${c['detail']}');
    }
  });

  test('单文件加密解密往返（含 Unicode 文件名）', () {
    final input = File('${work.path}/报告 A.bin');
    final payload = List<int>.generate(200 * 1024, (i) => i % 251);
    input.writeAsBytesSync(payload);
    final container = '${work.path}/报告 A.bin.safefile';
    final outDir = Directory('${work.path}/out')..createSync();

    final enc = NativeCore.instance.encrypt(
      input: input.path,
      output: container,
      password: '桥接测试-密码-2024',
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
      chunkSize: 65536,
    );
    expect(enc['ok'], isTrue, reason: '${enc['message']}');
    expect(enc['plaintext_size'], payload.length);
    expect(File(container).existsSync(), isTrue);

    final info = NativeCore.instance.inspect(container);
    expect(info['ok'], isTrue);
    expect(info['version'], 1);
    expect(info['chunk_size'], 65536);

    final dec = NativeCore.instance.decrypt(
      input: container,
      output: outDir.path,
      password: '桥接测试-密码-2024',
    );
    expect(dec['ok'], isTrue, reason: '${dec['message']}');
    final restored = File(dec['output'] as String);
    expect(restored.existsSync(), isTrue);
    expect(restored.readAsBytesSync(), payload);
    expect(restored.uri.pathSegments.last, '报告 A.bin');
  });

  test('错误密码返回 auth_failed 且不留下输出', () {
    final input = File('${work.path}/pw.bin')..writeAsBytesSync([1, 2, 3, 4, 5]);
    final container = '${work.path}/pw.bin.safefile';
    NativeCore.instance.encrypt(
      input: input.path,
      output: container,
      password: 'right',
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
    );
    final outDir = Directory('${work.path}/pw-out')..createSync();
    final dec = NativeCore.instance.decrypt(input: container, output: outDir.path, password: 'wrong');
    expect(dec['ok'], isFalse);
    expect(dec['code'], 'auth_failed');
    expect(outDir.listSync(), isEmpty);

    final verify = NativeCore.instance.verify(input: container, password: 'right');
    expect(verify['ok'], isTrue);
    expect((verify['metadata'] as Map)['original_size'], 5);
  });

  test('批量引擎：快照与汇总可用，全部成功', () {
    final sources = <String>[];
    for (var i = 0; i < 6; i++) {
      final f = File('${work.path}/batch-$i.bin')
        ..writeAsBytesSync(List<int>.generate(1000 + i * 500, (j) => (i + j) % 256));
      sources.add(f.path);
    }
    final encDir = Directory('${work.path}/batch-enc')..createSync();
    final handle = NativeCore.instance.newBatch(
      decrypt: false,
      perfMode: 2,
      concurrency: 4,
      overwrite: false,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
      password: 'batch-bridge',
    );
    addTearDown(handle.dispose);
    for (final s in sources) {
      handle.add(
        source: s,
        dest: '${encDir.path}/${s.split(RegExp(r'[\\/]')).last}.safefile',
        size: File(s).lengthSync(),
      );
    }
    handle.start();

    var summary = handle.summary();
    for (var i = 0; i < 100 && summary['is_done'] != true; i++) {
      sleep(const Duration(milliseconds: 100));
      summary = handle.summary();
    }
    expect(summary['is_done'], isTrue);
    expect(summary['success_items'], 6);
    expect(summary['failed_items'], 0);
    expect(handle.snapshot().length, 6);
    expect(encDir.listSync().length, 6);
  });

  // 回归：校验/预览解密必须放到子 isolate 且能真正返回。
  // 曾经的 bug 是把闭包连同 NativeCore（DynamicLibrary + 函数指针）塞进 Isolate.run，
  // 参数不可传递 → Future 永不完成，界面卡在「校验中…」。
  test('verifyOffThread 在子 isolate 内完成校验（正确密码）', () async {
    final input = File('${work.path}/isolate-a.bin');
    input.writeAsBytesSync(List<int>.generate(64 * 1024, (i) => i % 97));
    final container = '${work.path}/isolate-a.bin.safefile';
    final enc = NativeCore.instance.encrypt(
      input: input.path,
      output: container,
      password: 'isolate-pw-1',
      overwrite: true,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
    );
    expect(enc['ok'], isTrue, reason: '${enc['message']}');

    final r = await NativeCore.instance
        .verifyOffThread(input: container, password: 'isolate-pw-1')
        .timeout(const Duration(seconds: 30));
    expect(r['ok'], isTrue, reason: '${r['message']}');
    expect((r['metadata'] as Map?)?['filename'], 'isolate-a.bin');
  });

  test('verifyOffThread 错误密码返回失败而不是挂起', () async {
    final container = '${work.path}/isolate-a.bin.safefile';
    final r = await NativeCore.instance
        .verifyOffThread(input: container, password: 'wrong-pw')
        .timeout(const Duration(seconds: 30));
    expect(r['ok'], isFalse);
    expect(r['code'], 'auth_failed');
  });

  test('inspectOffThread 可读公开头且不阻塞', () async {
    final container = '${work.path}/isolate-a.bin.safefile';
    final r = await NativeCore.instance.inspectOffThread(container).timeout(const Duration(seconds: 30));
    expect(r['ok'], isTrue);
    expect(r['version'], 1);
  });
}
