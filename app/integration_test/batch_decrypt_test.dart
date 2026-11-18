import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:safefile/core/android_storage.dart';
import 'package:safefile/core/background_task.dart';
import 'package:safefile/core/native_core.dart';

/// 真机/模拟器上的端到端验证：直接调用与界面完全相同的 FFI 接口，
/// 不经过文件选择器，用来定位「批量解密一直进行中」这类只在设备上出现的挂起。
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('设备上批量解密能结束', (tester) async {
    final root = await Directory.systemTemp.createTemp('sf-batch-dec-');
    final src = File('${root.path}/payload.bin');
    src.writeAsBytesSync(List<int>.generate(256 * 1024, (i) => i % 211));
    final container = '${root.path}/payload.bin.safefile';
    final outDir = Directory('${root.path}/out')..createSync(recursive: true);

    final enc = NativeCore.instance.encrypt(
      input: src.path,
      output: container,
      password: 'device-batch-pw',
      overwrite: true,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
    );
    expect(enc['ok'], isTrue, reason: '加密失败：${enc['message']}');
    // ignore: avoid_print
    print('ENC_OK size=${File(container).lengthSync()}');

    // 单文件同步解密对照
    final syncDir = Directory('${root.path}/sync')..createSync(recursive: true);
    final syncOut = NativeCore.instance.decrypt(
      input: container,
      output: syncDir.path,
      password: 'device-batch-pw',
      overwrite: true,
    );
    // ignore: avoid_print
    print('SYNC_DECRYPT ok=${syncOut['ok']} out=${syncOut['output']} msg=${syncOut['message']}');
    expect(syncOut['ok'], isTrue, reason: '同步解密失败：${syncOut['message']}');

    // 批量解密（界面走的就是这条）
    final handle = NativeCore.instance.newBatch(
      decrypt: true,
      perfMode: 1,
      concurrency: 2,
      overwrite: false,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
      password: 'device-batch-pw',
    );
    addTearDown(handle.dispose);
    handle.add(source: container, dest: outDir.path, size: File(container).lengthSync());
    handle.start();

    var summary = handle.summary();
    final started = DateTime.now();
    while (summary['is_done'] != true && DateTime.now().difference(started).inSeconds < 60) {
      await Future<void>.delayed(const Duration(milliseconds: 250));
      summary = handle.summary();
    }
    // ignore: avoid_print
    print('BATCH summary=$summary');
    // ignore: avoid_print
    print('BATCH items=${handle.snapshot()}');
    // ignore: avoid_print
    print('BATCH outDir=${outDir.listSync().map((e) => e.path).toList()}');

    expect(summary['is_done'], isTrue, reason: '批量解密 60s 未结束，summary=$summary');
    expect(summary['failed_items'], 0, reason: '有失败项：${handle.snapshot()}');
    expect(outDir.listSync().whereType<File>().length, 1);
  }, timeout: const Timeout(Duration(minutes: 3)));

  // 复现探针：界面默认输出目录是 /storage/emulated/0/SafeFile（FUSE 模拟存储），
  // 与私有目录行为差异极大。这两个用例用来判定挂起是否只发生在公开目录。
  testWidgets('公开目录（/sdcard）批量解密能结束', (tester) async {
    final root = await Directory.systemTemp.createTemp('sf-pub-');
    final src = File('${root.path}/p.bin');
    src.writeAsBytesSync(List<int>.generate(192 * 1024, (i) => i % 193));
    final container = '${root.path}/p.bin.safefile';
    final enc = NativeCore.instance.encrypt(
      input: src.path,
      output: container,
      password: 'pub-pw',
      overwrite: true,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
    );
    expect(enc['ok'], isTrue, reason: '${enc['message']}');

    final publicDir = Directory('/storage/emulated/0/SafeFile');
    if (!publicDir.existsSync()) publicDir.createSync(recursive: true);
    // 该用例要求「所有文件访问权限」；测试包每次重装都会重置 appops，
    // 未授权时按跳过处理，避免把环境问题当成代码缺陷。
    if (!await AndroidStorage.hasAllFilesAccess()) {
      // ignore: avoid_print
      print('PUB skipped: MANAGE_EXTERNAL_STORAGE 未授权');
      return;
    }
    // ignore: avoid_print
    print('PUB dir writable=${publicDir.existsSync()} items=${publicDir.listSync().length}');

    final handle = NativeCore.instance.newBatch(
      decrypt: true,
      perfMode: 1,
      concurrency: 2,
      overwrite: true,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
      password: 'pub-pw',
    );
    addTearDown(handle.dispose);
    handle.add(source: container, dest: publicDir.path, size: File(container).lengthSync());
    handle.start();

    var summary = handle.summary();
    final started = DateTime.now();
    while (summary['is_done'] != true && DateTime.now().difference(started).inSeconds < 45) {
      await Future<void>.delayed(const Duration(milliseconds: 250));
      summary = handle.summary();
    }
    // ignore: avoid_print
    print('PUB summary=$summary');
    // ignore: avoid_print
    print('PUB items=${handle.snapshot()}');
    expect(summary['is_done'], isTrue, reason: '公开目录批量解密 45s 未结束，summary=$summary');
    expect(Directory(publicDir.path).listSync().whereType<File>().isEmpty, isFalse);
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets('公开目录（/sdcard）批量加密能结束', (tester) async {
    final root = await Directory.systemTemp.createTemp('sf-pub-enc-');
    final src = File('${root.path}/q.bin');
    src.writeAsBytesSync(List<int>.generate(192 * 1024, (i) => i % 197));
    final publicDir = Directory('/storage/emulated/0/SafeFile');
    if (!publicDir.existsSync()) publicDir.createSync(recursive: true);
    // 该用例要求「所有文件访问权限」；测试包每次重装都会重置 appops，
    // 未授权时按跳过处理，避免把环境问题当成代码缺陷。
    if (!await AndroidStorage.hasAllFilesAccess()) {
      // ignore: avoid_print
      print('PUB skipped: MANAGE_EXTERNAL_STORAGE 未授权');
      return;
    }

    final handle = NativeCore.instance.newBatch(
      decrypt: false,
      perfMode: 1,
      concurrency: 2,
      overwrite: true,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
      password: 'pub-pw',
    );
    addTearDown(handle.dispose);
    handle.add(source: src.path, dest: publicDir.path, size: src.lengthSync());
    handle.start();

    var summary = handle.summary();
    final started = DateTime.now();
    while (summary['is_done'] != true && DateTime.now().difference(started).inSeconds < 45) {
      await Future<void>.delayed(const Duration(milliseconds: 250));
      summary = handle.summary();
    }
    // ignore: avoid_print
    print('PUBENC summary=$summary');
    expect(summary['is_done'], isTrue, reason: '公开目录批量加密 45s 未结束：$summary');
  }, timeout: const Timeout(Duration(minutes: 3)));

  // 复现探针：目标文件已存在且 overwrite=false 时，引擎必须报错而不是卡住。
  // 用户场景：先解密成功过一次（文件已在输出目录），再次解密同一容器。
  testWidgets('目标已存在且不覆盖时能快速结束', (tester) async {
    final root = await Directory.systemTemp.createTemp('sf-exists-');
    final src = File('${root.path}/e.bin');
    src.writeAsBytesSync(List<int>.generate(96 * 1024, (i) => i % 181));
    final container = '${root.path}/e.bin.safefile';
    final enc = NativeCore.instance.encrypt(
      input: src.path,
      output: container,
      password: 'exists-pw',
      overwrite: true,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
    );
    expect(enc['ok'], isTrue, reason: '${enc['message']}');

    final outDir = Directory('${root.path}/out')..createSync(recursive: true);
    // 第一次：正常
    final first = NativeCore.instance.decrypt(
      input: container,
      output: outDir.path,
      password: 'exists-pw',
      overwrite: false,
    );
    // ignore: avoid_print
    print('EXISTS first=${first['ok']} out=${first['output']} msg=${first['message']}');

    // 第二次：目标已存在，overwrite=false
    final handle = NativeCore.instance.newBatch(
      decrypt: true,
      perfMode: 1,
      concurrency: 2,
      overwrite: false,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
      password: 'exists-pw',
    );
    addTearDown(handle.dispose);
    handle.add(source: container, dest: outDir.path, size: File(container).lengthSync());
    handle.start();

    var summary = handle.summary();
    final started = DateTime.now();
    while (summary['is_done'] != true && DateTime.now().difference(started).inSeconds < 30) {
      await Future<void>.delayed(const Duration(milliseconds: 250));
      summary = handle.summary();
    }
    // ignore: avoid_print
    print('EXISTS summary=$summary');
    // ignore: avoid_print
    print('EXISTS items=${handle.snapshot()}');
    expect(summary['is_done'], isTrue, reason: '目标已存在时未结束（挂起）：$summary');
    expect(summary['failed_items'], 1);
  }, timeout: const Timeout(Duration(minutes: 2)));

  // 与界面默认参数完全一致：KdfPreset.desktop = 65536 KiB / 3 轮 / 4 并行。
  testWidgets('桌面预设参数（64 MiB·3·4）单文件解密能结束', (tester) async {
    final root = await Directory.systemTemp.createTemp('sf-preset-');
    final src = File('${root.path}/big.bin');
    src.writeAsBytesSync(List<int>.generate(512 * 1024, (i) => i % 199));
    final container = '${root.path}/big.bin.safefile';
    final enc = NativeCore.instance.encrypt(
      input: src.path,
      output: container,
      password: 'preset-pw',
      overwrite: true,
      mCostKib: 65536,
      tCost: 3,
      pCost: 4,
    );
    expect(enc['ok'], isTrue, reason: '${enc['message']}');

    final outDir = Directory('${root.path}/out')..createSync(recursive: true);
    final handle = NativeCore.instance.newBatch(
      decrypt: true,
      perfMode: 1,
      concurrency: 4,
      overwrite: true,
      mCostKib: 65536,
      tCost: 3,
      pCost: 4,
      password: 'preset-pw',
    );
    addTearDown(handle.dispose);
    handle.add(source: container, dest: outDir.path, size: File(container).lengthSync());
    handle.start();

    var summary = handle.summary();
    final started = DateTime.now();
    while (summary['is_done'] != true && DateTime.now().difference(started).inSeconds < 60) {
      await Future<void>.delayed(const Duration(milliseconds: 250));
      summary = handle.summary();
    }
    // ignore: avoid_print
    print('PRESET summary=$summary');
    // ignore: avoid_print
    print('PRESET items=${handle.snapshot()}');
    expect(summary['is_done'], isTrue, reason: '桌面预设参数下解密未结束：$summary');
    expect(summary['success_items'], 1, reason: '${handle.snapshot()}');
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets('设备上批量加密删除原文件', (tester) async {
    final root = await Directory.systemTemp.createTemp('sf-delsrc-');
    final src = File('${root.path}/victim.bin');
    src.writeAsBytesSync(List<int>.generate(48 * 1024, (i) => i % 97));
    final out = Directory('${root.path}/out')..createSync();

    final handle = NativeCore.instance.newBatch(
      decrypt: false,
      perfMode: 0,
      concurrency: 2,
      overwrite: false,
      deleteSource: true,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
      password: 'delsrc-pw',
    );
    addTearDown(handle.dispose);
    handle.add(source: src.path, dest: '${out.path}/victim.bin.safefile', size: src.lengthSync());
    handle.start();

    var summary = handle.summary();
    final started = DateTime.now();
    while (summary['is_done'] != true && DateTime.now().difference(started).inSeconds < 60) {
      await Future<void>.delayed(const Duration(milliseconds: 200));
      summary = handle.summary();
    }
    final items = handle.snapshot();
    // ignore: avoid_print
    print('DELSRC summary=$summary items=$items');

    expect(summary['is_done'], isTrue, reason: '未结束：$summary');
    expect(summary['success_items'], 1, reason: '$items');
    expect(items.first['deleted'], isTrue, reason: '快照未标记删除：$items');
    expect(src.existsSync(), isFalse, reason: '原文件应已删除');
    expect(File('${out.path}/victim.bin.safefile').existsSync(), isTrue);
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets('后台通知通道可用（前台服务能起来）', (tester) async {
    await BackgroundTask.start(title: '测试任务', text: '已完成 0/1');
    // ignore: avoid_print
    print('BACKGROUND running=${BackgroundTask.running}');
    // 断言必须放在 stop 之前：stop 之后 running 本来就该是 false。
    expect(BackgroundTask.running, isTrue, reason: '前台服务应已启动');
    // 留 8 秒窗口，便于用 dumpsys 验证通知确实进了通知栏。
    await Future<void>.delayed(const Duration(seconds: 8));
    await BackgroundTask.stop();
    // ignore: avoid_print
    print('BACKGROUND after stop running=${BackgroundTask.running}');
    expect(BackgroundTask.running, isFalse, reason: '停止后不应再有前台服务');
  }, timeout: const Timeout(Duration(minutes: 2)));
}

