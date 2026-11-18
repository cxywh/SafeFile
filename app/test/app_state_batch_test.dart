import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:safefile/core/app_state.dart';
import 'package:safefile/core/native_core.dart';

/// AppState 是界面真正调用的一层：批量任务的启动、轮询、收敛、取消都在这里。
/// 「一直显示任务进行中」的两个已知成因都在本文件覆盖：
/// 1) 轮询异常或引擎无进度时，状态必须收敛成已完成并带原因；
/// 2) cancelBatch 之后 isBusy 必须立刻变 false（否则按钮永久禁用）。
/// 注意：AppState 用 Timer.periodic 轮询，用例体必须在 tester.runAsync 内跑真实时钟。
void main() {
  late Directory work;

  setUpAll(() {
    work = Directory.systemTemp.createTempSync('safefile-state-test-');
  });

  tearDownAll(() {
    if (work.existsSync()) work.deleteSync(recursive: true);
  });

  Future<String> makeContainer(String name, String password) async {
    final input = File('${work.path}/$name');
    input.writeAsBytesSync(List<int>.generate(80 * 1024, (i) => i % 173));
    final container = '${work.path}/$name.safefile';
    final enc = NativeCore.instance.encrypt(
      input: input.path,
      output: container,
      password: password,
      overwrite: true,
      mCostKib: 8192,
      tCost: 1,
      pCost: 1,
    );
    expect(enc['ok'], isTrue, reason: '${enc['message']}');
    return container;
  }

  Future<void> waitDone(AppState state, {Duration limit = const Duration(seconds: 30)}) async {
    final started = DateTime.now();
    while (DateTime.now().difference(started) < limit) {
      if (state.batch != null && state.batch!.isDone) return;
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  }

  testWidgets('批处理完成后 isBusy 变 false', (tester) async {
    await tester.runAsync(() async {
      final container = await makeContainer('a.bin', 'pw-a');
      final outDir = Directory('${work.path}/out-a')..createSync();
      final state = AppState();

      state.startBatch(
        decrypt: true,
        password: 'pw-a',
        jobs: [(source: container, dest: outDir.path, size: File(container).lengthSync())],
      );
      expect(state.isBusy, isTrue, reason: '启动后应立即视为进行中');

      await waitDone(state);
      expect(state.batch!.isDone, isTrue, reason: '批次未收敛');
      expect(state.batch!.successItems, 1);
      final item = state.batch!.items.single;
      // 解密进度以明文计；分母必须被引擎给出的总量校正，否则会出现「已完成 57%」。
      expect(item.processed, item.size, reason: '进度分母与已处理字节不一致');
      expect(item.progress, 1.0, reason: '已完成条目的进度条应为满格');
      expect(state.isBusy, isFalse);
      state.dispose();
    });
  });

  testWidgets('整批失败时顶部给出原因（输出已存在）', (tester) async {
    await tester.runAsync(() async {
      final container = await makeContainer('b.bin', 'pw-b');
      final outDir = Directory('${work.path}/out-b')..createSync();
      final first = NativeCore.instance.decrypt(
        input: container,
        output: outDir.path,
        password: 'pw-b',
        overwrite: false,
      );
      expect(first['ok'], isTrue, reason: '${first['message']}');

      final state = AppState();
      state.startBatch(
        decrypt: true,
        password: 'pw-b',
        jobs: [(source: container, dest: outDir.path, size: File(container).lengthSync())],
      );
      await waitDone(state);

      expect(state.batch!.isDone, isTrue);
      expect(state.batch!.failedItems, 1);
      expect(state.isBusy, isFalse);
      expect(state.batch!.note, isNotNull);
      expect(state.batch!.note!, contains('输出已存在'));
      state.dispose();
    });
  });

  testWidgets('cancelBatch 之后 isBusy 立刻为 false', (tester) async {
    await tester.runAsync(() async {
      final container = await makeContainer('c.bin', 'pw-c');
      final outDir = Directory('${work.path}/out-c')..createSync();
      final state = AppState();

      state.startBatch(
        decrypt: true,
        password: 'pw-c',
        jobs: [(source: container, dest: outDir.path, size: File(container).lengthSync())],
      );
      state.cancelBatch();
      expect(state.isBusy, isFalse, reason: '取消后仍被视为「任务进行中」');
      expect(state.batch!.isDone, isTrue);
      state.dispose();
    });
  });
}
