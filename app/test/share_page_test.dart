import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:safefile/core/app_state.dart';
import 'package:safefile/core/share_core.dart';
import 'package:safefile/ui/pages_share.dart';
import 'package:safefile/ui/theme.dart';

/// 页面级联调：真的走 FFI、真的开端口、真的收发一个文件。
///
/// 设备上的 UI 会被系统覆盖层挡住（测试机），所以这里用 widget 测试
/// 把「页面 → share_core → Rust」整条链路跑通，补上那一段证据。
Directory _root() {
  final base = Platform.environment['SAFEFILE_TEST_DIR'] ?? Directory.systemTemp.path;
  final dir = Directory('$base/ui-page-$pid');
  dir.createSync(recursive: true);
  return dir;
}

void main() {
  testWidgets('SharePage 显示本机身份、自动等待接收并能收到文件', (tester) async {
    final root = _root();
    final configDir = '${root.path}/lan';
    final saveDir = '${root.path}/save';
    Directory(saveDir).createSync(recursive: true);

    final status = await tester.runAsync(() => initLan(configDir));
    expect(status, isNotNull, reason: '局域网节点应能初始化');

    await tester.pumpWidget(
      MaterialApp(
        theme: buildTheme(Brightness.light),
        home: Scaffold(
          body: SharePage(
            state: AppState(),
            configDirOverride: configDir,
            saveDirOverride: saveDir,
          ),
        ),
      ),
    );

    // 等待页面的异步启动（读目录、开监听）在真实时间里完成。
    await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 600)));
    await tester.pump();

    expect(find.text('我的设备'), findsOneWidget);
    expect(find.textContaining(status!.name), findsWidgets, reason: '页面必须显示本机设备名');

    final listening = await tester.runAsync(lanStatus);
    expect(listening, isNotNull);
    expect(listening!.accepting, isTrue, reason: '进入页面后应自动开始等待接收');

    // 用同一个节点向自己发一个文件：覆盖握手、加密帧、落盘与界面进度。
    final file = File('${root.path}/hello.txt')..writeAsStringSync('safe file lan test');
    final sender = await tester.runAsync(
      () async => ShareSender.start('127.0.0.1:${listening.port}', [file.path]),
    );
    expect(sender, isNotNull, reason: '发送端应能连接本机监听端口');

    var progress = const ShareProgress();
    for (var i = 0; i < 40 && !progress.finished; i++) {
      await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 100)));
      progress = sender!.poll();
      await tester.pump(const Duration(milliseconds: 400));
    }
    sender?.free();

    expect(progress.finished, isTrue, reason: '传输应结束，错误：${progress.error}');
    expect(progress.error, isNull);
    expect(progress.peer, isNotEmpty);
    expect(progress.sas.length, 6);

    final received = File('$saveDir/hello.txt');
    expect(received.existsSync(), isTrue);
    expect(received.readAsStringSync(), 'safe file lan test');

    // 页面此时应显示安全码与已收文件。
    await tester.pump();
    expect(find.textContaining('安全码'), findsWidgets);
  });
}
