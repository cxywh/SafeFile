import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:safefile/core/native_core.dart';
import 'package:safefile/ui/preview_view.dart';

/// 预览分两层：
/// - `sf_preview` 解析磁盘上的明文（CLI/调试用）；
/// - `sf_preview_mem` / `sf_media_open` 直接把容器解密到内存再解析，
///   界面走这一条，保证磁盘上没有明文。
void main() {
  final dir = Directory('${Directory.systemTemp.path}/safefile-preview-test')
    ..createSync(recursive: true);

  tearDownAll(() {
    try {
      dir.deleteSync(recursive: true);
    } catch (_) {}
  });

  String seal(File plain, {String password = 'pw-test'}) {
    final out = '${plain.path}.safefile';
    final res = NativeCore.instance.encrypt(
      input: plain.path,
      output: out,
      password: password,
      mCostKib: 8 * 1024,
      tCost: 1,
      pCost: 1,
      overwrite: true,
    );
    expect(res['ok'], isTrue, reason: '${res['message']}');
    return out;
  }

  test('文本文件可以直接取到正文', () async {
    final file = File('${dir.path}/note.txt')..writeAsStringSync('第一行\n第二行 hello');
    final res = await NativeCore.instance.previewOffThread(path: file.path, kind: 'Text');
    expect(res['ok'], isTrue, reason: '${res['message']}');
    final preview = Map<String, dynamic>.from(res['preview'] as Map);
    expect(preview['format'], 'text');
    expect('${preview['text']}', contains('第二行 hello'));
  });

  test('含 NUL 的二进制不会被当作文本预览', () async {
    final file = File('${dir.path}/blob.bin')..writeAsBytesSync([0x41, 0x00, 0x42, 0x00]);
    final res = await NativeCore.instance.previewOffThread(path: file.path, kind: 'Text');
    expect(res['ok'], isTrue);
    final preview = Map<String, dynamic>.from(res['preview'] as Map);
    expect((preview['text'] as String?) ?? '', isEmpty);
    expect('${preview['notes']}', contains('二进制'));
  });

  test('未支持的扩展名给出说明而不是抛错', () async {
    final file = File('${dir.path}/tool.exe')..writeAsBytesSync([0x4d, 0x5a]);
    final res = await NativeCore.instance.previewOffThread(path: file.path);
    expect(res['ok'], isTrue);
    final preview = Map<String, dynamic>.from(res['preview'] as Map);
    expect(preview['format'], 'none');
  });

  test('内存预览：容器里的文本不落盘就能读到', () async {
    final file = File('${dir.path}/memo.md')..writeAsStringSync('# 标题\n正文在内存里');
    final ct = seal(file);
    final res = await NativeCore.instance.previewMemOffThread(container: ct, password: 'pw-test');
    expect(res['ok'], isTrue, reason: '${res['message']}');
    final preview = Map<String, dynamic>.from(res['preview'] as Map);
    expect(preview['format'], anyOf('text', 'markdown'));
    final doc = Map<String, dynamic>.from(preview['doc'] as Map);
    expect('${doc['text']}', contains('正文在内存里'));
  });

  test('内存预览：图片被重新编码成缩略图', () async {
    // 1×1 红色 PNG
    final png = base64Decode(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
    );
    final file = File('${dir.path}/dot.png')..writeAsBytesSync(png);
    final ct = seal(file);
    final res = await NativeCore.instance.previewMemOffThread(container: ct, password: 'pw-test');
    expect(res['ok'], isTrue, reason: '${res['message']}');
    final preview = Map<String, dynamic>.from(res['preview'] as Map);
    expect(preview['format'], 'image');
    final image = Map<String, dynamic>.from(preview['image'] as Map);
    expect('${image['mime']}', anyOf('image/png', 'image/jpeg'));
    expect(base64Decode('${image['data']}'), isNotEmpty);
  });

  test('内存预览：音视频只发回环令牌，不返回字节', () async {
    final file = File('${dir.path}/clip.mp4')
      ..writeAsBytesSync(List<int>.generate(2048, (i) => i % 251));
    final ct = seal(file);
    final res = await NativeCore.instance.previewMemOffThread(container: ct, password: 'pw-test');
    expect(res['ok'], isTrue);
    final preview = Map<String, dynamic>.from(res['preview'] as Map);
    expect(preview['format'], 'video');
    expect(preview['media'], 'video');

    final media = await NativeCore.instance.mediaOpenOffThread(container: ct, password: 'pw-test');
    expect(media['ok'], isTrue, reason: '${media['message']}');
    expect('${media['url']}', startsWith('http://127.0.0.1:'));
    expect(media['size'], 2048);
    final id = '${media['id']}';
    expect(id, isNotEmpty);
    NativeCore.instance.mediaClose(id);
  });

  testWidgets('预览组件把容器里的文本渲染出来', (tester) async {
    final file = File('${dir.path}/readme.md')..writeAsStringSync('# 安全预览\n正文内容');
    final ct = seal(file);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(child: SafePreview(container: ct, password: 'pw-test')),
        ),
      ),
    );
    // 解密与解析都在 isolate 里，等它回来再重建。
    for (var i = 0; i < 60 && find.textContaining('正文内容').evaluate().isEmpty; i++) {
      await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
      await tester.pump();
    }
    expect(find.textContaining('正文内容'), findsOneWidget);
  });
}
